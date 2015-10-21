package etcd

import (
	"path"
	"strconv"
	"sync"

	"github.com/cloudfoundry-incubator/auctioneer"
	"github.com/cloudfoundry-incubator/bbs"
	"github.com/cloudfoundry-incubator/bbs/encryption"
	"github.com/cloudfoundry-incubator/bbs/format"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/bbs/taskworkpool"
	"github.com/cloudfoundry-incubator/rep"
	"github.com/coreos/go-etcd/etcd"
	etcdclient "github.com/coreos/go-etcd/etcd"
	"github.com/pivotal-golang/clock"
	"github.com/pivotal-golang/lager"
)

const (
	V1SchemaRoot          = "/v1/"
	VersionKey            = "/version"
	EncryptionKeyLabelKey = "/encryption-key"

	DomainSchemaRoot = V1SchemaRoot + "domain"

	ActualLRPSchemaRoot    = V1SchemaRoot + "actual"
	ActualLRPInstanceKey   = "instance"
	ActualLRPEvacuatingKey = "evacuating"

	DesiredLRPComponentsSchemaRoot     = V1SchemaRoot + "desired_lrp"
	DesiredLRPSchedulingInfoKey        = "schedule"
	DesiredLRPSchedulingInfoSchemaRoot = DesiredLRPComponentsSchemaRoot + "/" + DesiredLRPSchedulingInfoKey
	DesiredLRPRunInfoKey               = "run"
	DesiredLRPRunInfoSchemaRoot        = DesiredLRPComponentsSchemaRoot + "/" + DesiredLRPRunInfoKey

	TaskSchemaRoot = V1SchemaRoot + "task"
)

const maxActualGroupGetterWorkPoolSize = 50

func ActualLRPProcessDir(processGuid string) string {
	return path.Join(ActualLRPSchemaRoot, processGuid)
}

func ActualLRPIndexDir(processGuid string, index int32) string {
	return path.Join(ActualLRPProcessDir(processGuid), strconv.Itoa(int(index)))
}

func ActualLRPSchemaPath(processGuid string, index int32) string {
	return path.Join(ActualLRPIndexDir(processGuid, index), ActualLRPInstanceKey)
}

func EvacuatingActualLRPSchemaPath(processGuid string, index int32) string {
	return path.Join(ActualLRPIndexDir(processGuid, index), ActualLRPEvacuatingKey)
}

func DesiredLRPSchedulingInfoSchemaPath(processGuid string) string {
	return path.Join(DesiredLRPSchedulingInfoSchemaRoot, processGuid)
}

func DesiredLRPRunInfoSchemaPath(processGuid string) string {
	return path.Join(DesiredLRPComponentsSchemaRoot, DesiredLRPRunInfoKey, processGuid)
}

func TaskSchemaPath(task *models.Task) string {
	return TaskSchemaPathByGuid(task.GetTaskGuid())
}

func TaskSchemaPathByGuid(taskGuid string) string {
	return path.Join(TaskSchemaRoot, taskGuid)
}

type ETCDOptions struct {
	CertFile               string
	KeyFile                string
	CAFile                 string
	ClusterUrls            []string
	IsSSL                  bool
	ClientSessionCacheSize int
	MaxIdleConnsPerHost    int
}

type ETCDDB struct {
	format                 *format.Format
	convergenceWorkersSize int
	updateWorkersSize      int
	serializer             format.Serializer
	client                 StoreClient
	clock                  clock.Clock
	inflightWatches        map[chan bool]bool
	inflightWatchLock      *sync.Mutex
	auctioneerClient       auctioneer.Client
	repClientFactory       rep.ClientFactory

	taskCompletionClient taskworkpool.TaskCompletionClient

	serviceClient bbs.ServiceClient
}

func NewETCD(
	serializationFormat *format.Format,
	convergenceWorkersSize int,
	updateWorkersSize int,
	cryptor encryption.Cryptor,
	storeClient StoreClient,
	auctioneerClient auctioneer.Client,
	serviceClient bbs.ServiceClient,
	clock clock.Clock,
	repClientFactory rep.ClientFactory,
	taskCC taskworkpool.TaskCompletionClient,
) *ETCDDB {
	return &ETCDDB{
		format:                 serializationFormat,
		convergenceWorkersSize: convergenceWorkersSize,
		updateWorkersSize:      updateWorkersSize,
		serializer:             format.NewSerializer(cryptor),
		client:                 storeClient,
		clock:                  clock,
		inflightWatches:        map[chan bool]bool{},
		inflightWatchLock:      &sync.Mutex{},
		auctioneerClient:       auctioneerClient,
		repClientFactory:       repClientFactory,
		taskCompletionClient:   taskCC,
		serviceClient:          serviceClient,
	}
}

func (db *ETCDDB) serializeModel(logger lager.Logger, model format.Versioner) ([]byte, error) {
	encodedPayload, err := db.serializer.Marshal(logger, db.format, model)
	if err != nil {
		logger.Error("failed-to-serialize-model", err)
		return nil, models.NewError(models.Error_InvalidRecord, err.Error())
	}
	return encodedPayload, nil
}

func (db *ETCDDB) deserializeModel(logger lager.Logger, node *etcdclient.Node, model format.Versioner) error {
	err := db.serializer.Unmarshal(logger, []byte(node.Value), model)
	if err != nil {
		logger.Error("failed-to-deserialize-model", err)
		return models.NewError(models.Error_InvalidRecord, err.Error())
	}
	return nil
}

func (db *ETCDDB) fetchRecursiveRaw(logger lager.Logger, key string) (*etcd.Node, error) {
	logger.Debug("fetching-recursive-from-etcd")
	response, err := db.client.Get(key, false, true)
	if err != nil {
		return nil, ErrorFromEtcdError(logger, err)
	}
	logger.Debug("succeeded-fetching-recursive-from-etcd", lager.Data{"num-nodes": response.Node.Nodes.Len()})
	return response.Node, nil
}

func (db *ETCDDB) fetchRaw(logger lager.Logger, key string) (*etcd.Node, error) {
	logger.Debug("fetching-from-etcd")
	response, err := db.client.Get(key, false, false)
	if err != nil {
		return nil, ErrorFromEtcdError(logger, err)
	}
	logger.Debug("succeeded-fetching-from-etcd")
	return response.Node, nil
}

const (
	ETCDErrKeyNotFound  = 100
	ETCDErrKeyExists    = 105
	ETCDErrIndexCleared = 401
)

func ErrorFromEtcdError(logger lager.Logger, err error) error {
	if err == nil {
		return nil
	}

	logger = logger.Session("etcd-error", lager.Data{"error": err})
	switch etcdErrCode(err) {
	case ETCDErrKeyNotFound:
		logger.Debug("resource-not-found")
		return models.ErrResourceNotFound
	case ETCDErrKeyExists:
		logger.Debug("resource-exits")
		return models.ErrResourceExists
	default:
		logger.Error("unknown-error", err)
		return models.ErrUnknownError
	}
}

func etcdErrCode(err error) int {
	if err != nil {
		switch err.(type) {
		case etcd.EtcdError:
			return err.(etcd.EtcdError).ErrorCode
		case *etcd.EtcdError:
			return err.(*etcd.EtcdError).ErrorCode
		}
	}
	return 0
}
