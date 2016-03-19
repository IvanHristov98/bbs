package etcd_test

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/cloudfoundry-incubator/bbs"
	"github.com/cloudfoundry-incubator/bbs/db"
	"github.com/cloudfoundry-incubator/bbs/db/etcd"
	"github.com/cloudfoundry-incubator/bbs/db/etcd/fakes"
	"github.com/cloudfoundry-incubator/bbs/db/etcd/test/etcd_helpers"
	"github.com/cloudfoundry-incubator/bbs/encryption"
	"github.com/cloudfoundry-incubator/bbs/format"
	"github.com/cloudfoundry-incubator/bbs/test_helpers"
	"github.com/cloudfoundry-incubator/consuladapter"
	"github.com/cloudfoundry-incubator/consuladapter/consulrunner"
	"github.com/cloudfoundry/storeadapter/storerunner/etcdstorerunner"
	etcdclient "github.com/coreos/go-etcd/etcd"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/clock/fakeclock"
	"github.com/pivotal-golang/lager/lagertest"

	"testing"
)

const DesiredLRPCreationTimeout = time.Minute

var etcdPort int
var etcdUrl string
var etcdRunner *etcdstorerunner.ETCDClusterRunner
var storeClient etcd.StoreClient
var fakeStoreClient *fakes.FakeStoreClient
var consulRunner *consulrunner.ClusterRunner
var consulClient consuladapter.Client

var logger *lagertest.TestLogger
var clock *fakeclock.FakeClock
var etcdHelper *etcd_helpers.ETCDHelper
var consulHelper *test_helpers.ConsulHelper

var serviceClient bbs.ServiceClient
var etcdDB db.DB
var etcdDBWithFakeStore db.DB
var workPoolCreateError error

var cryptor encryption.Cryptor

func TestDB(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ETCD DB Suite")
}

var _ = BeforeSuite(func() {
	clock = fakeclock.NewFakeClock(time.Unix(0, 1138))

	etcdPort = 4001 + GinkgoParallelNode()
	etcdUrl = fmt.Sprintf("http://127.0.0.1:%d", etcdPort)
	etcdRunner = etcdstorerunner.NewETCDClusterRunner(etcdPort, 1, nil)

	consulRunner = consulrunner.NewClusterRunner(
		9001+config.GinkgoConfig.ParallelNode*consulrunner.PortOffsetLength,
		1,
		"http",
	)

	consulRunner.Start()
	consulRunner.WaitUntilReady()

	etcdRunner.Start()

	Expect(workPoolCreateError).ToNot(HaveOccurred())

	encryptionKey, err := encryption.NewKey("label", "passphrase")
	Expect(err).NotTo(HaveOccurred())
	keyManager, err := encryption.NewKeyManager(encryptionKey, nil)
	Expect(err).NotTo(HaveOccurred())
	cryptor = encryption.NewCryptor(keyManager, rand.Reader)
})

var _ = AfterSuite(func() {
	etcdRunner.Stop()
	consulRunner.Stop()
})

var _ = BeforeEach(func() {
	logger = lagertest.NewTestLogger("test")

	etcdRunner.Reset()

	consulRunner.Reset()
	consulClient = consulRunner.NewClient()

	etcdClient := etcdRunner.Client()
	etcdClient.SetConsistency(etcdclient.STRONG_CONSISTENCY)
	storeClient = etcd.NewStoreClient(etcdClient)
	fakeStoreClient = &fakes.FakeStoreClient{}
	consulHelper = test_helpers.NewConsulHelper(logger, consulClient)
	serviceClient = bbs.NewServiceClient(consulClient, clock)
	etcdHelper = etcd_helpers.NewETCDHelper(format.ENCRYPTED_PROTO, cryptor, storeClient, clock)
	etcdDB = etcd.NewETCD(format.ENCRYPTED_PROTO, 100, 100, DesiredLRPCreationTimeout, cryptor, storeClient, serviceClient, clock)
	etcdDBWithFakeStore = etcd.NewETCD(format.ENCRYPTED_PROTO, 100, 100, DesiredLRPCreationTimeout, cryptor, fakeStoreClient, serviceClient, clock)
})
