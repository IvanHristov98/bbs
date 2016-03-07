package bbs

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/cloudfoundry-incubator/bbs/events"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/cf_http"
	"github.com/gogo/protobuf/proto"
	"github.com/tedsuo/rata"
	"github.com/vito/go-sse/sse"
)

const (
	ContentTypeHeader    = "Content-Type"
	XCfRouterErrorHeader = "X-Cf-Routererror"
	ProtoContentType     = "application/x-protobuf"
	KeepContainer        = true
	DeleteContainer      = false
)

//go:generate counterfeiter -o fake_bbs/fake_client.go . Client

/*
The Client interface exposes all available endpoints of the BBS server,
including private endpoints which should be used exclusively by internal Diego
components. To interact with the BBS from outside of Diego, the ExternalClient
should be used instead.
*/
type Client interface {
	ExternalClient

	ClaimActualLRP(processGuid string, index int, instanceKey *models.ActualLRPInstanceKey) error
	StartActualLRP(key *models.ActualLRPKey, instanceKey *models.ActualLRPInstanceKey, netInfo *models.ActualLRPNetInfo) error
	CrashActualLRP(key *models.ActualLRPKey, instanceKey *models.ActualLRPInstanceKey, errorMessage string) error
	FailActualLRP(key *models.ActualLRPKey, errorMessage string) error
	RemoveActualLRP(processGuid string, index int) error

	EvacuateClaimedActualLRP(*models.ActualLRPKey, *models.ActualLRPInstanceKey) (bool, error)
	EvacuateRunningActualLRP(*models.ActualLRPKey, *models.ActualLRPInstanceKey, *models.ActualLRPNetInfo, uint64) (bool, error)
	EvacuateStoppedActualLRP(*models.ActualLRPKey, *models.ActualLRPInstanceKey) (bool, error)
	EvacuateCrashedActualLRP(*models.ActualLRPKey, *models.ActualLRPInstanceKey, string) (bool, error)
	RemoveEvacuatingActualLRP(*models.ActualLRPKey, *models.ActualLRPInstanceKey) error

	ConvergeLRPs() error

	ConvergeTasks(kickTaskDuration, expirePendingTaskDuration, expireCompletedTaskDuration time.Duration) error
	StartTask(taskGuid string, cellID string) (bool, error)
	FailTask(taskGuid, failureReason string) error
	CompleteTask(taskGuid, cellId string, failed bool, failureReason, result string) error
	ResolvingTask(taskGuid string) error
	DeleteTask(taskGuid string) error
}

/*
The External Client can be used to access the BBS's public functionality.
It exposes methods for basic LRP and Task Lifecycles, Domain manipulation, and
event subscription.
*/
type ExternalClient interface {
	// Returns true if the BBS server is reachable
	Ping() bool

	// Lists the active domains
	Domains() ([]string, error)

	// Creates a domain or bumps the ttl on an existing domain
	UpsertDomain(domain string, ttl time.Duration) error

	// Returns all ActualLRPGroups matching the given ActualLRPFilter
	ActualLRPGroups(models.ActualLRPFilter) ([]*models.ActualLRPGroup, error)

	// Returns all ActualLRPGroups that have the given process guid
	ActualLRPGroupsByProcessGuid(processGuid string) ([]*models.ActualLRPGroup, error)

	// Returns the ActualLRPGroup with the given process guid and instance index
	ActualLRPGroupByProcessGuidAndIndex(processGuid string, index int) (*models.ActualLRPGroup, error)

	// Shuts down the ActualLRP matching the given ActualLRPKey, but does not modify the desired state
	RetireActualLRP(key *models.ActualLRPKey) error

	// Lists all DesiredLRPs that match the given DesiredLRPFilter
	DesiredLRPs(models.DesiredLRPFilter) ([]*models.DesiredLRP, error)

	// Returns the DesiredLRP with the given process guid
	DesiredLRPByProcessGuid(processGuid string) (*models.DesiredLRP, error)

	// Returns all DesiredLRPSchedulingInfos that match the given DesiredLRPFilter
	DesiredLRPSchedulingInfos(models.DesiredLRPFilter) ([]*models.DesiredLRPSchedulingInfo, error)

	// Creates the given DesiredLRP and its corresponding ActualLRPs
	DesireLRP(*models.DesiredLRP) error

	// Updates the DesiredLRP matching the given process guid
	UpdateDesiredLRP(processGuid string, update *models.DesiredLRPUpdate) error

	// Removes the DesiredLRP matching the given process guid
	RemoveDesiredLRP(processGuid string) error

	// Lists all Tasks
	Tasks() ([]*models.Task, error)

	// Lists all Tasks of the given domain
	TasksByDomain(domain string) ([]*models.Task, error)

	// Lists all Tasks on the given cell
	TasksByCellID(cellId string) ([]*models.Task, error)

	// Returns the Task with the given guid
	TaskByGuid(guid string) (*models.Task, error)

	// Creates a Task from the given TaskDefinition
	DesireTask(guid, domain string, def *models.TaskDefinition) error

	// Cancels the Task with the given task guid
	CancelTask(taskGuid string) error

	// Legacy, do not use
	SubscribeToEvents() (events.EventSource, error)

	// Returns an EventSource for watching changes to DesiredLRPs
	SubscribeToDesiredLRPEvents() (events.EventSource, error)

	// Returns an EventSource for watching changes to ActualLRPs
	SubscribeToActualLRPEvents() (events.EventSource, error)

	// Returns an EventSource for watching changes to Tasks
	SubscribeToTaskEvents() (events.EventSource, error)

	// Lists all Cells
	Cells() ([]*models.CellPresence, error)
}

func newClient(url string) *client {
	return &client{
		httpClient:          cf_http.NewClient(),
		streamingHTTPClient: cf_http.NewStreamingClient(),
		reqGen:              rata.NewRequestGenerator(url, Routes),
	}
}

func NewClient(url string) Client {
	return newClient(url)
}

func NewSecureClient(url, caFile, certFile, keyFile string, clientSessionCacheSize, maxIdleConnsPerHost int) (Client, error) {
	return newSecureClient(url, caFile, certFile, keyFile, clientSessionCacheSize, maxIdleConnsPerHost, false)
}

func NewSecureSkipVerifyClient(url, certFile, keyFile string, clientSessionCacheSize, maxIdleConnsPerHost int) (Client, error) {
	return newSecureClient(url, "", certFile, keyFile, clientSessionCacheSize, maxIdleConnsPerHost, true)
}

func newSecureClient(url, caFile, certFile, keyFile string, clientSessionCacheSize, maxIdleConnsPerHost int, skipVerify bool) (Client, error) {
	client := newClient(url)

	tlsConfig, err := cf_http.NewTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		return nil, err
	}
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(clientSessionCacheSize)

	tlsConfig.InsecureSkipVerify = skipVerify

	if tr, ok := client.httpClient.Transport.(*http.Transport); ok {
		tr.TLSClientConfig = tlsConfig
		tr.MaxIdleConnsPerHost = maxIdleConnsPerHost
	} else {
		return nil, errors.New("Invalid transport")
	}

	if tr, ok := client.streamingHTTPClient.Transport.(*http.Transport); ok {
		tr.TLSClientConfig = tlsConfig
		tr.MaxIdleConnsPerHost = maxIdleConnsPerHost
	} else {
		return nil, errors.New("Invalid transport")
	}

	return client, nil
}

type client struct {
	httpClient          *http.Client
	streamingHTTPClient *http.Client
	reqGen              *rata.RequestGenerator
}

func (c *client) Ping() bool {
	response := models.PingResponse{}
	err := c.doRequest(PingRoute, nil, nil, nil, &response)
	if err != nil {
		return false
	}
	return response.Available
}

func (c *client) Domains() ([]string, error) {
	response := models.DomainsResponse{}
	err := c.doRequest(DomainsRoute, nil, nil, nil, &response)
	if err != nil {
		return nil, err
	}
	return response.Domains, response.Error.ToError()
}

func (c *client) UpsertDomain(domain string, ttl time.Duration) error {
	request := models.UpsertDomainRequest{
		Domain: domain,
		Ttl:    uint32(ttl.Seconds()),
	}
	response := models.UpsertDomainResponse{}
	err := c.doRequest(UpsertDomainRoute, nil, nil, &request, &response)
	if err != nil {
		return err
	}
	return response.Error.ToError()
}

func (c *client) ActualLRPGroups(filter models.ActualLRPFilter) ([]*models.ActualLRPGroup, error) {
	request := models.ActualLRPGroupsRequest{
		Domain: filter.Domain,
		CellId: filter.CellID,
	}
	response := models.ActualLRPGroupsResponse{}
	err := c.doRequest(ActualLRPGroupsRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.ActualLrpGroups, response.Error.ToError()
}

func (c *client) ActualLRPGroupsByProcessGuid(processGuid string) ([]*models.ActualLRPGroup, error) {
	request := models.ActualLRPGroupsByProcessGuidRequest{
		ProcessGuid: processGuid,
	}
	response := models.ActualLRPGroupsResponse{}
	err := c.doRequest(ActualLRPGroupsByProcessGuidRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.ActualLrpGroups, response.Error.ToError()
}

func (c *client) ActualLRPGroupByProcessGuidAndIndex(processGuid string, index int) (*models.ActualLRPGroup, error) {
	request := models.ActualLRPGroupByProcessGuidAndIndexRequest{
		ProcessGuid: processGuid,
		Index:       int32(index),
	}
	response := models.ActualLRPGroupResponse{}
	err := c.doRequest(ActualLRPGroupByProcessGuidAndIndexRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.ActualLrpGroup, response.Error.ToError()
}

func (c *client) ClaimActualLRP(processGuid string, index int, instanceKey *models.ActualLRPInstanceKey) error {
	request := models.ClaimActualLRPRequest{
		ProcessGuid:          processGuid,
		Index:                int32(index),
		ActualLrpInstanceKey: instanceKey,
	}
	response := models.ActualLRPLifecycleResponse{}
	err := c.doRequest(ClaimActualLRPRoute, nil, nil, &request, &response)
	if err != nil {
		return err
	}
	return response.Error.ToError()
}

func (c *client) StartActualLRP(key *models.ActualLRPKey, instanceKey *models.ActualLRPInstanceKey, netInfo *models.ActualLRPNetInfo) error {
	request := models.StartActualLRPRequest{
		ActualLrpKey:         key,
		ActualLrpInstanceKey: instanceKey,
		ActualLrpNetInfo:     netInfo,
	}
	response := models.ActualLRPLifecycleResponse{}
	err := c.doRequest(StartActualLRPRoute, nil, nil, &request, &response)
	if err != nil {
		return err

	}
	return response.Error.ToError()
}

func (c *client) CrashActualLRP(key *models.ActualLRPKey, instanceKey *models.ActualLRPInstanceKey, errorMessage string) error {
	request := models.CrashActualLRPRequest{
		ActualLrpKey:         key,
		ActualLrpInstanceKey: instanceKey,
		ErrorMessage:         errorMessage,
	}
	response := models.ActualLRPLifecycleResponse{}
	err := c.doRequest(CrashActualLRPRoute, nil, nil, &request, &response)
	if err != nil {
		return err
	}
	return response.Error.ToError()
}

func (c *client) FailActualLRP(key *models.ActualLRPKey, errorMessage string) error {
	request := models.FailActualLRPRequest{
		ActualLrpKey: key,
		ErrorMessage: errorMessage,
	}
	response := models.ActualLRPLifecycleResponse{}
	err := c.doRequest(FailActualLRPRoute, nil, nil, &request, &response)
	if err != nil {
		return err

	}
	return response.Error.ToError()
}

func (c *client) RetireActualLRP(key *models.ActualLRPKey) error {
	request := models.RetireActualLRPRequest{
		ActualLrpKey: key,
	}
	response := models.ActualLRPLifecycleResponse{}
	err := c.doRequest(RetireActualLRPRoute, nil, nil, &request, &response)
	if err != nil {
		return err

	}
	return response.Error.ToError()
}

func (c *client) RemoveActualLRP(processGuid string, index int) error {
	request := models.RemoveActualLRPRequest{
		ProcessGuid: processGuid,
		Index:       int32(index),
	}
	response := models.ActualLRPLifecycleResponse{}
	err := c.doRequest(RemoveActualLRPRoute, nil, nil, &request, &response)
	if err != nil {
		return err
	}
	return response.Error.ToError()
}

func (c *client) EvacuateClaimedActualLRP(key *models.ActualLRPKey, instanceKey *models.ActualLRPInstanceKey) (bool, error) {
	return c.doEvacRequest(EvacuateClaimedActualLRPRoute, KeepContainer, &models.EvacuateClaimedActualLRPRequest{
		ActualLrpKey:         key,
		ActualLrpInstanceKey: instanceKey,
	})
}

func (c *client) EvacuateCrashedActualLRP(key *models.ActualLRPKey, instanceKey *models.ActualLRPInstanceKey, errorMessage string) (bool, error) {
	return c.doEvacRequest(EvacuateCrashedActualLRPRoute, DeleteContainer, &models.EvacuateCrashedActualLRPRequest{
		ActualLrpKey:         key,
		ActualLrpInstanceKey: instanceKey,
		ErrorMessage:         errorMessage,
	})
}

func (c *client) EvacuateStoppedActualLRP(key *models.ActualLRPKey, instanceKey *models.ActualLRPInstanceKey) (bool, error) {
	return c.doEvacRequest(EvacuateStoppedActualLRPRoute, DeleteContainer, &models.EvacuateStoppedActualLRPRequest{
		ActualLrpKey:         key,
		ActualLrpInstanceKey: instanceKey,
	})
}

func (c *client) EvacuateRunningActualLRP(key *models.ActualLRPKey, instanceKey *models.ActualLRPInstanceKey, netInfo *models.ActualLRPNetInfo, ttl uint64) (bool, error) {
	return c.doEvacRequest(EvacuateRunningActualLRPRoute, KeepContainer, &models.EvacuateRunningActualLRPRequest{
		ActualLrpKey:         key,
		ActualLrpInstanceKey: instanceKey,
		ActualLrpNetInfo:     netInfo,
		Ttl:                  ttl,
	})
}

func (c *client) RemoveEvacuatingActualLRP(key *models.ActualLRPKey, instanceKey *models.ActualLRPInstanceKey) error {
	request := models.RemoveEvacuatingActualLRPRequest{
		ActualLrpKey:         key,
		ActualLrpInstanceKey: instanceKey,
	}

	response := models.RemoveEvacuatingActualLRPResponse{}
	err := c.doRequest(RemoveEvacuatingActualLRPRoute, nil, nil, &request, &response)
	if err != nil {
		return err
	}

	return response.Error.ToError()
}

func (c *client) DesiredLRPs(filter models.DesiredLRPFilter) ([]*models.DesiredLRP, error) {
	request := models.DesiredLRPsRequest{
		Domain: filter.Domain,
	}
	response := models.DesiredLRPsResponse{}
	err := c.doRequest(DesiredLRPsRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.DesiredLrps, response.Error.ToError()
}

func (c *client) DesiredLRPByProcessGuid(processGuid string) (*models.DesiredLRP, error) {
	request := models.DesiredLRPByProcessGuidRequest{
		ProcessGuid: processGuid,
	}
	response := models.DesiredLRPResponse{}
	err := c.doRequest(DesiredLRPByProcessGuidRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.DesiredLrp, response.Error.ToError()
}

func (c *client) DesiredLRPSchedulingInfos(filter models.DesiredLRPFilter) ([]*models.DesiredLRPSchedulingInfo, error) {
	request := models.DesiredLRPsRequest{
		Domain: filter.Domain,
	}
	response := models.DesiredLRPSchedulingInfosResponse{}
	err := c.doRequest(DesiredLRPSchedulingInfosRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.DesiredLrpSchedulingInfos, response.Error.ToError()
}

func (c *client) doDesiredLRPLifecycleRequest(route string, request proto.Message) error {
	response := models.DesiredLRPLifecycleResponse{}
	err := c.doRequest(route, nil, nil, request, &response)
	if err != nil {
		return err
	}
	return response.Error.ToError()
}

func (c *client) DesireLRP(desiredLRP *models.DesiredLRP) error {
	request := models.DesireLRPRequest{
		DesiredLrp: desiredLRP,
	}
	return c.doDesiredLRPLifecycleRequest(DesireDesiredLRPRoute, &request)
}

func (c *client) UpdateDesiredLRP(processGuid string, update *models.DesiredLRPUpdate) error {
	request := models.UpdateDesiredLRPRequest{
		ProcessGuid: processGuid,
		Update:      update,
	}
	return c.doDesiredLRPLifecycleRequest(UpdateDesiredLRPRoute, &request)
}

func (c *client) RemoveDesiredLRP(processGuid string) error {
	request := models.RemoveDesiredLRPRequest{
		ProcessGuid: processGuid,
	}
	return c.doDesiredLRPLifecycleRequest(RemoveDesiredLRPRoute, &request)
}

func (c *client) ConvergeLRPs() error {
	route := ConvergeLRPsRoute
	response := models.ConvergeLRPsResponse{}
	err := c.doRequest(route, nil, nil, nil, &response)
	if err != nil {
		return err
	}
	return response.Error.ToError()
}

func (c *client) Tasks() ([]*models.Task, error) {
	request := models.TasksRequest{}
	response := models.TasksResponse{}
	err := c.doRequest(TasksRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.Tasks, response.Error.ToError()
}

func (c *client) TasksByDomain(domain string) ([]*models.Task, error) {
	request := models.TasksRequest{
		Domain: domain,
	}
	response := models.TasksResponse{}
	err := c.doRequest(TasksRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.Tasks, response.Error.ToError()
}

func (c *client) TasksByCellID(cellId string) ([]*models.Task, error) {
	request := models.TasksRequest{
		CellId: cellId,
	}
	response := models.TasksResponse{}
	err := c.doRequest(TasksRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.Tasks, response.Error.ToError()
}

func (c *client) TaskByGuid(taskGuid string) (*models.Task, error) {
	request := models.TaskByGuidRequest{
		TaskGuid: taskGuid,
	}
	response := models.TaskResponse{}
	err := c.doRequest(TaskByGuidRoute, nil, nil, &request, &response)
	if err != nil {
		return nil, err
	}

	return response.Task, response.Error.ToError()
}

func (c *client) doTaskLifecycleRequest(route string, request proto.Message) error {
	response := models.TaskLifecycleResponse{}
	err := c.doRequest(route, nil, nil, request, &response)
	if err != nil {
		return err
	}
	return response.Error.ToError()
}

func (c *client) DesireTask(taskGuid, domain string, taskDef *models.TaskDefinition) error {
	route := DesireTaskRoute
	request := models.DesireTaskRequest{
		TaskGuid:       taskGuid,
		Domain:         domain,
		TaskDefinition: taskDef,
	}
	return c.doTaskLifecycleRequest(route, &request)
}

func (c *client) StartTask(taskGuid string, cellId string) (bool, error) {
	request := &models.StartTaskRequest{
		TaskGuid: taskGuid,
		CellId:   cellId,
	}
	response := &models.StartTaskResponse{}
	err := c.doRequest(StartTaskRoute, nil, nil, request, response)
	if err != nil {
		return false, err
	}
	return response.ShouldStart, response.Error.ToError()
}

func (c *client) CancelTask(taskGuid string) error {
	request := models.TaskGuidRequest{
		TaskGuid: taskGuid,
	}
	route := CancelTaskRoute
	return c.doTaskLifecycleRequest(route, &request)
}

func (c *client) ResolvingTask(taskGuid string) error {
	request := models.TaskGuidRequest{
		TaskGuid: taskGuid,
	}
	route := ResolvingTaskRoute
	return c.doTaskLifecycleRequest(route, &request)
}

func (c *client) DeleteTask(taskGuid string) error {
	request := models.TaskGuidRequest{
		TaskGuid: taskGuid,
	}
	route := DeleteTaskRoute
	return c.doTaskLifecycleRequest(route, &request)
}

func (c *client) FailTask(taskGuid, failureReason string) error {
	request := models.FailTaskRequest{
		TaskGuid:      taskGuid,
		FailureReason: failureReason,
	}
	route := FailTaskRoute
	return c.doTaskLifecycleRequest(route, &request)
}

func (c *client) CompleteTask(taskGuid, cellId string, failed bool, failureReason, result string) error {
	request := models.CompleteTaskRequest{
		TaskGuid:      taskGuid,
		CellId:        cellId,
		Failed:        failed,
		FailureReason: failureReason,
		Result:        result,
	}
	route := CompleteTaskRoute
	return c.doTaskLifecycleRequest(route, &request)
}

func (c *client) ConvergeTasks(kickTaskDuration, expirePendingTaskDuration, expireCompletedTaskDuration time.Duration) error {
	request := &models.ConvergeTasksRequest{
		KickTaskDuration:            kickTaskDuration.Nanoseconds(),
		ExpirePendingTaskDuration:   expirePendingTaskDuration.Nanoseconds(),
		ExpireCompletedTaskDuration: expireCompletedTaskDuration.Nanoseconds(),
	}
	response := models.ConvergeTasksResponse{}
	route := ConvergeTasksRoute
	err := c.doRequest(route, nil, nil, request, &response)
	if err != nil {
		return err
	}
	return response.Error.ToError()
}

func (c *client) SubscribeToEvents() (events.EventSource, error) {
	eventSource, err := sse.Connect(c.streamingHTTPClient, time.Second, func() *http.Request {
		request, err := c.reqGen.CreateRequest(EventStreamRoute_r0, nil, nil)
		if err != nil {
			panic(err) // totally shouldn't happen
		}

		return request
	})

	if err != nil {
		return nil, err
	}

	return events.NewEventSource(eventSource), nil
}

func (c *client) SubscribeToDesiredLRPEvents() (events.EventSource, error) {
	eventSource, err := sse.Connect(c.streamingHTTPClient, time.Second, func() *http.Request {
		request, err := c.reqGen.CreateRequest(DesiredLRPEventStreamRoute, nil, nil)
		if err != nil {
			panic(err) // totally shouldn't happen
		}

		return request
	})

	if err != nil {
		return nil, err
	}

	return events.NewEventSource(eventSource), nil
}

func (c *client) SubscribeToActualLRPEvents() (events.EventSource, error) {
	eventSource, err := sse.Connect(c.streamingHTTPClient, time.Second, func() *http.Request {
		request, err := c.reqGen.CreateRequest(ActualLRPEventStreamRoute, nil, nil)
		if err != nil {
			panic(err) // totally shouldn't happen
		}

		return request
	})

	if err != nil {
		return nil, err
	}

	return events.NewEventSource(eventSource), nil
}

func (c *client) SubscribeToTaskEvents() (events.EventSource, error) {
	eventSource, err := sse.Connect(c.streamingHTTPClient, time.Second, func() *http.Request {
		request, err := c.reqGen.CreateRequest(TaskEventStreamRoute, nil, nil)
		if err != nil {
			panic(err) // totally shouldn't happen
		}

		return request
	})

	if err != nil {
		return nil, err
	}

	return events.NewEventSource(eventSource), nil
}

func (c *client) Cells() ([]*models.CellPresence, error) {
	response := models.CellsResponse{}
	err := c.doRequest(CellsRoute, nil, nil, nil, &response)
	if err != nil {
		return nil, err
	}
	return response.Cells, response.Error.ToError()
}

func (c *client) createRequest(requestName string, params rata.Params, queryParams url.Values, message proto.Message) (*http.Request, error) {
	var messageBody []byte
	var err error
	if message != nil {
		messageBody, err = proto.Marshal(message)
		if err != nil {
			return nil, err
		}
	}

	request, err := c.reqGen.CreateRequest(requestName, params, bytes.NewReader(messageBody))
	if err != nil {
		return nil, err
	}

	request.URL.RawQuery = queryParams.Encode()
	request.ContentLength = int64(len(messageBody))
	request.Header.Set("Content-Type", ProtoContentType)
	return request, nil
}

func (c *client) doEvacRequest(route string, defaultKeepContainer bool, request proto.Message) (bool, error) {
	var response models.EvacuationResponse
	err := c.doRequest(route, nil, nil, request, &response)
	if err != nil {
		return defaultKeepContainer, err
	}

	return response.KeepContainer, response.Error.ToError()
}

func (c *client) doRequest(requestName string, params rata.Params, queryParams url.Values, requestBody, responseBody proto.Message) error {
	var err error
	var request *http.Request

	for attempts := 0; attempts < 3; attempts++ {
		request, err = c.createRequest(requestName, params, queryParams, requestBody)
		if err != nil {
			return err
		}
		err = c.do(request, responseBody)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
		} else {
			break
		}
	}
	return err
}

func closeResponse(response *http.Response) error {
	// ensure we read the entire body
	bs, err2 := ioutil.ReadAll(response.Body)
	if err2 != nil {
		log.Println("Error during ReadAll!!", err2)
	}
	if len(bs) > 0 {
		log.Println("Had to read some bytes, not good!", bs, string(bs))
	}
	return response.Body.Close()
}

func (c *client) do(request *http.Request, responseObject proto.Message) error {
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer closeResponse(response)

	var parsedContentType string
	if contentType, ok := response.Header[ContentTypeHeader]; ok {
		parsedContentType, _, _ = mime.ParseMediaType(contentType[0])
	}

	if routerError, ok := response.Header[XCfRouterErrorHeader]; ok {
		return models.NewError(models.Error_RouterError, routerError[0])
	}

	if parsedContentType == ProtoContentType {
		return handleProtoResponse(response, responseObject)
	} else {
		return handleNonProtoResponse(response)
	}
}

func handleProtoResponse(response *http.Response, responseObject proto.Message) error {
	if responseObject == nil {
		return models.NewError(models.Error_InvalidRequest, "responseObject cannot be nil")
	}

	buf, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return models.NewError(models.Error_InvalidResponse, fmt.Sprint("failed to read body: ", err.Error()))
	}

	err = proto.Unmarshal(buf, responseObject)
	if err != nil {
		return models.NewError(models.Error_InvalidProtobufMessage, fmt.Sprintf("failed to unmarshal proto", err.Error()))
	}

	return nil
}

func handleNonProtoResponse(response *http.Response) error {
	if response.StatusCode > 299 {
		return models.NewError(models.Error_InvalidResponse, fmt.Sprintf("Invalid Response with status code: %d", response.StatusCode))
	}
	return nil
}
