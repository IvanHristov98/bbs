// This file was generated by counterfeiter
package fake_bbs

import (
	"sync"
	"time"

	"github.com/cloudfoundry-incubator/bbs"
	"github.com/cloudfoundry-incubator/bbs/models"
)

type FakeClient struct {
	DomainsStub        func() ([]string, error)
	domainsMutex       sync.RWMutex
	domainsArgsForCall []struct{}
	domainsReturns struct {
		result1 []string
		result2 error
	}
	UpsertDomainStub        func(domain string, ttl time.Duration) error
	upsertDomainMutex       sync.RWMutex
	upsertDomainArgsForCall []struct {
		domain string
		ttl    time.Duration
	}
	upsertDomainReturns struct {
		result1 error
	}
	ActualLRPGroupsStub        func(models.ActualLRPFilter) ([]*models.ActualLRPGroup, error)
	actualLRPGroupsMutex       sync.RWMutex
	actualLRPGroupsArgsForCall []struct {
		arg1 models.ActualLRPFilter
	}
	actualLRPGroupsReturns struct {
		result1 []*models.ActualLRPGroup
		result2 error
	}
	ActualLRPGroupsByProcessGuidStub        func(processGuid string) ([]*models.ActualLRPGroup, error)
	actualLRPGroupsByProcessGuidMutex       sync.RWMutex
	actualLRPGroupsByProcessGuidArgsForCall []struct {
		processGuid string
	}
	actualLRPGroupsByProcessGuidReturns struct {
		result1 []*models.ActualLRPGroup
		result2 error
	}
	ActualLRPGroupByProcessGuidAndIndexStub        func(processGuid string, index int) (*models.ActualLRPGroup, error)
	actualLRPGroupByProcessGuidAndIndexMutex       sync.RWMutex
	actualLRPGroupByProcessGuidAndIndexArgsForCall []struct {
		processGuid string
		index       int
	}
	actualLRPGroupByProcessGuidAndIndexReturns struct {
		result1 *models.ActualLRPGroup
		result2 error
	}
	DesiredLRPsStub        func(models.DesiredLRPFilter) ([]*models.DesiredLRP, error)
	desiredLRPsMutex       sync.RWMutex
	desiredLRPsArgsForCall []struct {
		arg1 models.DesiredLRPFilter
	}
	desiredLRPsReturns struct {
		result1 []*models.DesiredLRP
		result2 error
	}
}

func (fake *FakeClient) Domains() ([]string, error) {
	fake.domainsMutex.Lock()
	fake.domainsArgsForCall = append(fake.domainsArgsForCall, struct{}{})
	fake.domainsMutex.Unlock()
	if fake.DomainsStub != nil {
		return fake.DomainsStub()
	} else {
		return fake.domainsReturns.result1, fake.domainsReturns.result2
	}
}

func (fake *FakeClient) DomainsCallCount() int {
	fake.domainsMutex.RLock()
	defer fake.domainsMutex.RUnlock()
	return len(fake.domainsArgsForCall)
}

func (fake *FakeClient) DomainsReturns(result1 []string, result2 error) {
	fake.DomainsStub = nil
	fake.domainsReturns = struct {
		result1 []string
		result2 error
	}{result1, result2}
}

func (fake *FakeClient) UpsertDomain(domain string, ttl time.Duration) error {
	fake.upsertDomainMutex.Lock()
	fake.upsertDomainArgsForCall = append(fake.upsertDomainArgsForCall, struct {
		domain string
		ttl    time.Duration
	}{domain, ttl})
	fake.upsertDomainMutex.Unlock()
	if fake.UpsertDomainStub != nil {
		return fake.UpsertDomainStub(domain, ttl)
	} else {
		return fake.upsertDomainReturns.result1
	}
}

func (fake *FakeClient) UpsertDomainCallCount() int {
	fake.upsertDomainMutex.RLock()
	defer fake.upsertDomainMutex.RUnlock()
	return len(fake.upsertDomainArgsForCall)
}

func (fake *FakeClient) UpsertDomainArgsForCall(i int) (string, time.Duration) {
	fake.upsertDomainMutex.RLock()
	defer fake.upsertDomainMutex.RUnlock()
	return fake.upsertDomainArgsForCall[i].domain, fake.upsertDomainArgsForCall[i].ttl
}

func (fake *FakeClient) UpsertDomainReturns(result1 error) {
	fake.UpsertDomainStub = nil
	fake.upsertDomainReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeClient) ActualLRPGroups(arg1 models.ActualLRPFilter) ([]*models.ActualLRPGroup, error) {
	fake.actualLRPGroupsMutex.Lock()
	fake.actualLRPGroupsArgsForCall = append(fake.actualLRPGroupsArgsForCall, struct {
		arg1 models.ActualLRPFilter
	}{arg1})
	fake.actualLRPGroupsMutex.Unlock()
	if fake.ActualLRPGroupsStub != nil {
		return fake.ActualLRPGroupsStub(arg1)
	} else {
		return fake.actualLRPGroupsReturns.result1, fake.actualLRPGroupsReturns.result2
	}
}

func (fake *FakeClient) ActualLRPGroupsCallCount() int {
	fake.actualLRPGroupsMutex.RLock()
	defer fake.actualLRPGroupsMutex.RUnlock()
	return len(fake.actualLRPGroupsArgsForCall)
}

func (fake *FakeClient) ActualLRPGroupsArgsForCall(i int) models.ActualLRPFilter {
	fake.actualLRPGroupsMutex.RLock()
	defer fake.actualLRPGroupsMutex.RUnlock()
	return fake.actualLRPGroupsArgsForCall[i].arg1
}

func (fake *FakeClient) ActualLRPGroupsReturns(result1 []*models.ActualLRPGroup, result2 error) {
	fake.ActualLRPGroupsStub = nil
	fake.actualLRPGroupsReturns = struct {
		result1 []*models.ActualLRPGroup
		result2 error
	}{result1, result2}
}

func (fake *FakeClient) ActualLRPGroupsByProcessGuid(processGuid string) ([]*models.ActualLRPGroup, error) {
	fake.actualLRPGroupsByProcessGuidMutex.Lock()
	fake.actualLRPGroupsByProcessGuidArgsForCall = append(fake.actualLRPGroupsByProcessGuidArgsForCall, struct {
		processGuid string
	}{processGuid})
	fake.actualLRPGroupsByProcessGuidMutex.Unlock()
	if fake.ActualLRPGroupsByProcessGuidStub != nil {
		return fake.ActualLRPGroupsByProcessGuidStub(processGuid)
	} else {
		return fake.actualLRPGroupsByProcessGuidReturns.result1, fake.actualLRPGroupsByProcessGuidReturns.result2
	}
}

func (fake *FakeClient) ActualLRPGroupsByProcessGuidCallCount() int {
	fake.actualLRPGroupsByProcessGuidMutex.RLock()
	defer fake.actualLRPGroupsByProcessGuidMutex.RUnlock()
	return len(fake.actualLRPGroupsByProcessGuidArgsForCall)
}

func (fake *FakeClient) ActualLRPGroupsByProcessGuidArgsForCall(i int) string {
	fake.actualLRPGroupsByProcessGuidMutex.RLock()
	defer fake.actualLRPGroupsByProcessGuidMutex.RUnlock()
	return fake.actualLRPGroupsByProcessGuidArgsForCall[i].processGuid
}

func (fake *FakeClient) ActualLRPGroupsByProcessGuidReturns(result1 []*models.ActualLRPGroup, result2 error) {
	fake.ActualLRPGroupsByProcessGuidStub = nil
	fake.actualLRPGroupsByProcessGuidReturns = struct {
		result1 []*models.ActualLRPGroup
		result2 error
	}{result1, result2}
}

func (fake *FakeClient) ActualLRPGroupByProcessGuidAndIndex(processGuid string, index int) (*models.ActualLRPGroup, error) {
	fake.actualLRPGroupByProcessGuidAndIndexMutex.Lock()
	fake.actualLRPGroupByProcessGuidAndIndexArgsForCall = append(fake.actualLRPGroupByProcessGuidAndIndexArgsForCall, struct {
		processGuid string
		index       int
	}{processGuid, index})
	fake.actualLRPGroupByProcessGuidAndIndexMutex.Unlock()
	if fake.ActualLRPGroupByProcessGuidAndIndexStub != nil {
		return fake.ActualLRPGroupByProcessGuidAndIndexStub(processGuid, index)
	} else {
		return fake.actualLRPGroupByProcessGuidAndIndexReturns.result1, fake.actualLRPGroupByProcessGuidAndIndexReturns.result2
	}
}

func (fake *FakeClient) ActualLRPGroupByProcessGuidAndIndexCallCount() int {
	fake.actualLRPGroupByProcessGuidAndIndexMutex.RLock()
	defer fake.actualLRPGroupByProcessGuidAndIndexMutex.RUnlock()
	return len(fake.actualLRPGroupByProcessGuidAndIndexArgsForCall)
}

func (fake *FakeClient) ActualLRPGroupByProcessGuidAndIndexArgsForCall(i int) (string, int) {
	fake.actualLRPGroupByProcessGuidAndIndexMutex.RLock()
	defer fake.actualLRPGroupByProcessGuidAndIndexMutex.RUnlock()
	return fake.actualLRPGroupByProcessGuidAndIndexArgsForCall[i].processGuid, fake.actualLRPGroupByProcessGuidAndIndexArgsForCall[i].index
}

func (fake *FakeClient) ActualLRPGroupByProcessGuidAndIndexReturns(result1 *models.ActualLRPGroup, result2 error) {
	fake.ActualLRPGroupByProcessGuidAndIndexStub = nil
	fake.actualLRPGroupByProcessGuidAndIndexReturns = struct {
		result1 *models.ActualLRPGroup
		result2 error
	}{result1, result2}
}

func (fake *FakeClient) DesiredLRPs(arg1 models.DesiredLRPFilter) ([]*models.DesiredLRP, error) {
	fake.desiredLRPsMutex.Lock()
	fake.desiredLRPsArgsForCall = append(fake.desiredLRPsArgsForCall, struct {
		arg1 models.DesiredLRPFilter
	}{arg1})
	fake.desiredLRPsMutex.Unlock()
	if fake.DesiredLRPsStub != nil {
		return fake.DesiredLRPsStub(arg1)
	} else {
		return fake.desiredLRPsReturns.result1, fake.desiredLRPsReturns.result2
	}
}

func (fake *FakeClient) DesiredLRPsCallCount() int {
	fake.desiredLRPsMutex.RLock()
	defer fake.desiredLRPsMutex.RUnlock()
	return len(fake.desiredLRPsArgsForCall)
}

func (fake *FakeClient) DesiredLRPsArgsForCall(i int) models.DesiredLRPFilter {
	fake.desiredLRPsMutex.RLock()
	defer fake.desiredLRPsMutex.RUnlock()
	return fake.desiredLRPsArgsForCall[i].arg1
}

func (fake *FakeClient) DesiredLRPsReturns(result1 []*models.DesiredLRP, result2 error) {
	fake.DesiredLRPsStub = nil
	fake.desiredLRPsReturns = struct {
		result1 []*models.DesiredLRP
		result2 error
	}{result1, result2}
}

var _ bbs.Client = new(FakeClient)
