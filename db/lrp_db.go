package db

import (
	"github.com/cloudfoundry-incubator/auctioneer"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/pivotal-golang/lager"
)

//go:generate counterfeiter . LRPDB

type LRPDB interface {
	ActualLRPDB
	DesiredLRPDB

	ConvergeLRPs(logger lager.Logger) (startRequest []*auctioneer.LRPStartRequest, keysToRetire []*models.ActualLRPKey)

	// Exposed For Test
	GatherAndPruneLRPs(logger lager.Logger) (*models.ConvergenceInput, error)
}
