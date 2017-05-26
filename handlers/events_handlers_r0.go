package handlers

import (
	"net/http"

	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/lager"
)

func (h *EventHandler) Subscribe_r0(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	logger = logger.Session("subscribe-r0")

	request := &models.EventsByCellId{}
	err := parseRequest(logger, req, request)
	if err != nil {
		logger.Error("failed-parsing-request", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	desiredSource, err := h.desiredHub.Subscribe()
	if err != nil {
		logger.Error("failed-to-subscribe-to-desired-event-hub", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer desiredSource.Close()

	actualSource, err := h.actualHub.Subscribe()
	if err != nil {
		logger.Error("failed-to-subscribe-to-actual-event-hub", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer actualSource.Close()

	eventChan := make(chan models.Event)
	errorChan := make(chan error)
	closeChan := make(chan struct{})
	defer close(closeChan)

	actualEventsFetcher := actualSource.Next
	if request.CellId != "" {
		actualEventsFetcher = func() (models.Event, error) {
			for {
				event, err := actualSource.Next()
				if err != nil {
					return event, err
				}

				if filterByCellID(request.CellId, event, err) {
					return event, nil
				}
			}
		}
	}

	desiredEventsFetcher := func() (models.Event, error) {
		event, err := desiredSource.Next()
		if err != nil {
			return event, err
		}
		event = models.VersionDesiredLRPsToV0(event)
		return event, err
	}

	go streamSource(eventChan, errorChan, closeChan, desiredEventsFetcher)
	go streamSource(eventChan, errorChan, closeChan, actualEventsFetcher)

	streamEventsToResponse(logger, w, eventChan, errorChan)
}

func filterByCellID(cellID string, bbsEvent models.Event, err error) bool {
	switch x := bbsEvent.(type) {
	case *models.ActualLRPCreatedEvent:
		if x.ActualLrpGroup.Instance.ActualLRPInstanceKey.CellId != cellID {
			return false
		}
	case *models.ActualLRPChangedEvent:
		if x.After.Instance.ActualLRPInstanceKey.CellId != cellID && x.Before.Instance.ActualLRPInstanceKey.CellId != cellID {
			return false
		}

	case *models.ActualLRPRemovedEvent:
		if x.ActualLrpGroup.Instance.ActualLRPInstanceKey.CellId != cellID {
			return false
		}

	case *models.ActualLRPCrashedEvent:
		if x.ActualLRPInstanceKey.CellId != cellID {
			return false
		}
	}

	return true
}
