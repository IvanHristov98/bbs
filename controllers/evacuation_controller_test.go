package controllers_test

import (
	"errors"

	"code.cloudfoundry.org/auctioneer"
	"code.cloudfoundry.org/auctioneer/auctioneerfakes"
	"code.cloudfoundry.org/bbs/controllers"
	"code.cloudfoundry.org/bbs/db/dbfakes"
	"code.cloudfoundry.org/bbs/events/eventfakes"
	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/bbs/models/test/model_helpers"
	"code.cloudfoundry.org/bbs/serviceclient/serviceclientfakes"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/rep/repfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("ActualLRP Lifecycle Controller", func() {
	var (
		logger               *lagertest.TestLogger
		fakeActualLRPDB      *dbfakes.FakeActualLRPDB
		fakeDesiredLRPDB     *dbfakes.FakeDesiredLRPDB
		fakeEvacuationDB     *dbfakes.FakeEvacuationDB
		fakeSuspectDB        *dbfakes.FakeSuspectDB
		fakeAuctioneerClient *auctioneerfakes.FakeClient
		actualHub            *eventfakes.FakeHub

		controller *controllers.EvacuationController
		err        error
		modelErr   *models.Error
	)

	BeforeEach(func() {
		fakeActualLRPDB = new(dbfakes.FakeActualLRPDB)
		fakeSuspectDB = new(dbfakes.FakeSuspectDB)
		fakeDesiredLRPDB = new(dbfakes.FakeDesiredLRPDB)
		fakeEvacuationDB = new(dbfakes.FakeEvacuationDB)
		fakeAuctioneerClient = new(auctioneerfakes.FakeClient)
		logger = lagertest.NewTestLogger("test")

		fakeServiceClient = new(serviceclientfakes.FakeServiceClient)
		fakeRepClientFactory = new(repfakes.FakeClientFactory)
		fakeRepClient = new(repfakes.FakeClient)
		fakeRepClientFactory.CreateClientReturns(fakeRepClient, nil)

		actualHub = &eventfakes.FakeHub{}
		controller = controllers.NewEvacuationController(
			fakeEvacuationDB,
			fakeActualLRPDB,
			fakeSuspectDB,
			fakeDesiredLRPDB,
			fakeAuctioneerClient,
			actualHub,
		)
	})

	Describe("RemoveEvacuatingActualLRP", func() {
		var (
			processGuid = "process-guid"
			index       = int32(1)

			key                   models.ActualLRPKey
			instanceKey           models.ActualLRPInstanceKey
			actual, evacuatingLRP *models.ActualLRP

			replacementInstanceKey models.ActualLRPInstanceKey
			replacementActual      *models.ActualLRP
		)

		BeforeEach(func() {
			key = models.NewActualLRPKey(
				processGuid,
				index,
				"domain-0",
			)
			instanceKey = models.NewActualLRPInstanceKey("instance-guid", "cell-id")
			actual = &models.ActualLRP{
				ActualLRPInstanceKey: instanceKey,
			}
			evacuatingLRP = &models.ActualLRP{
				ActualLRPInstanceKey: instanceKey,
				Presence:             models.ActualLRP_Evacuating,
			}

			replacementInstanceKey = models.NewActualLRPInstanceKey("replacement-instance-guid", "replacement-cell-id")
			replacementActual = &models.ActualLRP{
				ActualLRPInstanceKey: replacementInstanceKey,
				State:                models.ActualLRPStateClaimed,
				PlacementError:       "some-placement-error",
			}
			fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{
				evacuatingLRP,
			}, nil)
		})

		JustBeforeEach(func() {
			err = controller.RemoveEvacuatingActualLRP(logger, &key, &instanceKey)
			modelErr = models.ConvertError(err)
		})

		Context("when removeEvacuatinging the actual lrp in the DB succeeds", func() {
			BeforeEach(func() {
				fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(nil)
			})

			It("removeEvacuatings the actual lrp by process guid and index", func() {
				Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(1))
				_, actualKey, actualInstanceKey := fakeEvacuationDB.RemoveEvacuatingActualLRPArgsForCall(0)
				Expect(*actualKey).To(Equal(key))
				Expect(*actualInstanceKey).To(Equal(instanceKey))
			})

			It("emits events to the hub", func() {
				Eventually(actualHub.EmitCallCount).Should(Equal(1))
				event := actualHub.EmitArgsForCall(0)
				removeEvent, ok := event.(*models.ActualLRPRemovedEvent)
				Expect(ok).To(BeTrue())
				Expect(removeEvent.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: evacuatingLRP}))
			})

			It("logs the stranded evacuating actual lrp", func() {
				Eventually(logger).Should(gbytes.Say(`removing-stranded-evacuating-actual-lrp.*"index":%d,"instance-key":{"instance_guid":"%s","cell_id":"%s"},"process-guid":"%s"`, key.Index, instanceKey.InstanceGuid, instanceKey.CellId, key.ProcessGuid))
			})

			Context("when the evacuating lrp is being replaced", func() {
				BeforeEach(func() {
					fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{
						evacuatingLRP,
						replacementActual,
					}, nil)
				})

				It("logs the current instance information for the evacuating lrp", func() {
					Eventually(logger).Should(gbytes.Say(`removing-stranded-evacuating-actual-lrp.*,"replacement-lrp-instance-key":{"instance_guid":"%s","cell_id":"%s"},"replacement-lrp-placement-error":"%s","replacement-state":"%s"`, replacementInstanceKey.InstanceGuid, replacementInstanceKey.CellId, replacementActual.PlacementError, replacementActual.State))
				})
			})

			Context("when the lrp has a running instance", func() {
				BeforeEach(func() {
					fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{
						evacuatingLRP,
						actual,
					}, nil)
				})

				It("emits event with the evacuating instance only", func() {
					Eventually(actualHub.EmitCallCount).Should(Equal(1))
					event := actualHub.EmitArgsForCall(0)
					removeEvent, ok := event.(*models.ActualLRPRemovedEvent)
					Expect(ok).To(BeTrue())
					Expect(removeEvent.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: evacuatingLRP}))
				})
			})
		})

		Context("when the DB returns an unrecoverable error", func() {
			BeforeEach(func() {
				fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(models.NewUnrecoverableError(nil))
			})

			It("logs and writes to the exit channel", func() {
				Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
			})
		})

		Context("when DB errors out", func() {
			BeforeEach(func() {
				fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(models.ErrUnknownError)
			})

			It("returns unknown error", func() {
				Expect(modelErr).NotTo(BeNil())
				Expect(modelErr).To(Equal(models.ErrUnknownError))
			})
		})

		Context("when we cannot find the resource", func() {
			BeforeEach(func() {
				fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(models.ErrResourceNotFound)
			})

			It("returns resource not found error", func() {
				Expect(modelErr).NotTo(BeNil())
				Expect(modelErr).To(Equal(models.ErrResourceNotFound))
			})
		})
	})

	Describe("EvacuateClaimedActualLRP", func() {
		var (
			actual, evacuating *models.ActualLRP
			suspectActual      *models.ActualLRP
			afterActual        *models.ActualLRP
			desiredLRP         *models.DesiredLRP
			instanceKey        *models.ActualLRPInstanceKey
			key                *models.ActualLRPKey
			keepContainer      bool
		)

		BeforeEach(func() {
			desiredLRP = model_helpers.NewValidDesiredLRP("the-guid")
			fakeDesiredLRPDB.DesiredLRPByProcessGuidReturns(desiredLRP, nil)

			actual = model_helpers.NewValidActualLRP("process-guid", 1)
			actual.State = models.ActualLRPStateClaimed

			evacuating = model_helpers.NewValidEvacuatingActualLRP("process-guid", 1)

			suspectActual = model_helpers.NewValidActualLRP("process-guid", 1)
			suspectActual.State = models.ActualLRPStateClaimed
			suspectActual.Presence = models.ActualLRP_Suspect

			afterActual = model_helpers.NewValidActualLRP("process-guid", 1)
			afterActual.State = models.ActualLRPStateUnclaimed

			key = &actual.ActualLRPKey
			instanceKey = &actual.ActualLRPInstanceKey

			fakeActualLRPDB.UnclaimActualLRPReturns(actual, afterActual, nil)
		})

		JustBeforeEach(func() {
			err, keepContainer = controller.EvacuateClaimedActualLRP(logger, key, instanceKey)
			modelErr = models.ConvertError(err)
		})

		Context("when the claimed actual lrp is already evacuating", func() {
			BeforeEach(func() {
				instanceKey = &evacuating.ActualLRPInstanceKey
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{evacuating}, nil)
			})

			It("removes the evacuating actual lrp", func() {
				Expect(keepContainer).To(BeFalse())
				Expect(modelErr).To(BeNil())

				Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(1))
				_, key, instanceKey := fakeEvacuationDB.RemoveEvacuatingActualLRPArgsForCall(0)
				Expect(*key).To(Equal(evacuating.ActualLRPKey))
				Expect(*instanceKey).To(Equal(evacuating.ActualLRPInstanceKey))
			})
		})

		Context("when the claimed actual lrp is not already evacuating", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actual}, nil)
			})

			It("emits an LRPChanged event to the hub", func() {
				Eventually(actualHub.EmitCallCount).Should(Equal(1))

				event := actualHub.EmitArgsForCall(0)
				Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPChangedEvent{}))
				che := event.(*models.ActualLRPChangedEvent)
				Expect(che.Before).To(Equal(&models.ActualLRPGroup{Instance: actual}))
				Expect(che.After).To(Equal(&models.ActualLRPGroup{Instance: afterActual}))
			})

			It("unclaims the actual lrp instance and requests an auction", func() {
				Expect(keepContainer).To(BeFalse())
				Expect(modelErr).To(BeNil())

				Expect(fakeActualLRPDB.UnclaimActualLRPCallCount()).To(Equal(1))
				_, lrpKey := fakeActualLRPDB.UnclaimActualLRPArgsForCall(0)
				Expect(lrpKey.ProcessGuid).To(Equal("process-guid"))
				Expect(lrpKey.Index).To(BeEquivalentTo(1))

				Expect(fakeDesiredLRPDB.DesiredLRPByProcessGuidCallCount()).To(Equal(1))
				_, guid := fakeDesiredLRPDB.DesiredLRPByProcessGuidArgsForCall(0)
				Expect(guid).To(Equal("process-guid"))

				expectedStartRequest := auctioneer.NewLRPStartRequestFromModel(desiredLRP, int(actual.Index))
				Expect(fakeAuctioneerClient.RequestLRPAuctionsCallCount()).To(Equal(1))
				_, startRequests := fakeAuctioneerClient.RequestLRPAuctionsArgsForCall(0)
				Expect(startRequests).To(Equal([]*auctioneer.LRPStartRequest{&expectedStartRequest}))
			})
		})

		Context("when the evacuating actual lrp instance is suspect", func() {
			BeforeEach(func() {
				suspectCellId := "suspect-cell"
				suspectActual.ActualLRPInstanceKey.CellId = suspectCellId
				instanceKey.CellId = suspectCellId
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{suspectActual, evacuating}, nil)
				fakeActualLRPDB.UnclaimActualLRPReturns(suspectActual, afterActual, nil)
			})

			It("removes the evacuating actual lrp", func() {
				Expect(keepContainer).To(BeFalse())
				Expect(modelErr).To(BeNil())

				Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(1))
				_, key, instanceKey := fakeEvacuationDB.RemoveEvacuatingActualLRPArgsForCall(0)
				Expect(*key).To(Equal(actual.ActualLRPKey))
				Expect(*instanceKey).To(Equal(actual.ActualLRPInstanceKey))
			})

			It("should unclaim the suspect", func() {
				Expect(fakeActualLRPDB.UnclaimActualLRPCallCount()).To(Equal(1))
				_, key := fakeActualLRPDB.UnclaimActualLRPArgsForCall(0)
				Expect(key).To(Equal(&actual.ActualLRPKey))
			})

			It("emits an LRPChanged event  as well as an LRPRemoved event to the hub", func() {
				Eventually(actualHub.EmitCallCount).Should(Equal(2))

				event := actualHub.EmitArgsForCall(0)
				Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPRemovedEvent{}))
				ev := event.(*models.ActualLRPRemovedEvent)
				Expect(ev.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: evacuating}))

				event = actualHub.EmitArgsForCall(1)
				Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPChangedEvent{}))
				che := event.(*models.ActualLRPChangedEvent)
				Expect(che.Before).To(Equal(&models.ActualLRPGroup{Instance: suspectActual}))
				Expect(che.After).To(Equal(&models.ActualLRPGroup{Instance: afterActual}))
			})
		})

		Context("when the evacuating instance is not the suspect one", func() {
			BeforeEach(func() {
				suspectCellId := "suspect-cell"
				suspectActual.ActualLRPInstanceKey.CellId = suspectCellId
				suspectActual.State = models.ActualLRPStateRunning
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actual, suspectActual}, nil)
			})

			It("should unclaim the claimed one", func() {
				Expect(fakeActualLRPDB.UnclaimActualLRPCallCount()).To(Equal(1))
				_, key := fakeActualLRPDB.UnclaimActualLRPArgsForCall(0)
				Expect(key).To(Equal(&actual.ActualLRPKey))
			})

			It("should not emit an LRPChanged event", func() {
				Consistently(actualHub.EmitCallCount).Should(Equal(0))
			})
		})

		Context("when the evacuating instance is the suspect one in the presence of a claimed ordinary", func() {
			BeforeEach(func() {
				suspectCellId := "suspect-cell"
				suspectActual.ActualLRPInstanceKey.CellId = suspectCellId
				suspectActual.State = models.ActualLRPStateRunning
				instanceKey = &suspectActual.ActualLRPInstanceKey
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actual, suspectActual}, nil)
			})

			It("should remove the suspect LRP", func() {
				Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(1))
				_, guid, index, iKey := fakeActualLRPDB.RemoveActualLRPArgsForCall(0)
				Expect(guid).To(Equal(suspectActual.ProcessGuid))
				Expect(index).To(Equal(suspectActual.Index))
				Expect(iKey).To(Equal(&suspectActual.ActualLRPInstanceKey))
			})

			It("should not emit an LRPChanged event", func() {
				Consistently(actualHub.EmitCallCount).Should(Equal(0))
			})
		})

		Context("when the claimed lrp is already evacuating", func() {
			BeforeEach(func() {
				instanceKey = &evacuating.ActualLRPInstanceKey
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{evacuating}, nil)
			})

			Context("when the DB returns an unrecoverable error", func() {
				BeforeEach(func() {
					fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(models.NewUnrecoverableError(nil))
				})

				It("returns an unrecoverable error", func() {
					Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
				})
			})

			Context("when removing the evacuating lrp fails", func() {
				BeforeEach(func() {
					fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(errors.New("i failed"))
				})

				It("logs the error and continues", func() {
					Expect(keepContainer).To(BeFalse())
					Expect(modelErr).To(BeNil())
					Expect(logger).To(gbytes.Say("failed-removing-evacuating-actual-lrp"))
				})
			})
		})

		Context("when unclaiming the lrp instance fails", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actual}, nil)
			})

			Context("when the DB returns an unrecoverable error", func() {
				BeforeEach(func() {
					fakeActualLRPDB.UnclaimActualLRPReturns(nil, nil, models.NewUnrecoverableError(nil))
				})

				It("returns the unrecoverable error", func() {
					Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
				})
			})

			Context("because the instance does not exist", func() {
				BeforeEach(func() {
					fakeActualLRPDB.UnclaimActualLRPReturns(nil, nil, models.ErrResourceNotFound)
				})

				It("does not keep the container and does not return an error", func() {
					Expect(keepContainer).To(BeFalse())
					Expect(modelErr).To(BeNil())
				})

				Context("when there is an evacuating instance", func() {
					BeforeEach(func() {
						fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actual, evacuating}, nil)
					})

					It("only emits events for deleting evacuating", func() {
						Eventually(actualHub.EmitCallCount).Should(Equal(1))
						event := actualHub.EmitArgsForCall(0)
						removeEvent, ok := event.(*models.ActualLRPRemovedEvent)
						Expect(ok).To(BeTrue())
						Expect(removeEvent.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: evacuating}))
					})
				})
			})

			Context("for another reason", func() {
				BeforeEach(func() {
					fakeActualLRPDB.UnclaimActualLRPReturns(nil, nil, errors.New("can't unclaim this"))
				})

				It("returns the error and keeps the container", func() {
					Expect(keepContainer).To(BeTrue())
					Expect(modelErr).NotTo(BeNil())
					Expect(modelErr.Error()).To(Equal("can't unclaim this"))
				})

				Context("when there is an evacuating instance", func() {
					BeforeEach(func() {
						fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actual, evacuating}, nil)
					})

					It("only emits events for deleting evacuating", func() {
						Eventually(actualHub.EmitCallCount).Should(Equal(1))
						event := actualHub.EmitArgsForCall(0)
						removeEvent, ok := event.(*models.ActualLRPRemovedEvent)
						Expect(ok).To(BeTrue())
						Expect(removeEvent.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: evacuating}))
					})
				})
			})
		})

		Context("when requesting the lrp auction fails", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actual}, nil)
				fakeAuctioneerClient.RequestLRPAuctionsReturns(errors.New("boom!"))
			})

			It("does not return the error or keep the container", func() {
				Expect(keepContainer).To(BeFalse())
				Expect(modelErr).To(BeNil())
			})
		})
	})

	Describe("EvacuateCrashedActualLRP", func() {
		var (
			actualLRP   *models.ActualLRP
			key         models.ActualLRPKey
			instanceKey models.ActualLRPInstanceKey
			err         error
			modelErr    *models.Error
			errMessage  string
		)

		BeforeEach(func() {
			actualLRP = model_helpers.NewValidEvacuatingActualLRP("process-guid", 1)
			key = actualLRP.ActualLRPKey
			instanceKey = actualLRP.ActualLRPInstanceKey
			fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actualLRP}, nil)
			errMessage = "i failed"
		})

		JustBeforeEach(func() {
			err = controller.EvacuateCrashedActualLRP(logger, &key, &instanceKey, errMessage)
			modelErr = models.ConvertError(err)
		})

		Context("when the  actual lrp is not in the db", func() {
			BeforeEach(func() {
				actualLRP.ActualLRPInstanceKey.CellId = "some-random-cell"
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actualLRP}, nil)
			})

			It("should successfully make a call to remove evacuating actual lrp", func() {
				Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(1))
				_, _, instanceKey := fakeEvacuationDB.RemoveEvacuatingActualLRPArgsForCall(0)
				Expect(instanceKey.CellId).NotTo(Equal(actualLRP.ActualLRPInstanceKey.CellId))
			})
		})

		Context("when fetching actual lrps returns an error", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{}, errors.New("blows up!"))
			})

			It("should return early with an error", func() {
				Expect(err).To(MatchError("blows up!"))
			})
		})

		Context("when the LRP presence is Suspect", func() {
			BeforeEach(func() {
				actualLRP.Presence = models.ActualLRP_Suspect
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actualLRP}, nil)
				fakeSuspectDB.RemoveSuspectActualLRPReturns(actualLRP, nil)
			})

			It("removes the suspect lrp", func() {
				Expect(fakeSuspectDB.RemoveSuspectActualLRPCallCount()).To(Equal(1))
				_, lrpKey := fakeSuspectDB.RemoveSuspectActualLRPArgsForCall(0)
				Expect(lrpKey.ProcessGuid).To(Equal(actualLRP.ProcessGuid))
				Expect(lrpKey.Index).To(Equal(actualLRP.Index))
			})

			It("emits ActualLRPRemovedEvent", func() {
				Eventually(actualHub.EmitCallCount).Should(Equal(1))
				events := []models.Event{}
				events = append(events, actualHub.EmitArgsForCall(0))
				Expect(events).To(ConsistOf(models.NewActualLRPRemovedEvent(&models.ActualLRPGroup{Instance: actualLRP})))
			})

			Context("when the DB returns an unrecoverable error", func() {
				BeforeEach(func() {
					fakeSuspectDB.RemoveSuspectActualLRPReturns(nil, models.NewUnrecoverableError(nil))
				})

				It("logs and writes to the exit channel", func() {
					Expect(err).To(HaveOccurred())
					Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
				})
			})

			Context("when removing the evacuating actual lrp fails", func() {
				BeforeEach(func() {
					fakeSuspectDB.RemoveSuspectActualLRPReturns(nil, errors.New("oh no!"))
				})

				It("returns the error", func() {
					Expect(err).To(MatchError("oh no!"))
				})

				It("does not emit ActualLRPRemovedEvent", func() {
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})

				It("logs the error", func() {
					Expect(logger).To(gbytes.Say("failed-removing-suspect-actual-lrp"))
				})
			})
		})

		It("does not return an error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		It("removes the evacuating actual lrp", func() {
			Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(1))
			_, key, instanceKey := fakeEvacuationDB.RemoveEvacuatingActualLRPArgsForCall(0)
			Expect(*key).To(Equal(actualLRP.ActualLRPKey))
			Expect(*instanceKey).To(Equal(actualLRP.ActualLRPInstanceKey))
		})

		It("emits events to the hub", func() {
			Eventually(actualHub.EmitCallCount).Should(Equal(1))
			event := actualHub.EmitArgsForCall(0)
			removeEvent, ok := event.(*models.ActualLRPRemovedEvent)
			Expect(ok).To(BeTrue())
			Expect(removeEvent.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: actualLRP}))
		})

		It("crashes the actual lrp instance", func() {
			Expect(fakeActualLRPDB.CrashActualLRPCallCount()).To(Equal(1))
			_, key, instanceKey, errorMessage := fakeActualLRPDB.CrashActualLRPArgsForCall(0)
			Expect(*key).To(Equal(actualLRP.ActualLRPKey))
			Expect(*instanceKey).To(Equal(actualLRP.ActualLRPInstanceKey))
			Expect(errorMessage).To(Equal("i failed"))
		})

		Context("when the DB returns an unrecoverable error", func() {
			BeforeEach(func() {
				fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(models.NewUnrecoverableError(nil))
			})

			It("logs and writes to the exit channel", func() {
				Eventually(modelErr.Type).Should(Equal(models.Error_Unrecoverable))
			})
		})

		Context("when removing the evacuating actual lrp fails", func() {
			BeforeEach(func() {
				fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(errors.New("oh no!"))
			})

			It("logs the error and continues", func() {
				Expect(err).NotTo(HaveOccurred())
				Expect(logger).To(gbytes.Say("failed-removing-evacuating-actual-lrp"))
			})
		})

		Context("when crashing the actual lrp fails", func() {
			Context("when the DB returns an unrecoverable error", func() {
				BeforeEach(func() {
					fakeActualLRPDB.CrashActualLRPReturns(nil, nil, false, models.NewUnrecoverableError(nil))
				})

				It("logs and writes to the exit channel", func() {
					Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
				})
			})

			Context("because the resource does not exist", func() {
				BeforeEach(func() {
					fakeActualLRPDB.CrashActualLRPReturns(nil, nil, false, models.ErrResourceNotFound)
				})

				It("does not return an error or keep the container", func() {
					Expect(err).NotTo(HaveOccurred())
				})
			})

			Context("for a reason other than resource not found", func() {
				BeforeEach(func() {
					fakeActualLRPDB.CrashActualLRPReturns(nil, nil, false, errors.New("failed-crashing-dawg"))
				})

				It("returns an error and does not keep the container", func() {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal("failed-crashing-dawg"))
				})
			})
		})
	})

	Describe("EvacuateRunningActualLRP", func() {
		var (
			desiredLRP *models.DesiredLRP

			actual             *models.ActualLRP
			evacuatingActual   *models.ActualLRP
			afterActual        *models.ActualLRP
			unclaimedActualLRP *models.ActualLRP
			actualLRPs         []*models.ActualLRP
			targetKey          models.ActualLRPKey
			targetInstanceKey  models.ActualLRPInstanceKey
			netInfo            models.ActualLRPNetInfo

			keepContainer bool

			err      error
			modelErr *models.Error
		)

		BeforeEach(func() {
			desiredLRP = model_helpers.NewValidDesiredLRP("the-guid")
			fakeDesiredLRPDB.DesiredLRPByProcessGuidReturns(desiredLRP, nil)

			actual = model_helpers.NewValidActualLRP("the-guid", 1)

			evacuatingActual = model_helpers.NewValidEvacuatingActualLRP("the-guid", 1)

			afterActual = model_helpers.NewValidActualLRP("the-guid", 1)
			afterActual.Presence = models.ActualLRP_Evacuating

			targetKey = actual.ActualLRPKey
			targetInstanceKey = actual.ActualLRPInstanceKey
			netInfo = actual.ActualLRPNetInfo

			unclaimedActualLRP = model_helpers.NewValidActualLRP("some-guid", 1)
			unclaimedActualLRP.State = models.ActualLRPStateUnclaimed
			fakeActualLRPDB.UnclaimActualLRPReturns(actual, unclaimedActualLRP, nil)
		})

		JustBeforeEach(func() {
			fakeActualLRPDB.ActualLRPsReturns(actualLRPs, nil)
			err, keepContainer = controller.EvacuateRunningActualLRP(logger, &targetKey, &targetInstanceKey, &netInfo)
			modelErr = models.ConvertError(err)
		})

		Context("when the actual LRP instance is already evacuating", func() {
			BeforeEach(func() {
				actualLRPs = []*models.ActualLRP{evacuatingActual}
				targetInstanceKey = evacuatingActual.ActualLRPInstanceKey
			})

			It("removes the evacuating lrp and does not keep the container", func() {
				Expect(keepContainer).To(BeFalse())
				Expect(err).To(BeNil())

				Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(1))
				_, actualLRPKey, actualLRPInstanceKey := fakeEvacuationDB.RemoveEvacuatingActualLRPArgsForCall(0)
				Expect(*actualLRPKey).To(Equal(evacuatingActual.ActualLRPKey))
				Expect(*actualLRPInstanceKey).To(Equal(evacuatingActual.ActualLRPInstanceKey))
			})

			It("emits events to the hub", func() {
				Eventually(actualHub.EmitCallCount).Should(Equal(1))

				event := actualHub.EmitArgsForCall(0)
				removeEvent, ok := event.(*models.ActualLRPRemovedEvent)
				Expect(ok).To(BeTrue())

				Expect(removeEvent.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: evacuatingActual}))
			})

			Context("when the evacuating lrp cannot be removed", func() {
				BeforeEach(func() {
					fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(models.ErrActualLRPCannotBeRemoved)
				})

				It("returns no error and removes the container", func() {
					Expect(keepContainer).To(BeFalse())
					Expect(err).To(BeNil())
				})

				It("does not emit any events", func() {
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})
			})

			Context("when the DB returns an unrecoverable error", func() {
				BeforeEach(func() {
					fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(models.NewUnrecoverableError(nil))
				})

				It("logs and writes to the exit channel", func() {
					Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
				})

				It("does not emit any events", func() {
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})
			})

			Context("when removing the evacuating lrp fails for a different reason", func() {
				BeforeEach(func() {
					fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(errors.New("didnt work"))
				})

				It("returns an error and keeps the container", func() {
					Expect(keepContainer).To(BeTrue())
					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(Equal("didnt work"))
				})

				It("does not emit any events", func() {
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})
			})
		})

		Context("when the instance is unclaimed", func() {
			BeforeEach(func() {
				actual.State = models.ActualLRPStateUnclaimed
				actualLRPs = []*models.ActualLRP{actual}
			})

			Context("without a placement error", func() {
				BeforeEach(func() {
					actual.PlacementError = ""
					fakeEvacuationDB.EvacuateActualLRPReturns(afterActual, nil)
				})

				It("evacuates the LRP", func() {
					Expect(keepContainer).To(BeTrue())
					Expect(err).To(BeNil())

					Expect(fakeEvacuationDB.EvacuateActualLRPCallCount()).To(Equal(1))
					_, actualLRPKey, actualLRPInstanceKey, actualLrpNetInfo := fakeEvacuationDB.EvacuateActualLRPArgsForCall(0)
					Expect(*actualLRPKey).To(Equal(actual.ActualLRPKey))
					Expect(*actualLRPInstanceKey).To(Equal(actual.ActualLRPInstanceKey))
					Expect(*actualLrpNetInfo).To(Equal(actual.ActualLRPNetInfo))
				})

				It("emits events to the hub", func() {
					Eventually(actualHub.EmitCallCount).Should(Equal(1))

					event := actualHub.EmitArgsForCall(0)
					Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPCreatedEvent{}))
					ce := event.(*models.ActualLRPCreatedEvent)
					Expect(ce.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: afterActual}))
				})

				Context("when there's an existing evacuating on another cell", func() {
					BeforeEach(func() {
						actualLRPs = []*models.ActualLRP{actual, evacuatingActual}
					})

					It("does not error and does not keep the container", func() {
						Expect(keepContainer).To(BeFalse())
						Expect(err).To(BeNil())
					})
				})

				Context("when the lrp cannot be evacuated", func() {
					BeforeEach(func() {
						fakeEvacuationDB.EvacuateActualLRPReturns(nil, models.ErrActualLRPCannotBeEvacuated)
					})

					It("does not error and does not keep the container", func() {
						Expect(keepContainer).To(BeFalse())
						Expect(err).To(BeNil())
					})
				})

				Context("when evacuating the actual lrp fails for some other reason", func() {
					BeforeEach(func() {
						fakeEvacuationDB.EvacuateActualLRPReturns(nil, errors.New("didnt work"))
					})

					It("returns an error and keeps the container", func() {
						Expect(keepContainer).To(BeTrue())
						Expect(err).NotTo(BeNil())
						Expect(err.Error()).To(Equal("didnt work"))
					})
				})
			})

			Context("with a placement error", func() {
				BeforeEach(func() {
					actual.PlacementError = "jim kinda likes cats, but loves kittens"
				})

				It("does not remove the evacuating LRP", func() {
					Expect(keepContainer).To(BeTrue())
					Expect(err).To(BeNil())

					Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(0))
				})

				It("does not emit events to the hub", func() {
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})
			})
		})

		Context("when the instance is claimed", func() {
			BeforeEach(func() {
				actual.State = models.ActualLRPStateClaimed
				actualLRPs = []*models.ActualLRP{actual}
			})

			Context("and the evacuate request came", func() {
				Context("from a different cell than where the instance is claimed", func() {
					BeforeEach(func() {
						targetInstanceKey.CellId = "some-other-cell"
					})

					Context("and there's an existing evacuating on a different cell than where the evacuate request came from", func() {
						BeforeEach(func() {
							actualLRPs = []*models.ActualLRP{actual, evacuatingActual}
						})

						It("does not error and does not keep the container", func() {
							Expect(keepContainer).To(BeFalse())
							Expect(err).To(BeNil())
						})
					})

					Context("when there's an existing evacuating instance on the cell the request came from", func() {
						BeforeEach(func() {
							evacuatingActual.CellId = "some-other-cell"
							actualLRPs = []*models.ActualLRP{actual, evacuatingActual}
							fakeEvacuationDB.EvacuateActualLRPReturns(nil, models.ErrResourceExists)
						})

						It("does not error and keeps the container", func() {
							Expect(keepContainer).To(BeTrue())
							Expect(err).To(BeNil())
						})
					})

					Context("when evacuating the actual lrp fails", func() {
						BeforeEach(func() {
							fakeEvacuationDB.EvacuateActualLRPReturns(nil, errors.New("didnt work"))
						})

						It("returns an error and keeps the container", func() {
							Expect(keepContainer).To(BeTrue())
							Expect(err).NotTo(BeNil())
							Expect(err.Error()).To(Equal("didnt work"))
						})
					})

					Context("when the lrp cannot be evacuated", func() {
						BeforeEach(func() {
							fakeEvacuationDB.EvacuateActualLRPReturns(nil, models.ErrActualLRPCannotBeEvacuated)
						})

						It("does not error and does not keep the container", func() {
							Expect(keepContainer).To(BeFalse())
							Expect(err).To(BeNil())
						})
					})
				})

				Context("by the same cell", func() {
					BeforeEach(func() {
						fakeEvacuationDB.EvacuateActualLRPReturns(afterActual, nil)
					})

					It("evacuates the lrp", func() {
						Expect(keepContainer).To(BeTrue())
						Expect(err).To(BeNil())

						Expect(fakeEvacuationDB.EvacuateActualLRPCallCount()).To(Equal(1))
						_, actualLRPKey, actualLRPInstanceKey, actualLrpNetInfo := fakeEvacuationDB.EvacuateActualLRPArgsForCall(0)
						Expect(*actualLRPKey).To(Equal(actual.ActualLRPKey))
						Expect(*actualLRPInstanceKey).To(Equal(actual.ActualLRPInstanceKey))
						Expect(*actualLrpNetInfo).To(Equal(actual.ActualLRPNetInfo))
					})

					It("unclaims the lrp and requests an auction", func() {
						Expect(fakeActualLRPDB.UnclaimActualLRPCallCount()).To(Equal(1))
						_, actualLRPKey, actualLRPInstanceKey, actualLrpNetInfo := fakeEvacuationDB.EvacuateActualLRPArgsForCall(0)
						Expect(*actualLRPKey).To(Equal(actual.ActualLRPKey))
						Expect(*actualLRPInstanceKey).To(Equal(actual.ActualLRPInstanceKey))
						Expect(*actualLrpNetInfo).To(Equal(actual.ActualLRPNetInfo))

						schedulingInfo := desiredLRP.DesiredLRPSchedulingInfo()
						expectedStartRequest := auctioneer.NewLRPStartRequestFromSchedulingInfo(&schedulingInfo, int(actual.Index))

						Expect(fakeAuctioneerClient.RequestLRPAuctionsCallCount()).To(Equal(1))
						_, startRequests := fakeAuctioneerClient.RequestLRPAuctionsArgsForCall(0)
						Expect(startRequests).To(Equal([]*auctioneer.LRPStartRequest{&expectedStartRequest}))
					})

					It("emits events to the hub", func() {
						Eventually(actualHub.EmitCallCount).Should(Equal(2))

						event := actualHub.EmitArgsForCall(0)
						Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPCreatedEvent{}))
						ce := event.(*models.ActualLRPCreatedEvent)
						Expect(ce.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: afterActual}))

						event = actualHub.EmitArgsForCall(1)
						Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPChangedEvent{}))
						che := event.(*models.ActualLRPChangedEvent)
						Expect(che.Before).To(Equal(&models.ActualLRPGroup{Instance: actual}))
						Expect(che.After).To(Equal(&models.ActualLRPGroup{Instance: unclaimedActualLRP}))
					})

					Context("when evacuating fails", func() {
						BeforeEach(func() {
							fakeEvacuationDB.EvacuateActualLRPReturns(nil, errors.New("this is a disaster"))
						})

						It("returns an error and keep the container", func() {
							Expect(keepContainer).To(BeTrue())
							Expect(err).NotTo(BeNil())
							Expect(err.Error()).To(Equal("this is a disaster"))
						})
					})

					Context("when unclaiming fails", func() {
						BeforeEach(func() {
							fakeActualLRPDB.UnclaimActualLRPReturns(nil, nil, errors.New("unclaiming failed"))
						})

						It("returns an error and keeps the contianer", func() {
							Expect(keepContainer).To(BeTrue())
							Expect(err).NotTo(BeNil())
							Expect(err.Error()).To(Equal("unclaiming failed"))
						})
					})
				})
			})
		})

		Context("when the instance is running", func() {
			BeforeEach(func() {
				actual.State = models.ActualLRPStateRunning
				actualLRPs = []*models.ActualLRP{actual}
			})

			Context("on this cell", func() {
				BeforeEach(func() {
					fakeEvacuationDB.EvacuateActualLRPReturns(afterActual, nil)
				})

				It("evacuates the lrp and keeps the container", func() {
					Expect(keepContainer).To(BeTrue())
					Expect(err).To(BeNil())

					Expect(fakeEvacuationDB.EvacuateActualLRPCallCount()).To(Equal(1))
					_, actualLRPKey, actualLRPInstanceKey, actualLrpNetInfo := fakeEvacuationDB.EvacuateActualLRPArgsForCall(0)
					Expect(*actualLRPKey).To(Equal(actual.ActualLRPKey))
					Expect(*actualLRPInstanceKey).To(Equal(actual.ActualLRPInstanceKey))
					Expect(*actualLrpNetInfo).To(Equal(actual.ActualLRPNetInfo))
				})

				It("unclaims the lrp and requests an auction", func() {
					Expect(fakeActualLRPDB.UnclaimActualLRPCallCount()).To(Equal(1))
					_, lrpKey := fakeActualLRPDB.UnclaimActualLRPArgsForCall(0)
					Expect(lrpKey.ProcessGuid).To(Equal(actual.ProcessGuid))
					Expect(lrpKey.Index).To(Equal(actual.Index))

					schedulingInfo := desiredLRP.DesiredLRPSchedulingInfo()
					expectedStartRequest := auctioneer.NewLRPStartRequestFromSchedulingInfo(&schedulingInfo, int(actual.Index))

					Expect(fakeAuctioneerClient.RequestLRPAuctionsCallCount()).To(Equal(1))
					_, startRequests := fakeAuctioneerClient.RequestLRPAuctionsArgsForCall(0)
					Expect(startRequests).To(Equal([]*auctioneer.LRPStartRequest{&expectedStartRequest}))
				})

				Context("when the instance is suspect", func() {
					BeforeEach(func() {
						actual.Presence = models.ActualLRP_Suspect
						fakeSuspectDB.RemoveSuspectActualLRPReturns(actual, nil)
					})

					It("removes the suspect LRP", func() {
						Expect(fakeSuspectDB.RemoveSuspectActualLRPCallCount()).To(Equal(1))
						_, lrpKey := fakeSuspectDB.RemoveSuspectActualLRPArgsForCall(0)
						Expect(lrpKey.ProcessGuid).To(Equal(actual.ProcessGuid))
						Expect(lrpKey.Index).To(Equal(actual.Index))
					})

					It("does not unclaim the LRP", func() {
						Expect(fakeActualLRPDB.UnclaimActualLRPCallCount()).To(Equal(0))
					})

					It("emits a LRPCreated and then LRPRemoved event", func() {
						Eventually(actualHub.EmitCallCount).Should(Equal(2))
						Consistently(actualHub.EmitCallCount).Should(Equal(2))

						event := actualHub.EmitArgsForCall(0)
						Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPCreatedEvent{}))
						ce := event.(*models.ActualLRPCreatedEvent)
						Expect(ce.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: afterActual}))

						event = actualHub.EmitArgsForCall(1)
						Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPRemovedEvent{}))
						re := event.(*models.ActualLRPRemovedEvent)
						Expect(re.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Instance: actual}))
					})

					Context("when there is an ordinary claimed replacement LRP", func() {
						var replacementActual *models.ActualLRP

						BeforeEach(func() {
							replacementActual = model_helpers.NewValidActualLRP("the-guid", 1)
							replacementActual.State = models.ActualLRPStateClaimed
							replacementActual.CellId = "other-cell"
							replacementActual.InstanceGuid = "other-guid"
							actualLRPs = append(actualLRPs, replacementActual)
						})

						It("emits two LRPCreated events and then a LRPRemoved event", func() {
							Eventually(actualHub.EmitCallCount).Should(Equal(3))
							Consistently(actualHub.EmitCallCount).Should(Equal(3))

							event := actualHub.EmitArgsForCall(0)
							Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPCreatedEvent{}))
							ce := event.(*models.ActualLRPCreatedEvent)
							Expect(ce.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: afterActual}))

							event = actualHub.EmitArgsForCall(1)
							Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPCreatedEvent{}))
							ce = event.(*models.ActualLRPCreatedEvent)
							Expect(ce.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Instance: replacementActual}))

							event = actualHub.EmitArgsForCall(2)
							Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPRemovedEvent{}))
							re := event.(*models.ActualLRPRemovedEvent)
							Expect(re.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Instance: actual}))
						})
					})

					Context("when removing the suspect lrp fails", func() {
						BeforeEach(func() {
							fakeSuspectDB.RemoveSuspectActualLRPReturns(nil, errors.New("didnt work"))
						})

						It("does not emit an LRPRemoved event", func() {
							Eventually(actualHub.EmitCallCount).Should(Equal(1))
							event := actualHub.EmitArgsForCall(0)
							Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPCreatedEvent{}))
							Consistently(actualHub.EmitCallCount).Should(Equal(1))
						})

						It("logs the failure", func() {
							Eventually(logger).Should(gbytes.Say("failed-removing-suspect-actual-lrp"))
						})
					})

					Context("when removing the suspect LRP fails with an unrecoverable error", func() {
						BeforeEach(func() {
							fakeSuspectDB.RemoveSuspectActualLRPReturns(nil, models.NewUnrecoverableError(nil))
						})

						It("logs and writes to the exit channel", func() {
							Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
						})
					})
				})

				It("emits an LRPCreated event and then an LRPChanged event to the hub", func() {
					Eventually(actualHub.EmitCallCount).Should(Equal(2))

					event := actualHub.EmitArgsForCall(0)
					Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPCreatedEvent{}))
					ce := event.(*models.ActualLRPCreatedEvent)
					Expect(ce.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: afterActual}))

					event = actualHub.EmitArgsForCall(1)
					Expect(event).To(BeAssignableToTypeOf(&models.ActualLRPChangedEvent{}))
					che := event.(*models.ActualLRPChangedEvent)
					Expect(che.Before).To(Equal(&models.ActualLRPGroup{Instance: actual}))
					Expect(che.After).To(Equal(&models.ActualLRPGroup{Instance: unclaimedActualLRP}))
				})

				Context("when evacuating fails", func() {
					BeforeEach(func() {
						fakeEvacuationDB.EvacuateActualLRPReturns(nil, errors.New("this is a disaster"))
					})

					It("returns an error and keep the container", func() {
						Expect(keepContainer).To(BeTrue())
						Expect(err).NotTo(BeNil())
						Expect(err.Error()).To(Equal("this is a disaster"))
					})
				})

				Context("when unclaiming fails", func() {
					BeforeEach(func() {
						fakeActualLRPDB.UnclaimActualLRPReturns(nil, nil, errors.New("unclaiming failed"))
					})

					It("returns an error and keeps the container", func() {
						Expect(keepContainer).To(BeTrue())
						Expect(err).NotTo(BeNil())
						Expect(err.Error()).To(Equal("unclaiming failed"))
					})
				})

				Context("when fetching the desired lrp fails", func() {
					BeforeEach(func() {
						fakeDesiredLRPDB.DesiredLRPByProcessGuidReturns(nil, errors.New("jolly rancher beer :/"))
					})

					It("does not return an error and keeps the container", func() {
						Expect(keepContainer).To(BeTrue())
						Expect(err).To(BeNil())
					})
				})
			})

			Context("on another cell with an evacuating instance on the cell where the request comes from", func() {
				BeforeEach(func() {
					targetInstanceKey.CellId = "some-evacuating-cell"
					actualLRPs = []*models.ActualLRP{actual, evacuatingActual}
				})

				It("removes the evacuating LRP", func() {
					Expect(keepContainer).To(BeFalse())
					Expect(err).To(BeNil())

					Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(1))
					_, actualLRPKey, actualLRPInstanceKey := fakeEvacuationDB.RemoveEvacuatingActualLRPArgsForCall(0)
					Expect(*actualLRPKey).To(Equal(evacuatingActual.ActualLRPKey))
					Expect(*actualLRPInstanceKey).To(Equal(evacuatingActual.ActualLRPInstanceKey))
				})

				It("emits events to the hub", func() {
					Eventually(actualHub.EmitCallCount).Should(Equal(1))
					event := actualHub.EmitArgsForCall(0)
					removeEvent, ok := event.(*models.ActualLRPRemovedEvent)
					Expect(ok).To(BeTrue())
					Expect(removeEvent.ActualLrpGroup).To(Equal(&models.ActualLRPGroup{Evacuating: evacuatingActual}))
				})

				Context("when removing the evacuating LRP fails", func() {
					BeforeEach(func() {
						fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(errors.New("boom!"))
					})

					It("returns an error and does keep the container", func() {
						Expect(keepContainer).To(BeTrue())
						Expect(err).NotTo(BeNil())
						Expect(err.Error()).To(Equal("boom!"))
					})

					Context("when the error is a ErrActualLRPCannotBeRemoved", func() {
						BeforeEach(func() {
							fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(models.ErrActualLRPCannotBeRemoved)
						})

						It("does not return an error or keep the container", func() {
							Expect(keepContainer).To(BeFalse())
							Expect(err).To(BeNil())
						})
					})
				})

				Context("and there is no evacuating lrp", func() {
					BeforeEach(func() {
						actualLRPs = []*models.ActualLRP{actual}
					})

					It("responds with KeepContainer set to false", func() {
						Expect(keepContainer).To(BeFalse())
						Expect(err).To(BeNil())
					})
				})
			})
		})

		Context("when the instance is crashed", func() {
			BeforeEach(func() {
				actual.State = models.ActualLRPStateCrashed
				actualLRPs = []*models.ActualLRP{actual, evacuatingActual}
			})

			It("removes the evacuating LRP", func() {
				Expect(keepContainer).To(BeFalse())
				Expect(err).To(BeNil())

				Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(1))
				_, actualLRPKey, actualLRPInstanceKey := fakeEvacuationDB.RemoveEvacuatingActualLRPArgsForCall(0)
				Expect(*actualLRPKey).To(Equal(evacuatingActual.ActualLRPKey))
				Expect(*actualLRPInstanceKey).To(Equal(evacuatingActual.ActualLRPInstanceKey))
			})

			Context("when removing the evacuating LRP fails", func() {
				BeforeEach(func() {
					fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(errors.New("boom!"))
				})

				It("returns an error and does keep the container", func() {
					Expect(keepContainer).To(BeTrue())
					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(Equal("boom!"))
				})

				Context("when the error is a ErrActualLRPCannotBeRemoved", func() {
					BeforeEach(func() {
						fakeEvacuationDB.RemoveEvacuatingActualLRPReturns(models.ErrActualLRPCannotBeRemoved)
					})

					It("does not return an error or keep the container", func() {
						Expect(keepContainer).To(BeFalse())
						Expect(err).To(BeNil())
					})
				})
			})
		})

		Context("when the actual lrps do not exist", func() {
			BeforeEach(func() {
				actualLRPs = []*models.ActualLRP{}
			})

			It("does not return an error or keep the container", func() {
				Expect(keepContainer).To(BeFalse())
				Expect(err).To(BeNil())
			})
		})
	})

	Describe("EvacuateStoppedActualLRP", func() {
		var (
			actual, evacuating *models.ActualLRP
			targetInstanceKey  models.ActualLRPInstanceKey
			targetKey          models.ActualLRPKey

			err      error
			modelErr *models.Error
		)

		BeforeEach(func() {
			actual = model_helpers.NewValidActualLRP("process-guid", 1)
			evacuating = model_helpers.NewValidEvacuatingActualLRP("process-guid", 1)

			fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{
				actual,
				evacuating,
			}, nil)

			targetInstanceKey = actual.ActualLRPInstanceKey
			targetKey = actual.ActualLRPKey
		})

		JustBeforeEach(func() {
			err = controller.EvacuateStoppedActualLRP(logger, &targetKey, &targetInstanceKey)
			modelErr = models.ConvertError(err)
		})

		It("emits an ActualLRPGroup event for the removal of the non-evacuating instance", func() {
			Eventually(actualHub.EmitCallCount).Should(Equal(1))
			events := []models.Event{}

			events = append(events, actualHub.EmitArgsForCall(0))

			Expect(events).To(ConsistOf(
				models.NewActualLRPRemovedEvent(&models.ActualLRPGroup{Instance: actual}),
			))
		})

		It("does not error and does not keep the container", func() {
			Expect(err).To(BeNil())
		})

		It("removes the actual lrp", func() {
			Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(0))
			Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(1))

			_, guid, index, actualLRPInstanceKey := fakeActualLRPDB.RemoveActualLRPArgsForCall(0)
			Expect(guid).To(Equal("process-guid"))
			Expect(index).To(BeEquivalentTo(1))
			Expect(actualLRPInstanceKey).To(Equal(&actual.ActualLRPInstanceKey))
		})

		Context("when the LRP Instance is missing", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{}, nil)
			})

			It("returns an error", func() {
				Expect(err).To(Equal(models.ErrResourceNotFound))
			})
		})

		Context("when the LRP presence is Suspect", func() {
			BeforeEach(func() {
				actual.Presence = models.ActualLRP_Suspect
				fakeSuspectDB.RemoveSuspectActualLRPReturns(actual, nil)
				fakeActualLRPDB.ActualLRPsReturns([]*models.ActualLRP{actual}, nil)
			})

			It("removes the suspect lrp", func() {
				Expect(fakeSuspectDB.RemoveSuspectActualLRPCallCount()).To(Equal(1))
				Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(0))
				Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(0))

				_, lrpKey := fakeSuspectDB.RemoveSuspectActualLRPArgsForCall(0)
				Expect(lrpKey.ProcessGuid).To(Equal(actual.ProcessGuid))
				Expect(lrpKey.Index).To(Equal(actual.Index))
			})

			It("emits ActualLRPRemovedEvent", func() {
				Eventually(actualHub.EmitCallCount).Should(Equal(1))
				events := []models.Event{}
				events = append(events, actualHub.EmitArgsForCall(0))
				Expect(events).To(ConsistOf(models.NewActualLRPRemovedEvent(&models.ActualLRPGroup{Instance: actual})))
			})

			Context("when the DB returns an unrecoverable error", func() {
				BeforeEach(func() {
					fakeSuspectDB.RemoveSuspectActualLRPReturns(nil, models.NewUnrecoverableError(nil))
				})

				It("logs and writes to the exit channel", func() {
					Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
				})
			})

			Context("when removing the suspect actual lrp fails", func() {
				BeforeEach(func() {
					fakeSuspectDB.RemoveSuspectActualLRPReturns(nil, errors.New("boom!"))
				})

				It("logs the failure", func() {
					Eventually(logger).Should(gbytes.Say("failed-removing-suspect-actual-lrp"))
				})

				It("does not emit any events", func() {
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})
			})
		})

		Context("when the LRP presence is Evacuating", func() {
			BeforeEach(func() {
				targetInstanceKey = evacuating.ActualLRPInstanceKey
			})

			It("removes the evacuating actual lrp", func() {
				Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(1))
				Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(0))

				_, lrpKey, lrpInstanceKey := fakeEvacuationDB.RemoveEvacuatingActualLRPArgsForCall(0)
				Expect(*lrpKey).To(Equal(evacuating.ActualLRPKey))
				Expect(*lrpInstanceKey).To(Equal(evacuating.ActualLRPInstanceKey))
			})

			It("emits a removal event for the evacuating actual LRP", func() {
				Eventually(actualHub.EmitCallCount).Should(Equal(1))
				events := []models.Event{}
				events = append(events, actualHub.EmitArgsForCall(0))
				Expect(events).To(ConsistOf(models.NewActualLRPRemovedEvent(&models.ActualLRPGroup{Evacuating: evacuating})))

			})
		})

		Context("when the actual lrp is on a different cell", func() {
			BeforeEach(func() {
				targetInstanceKey.CellId = "different-cell"
			})

			It("returns an error but does not keep the container", func() {
				Expect(modelErr).To(MatchError(models.ErrResourceNotFound))
			})

			It("does not remove anything actual LRPs", func() {
				Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(0))
				Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(0))
				Expect(fakeSuspectDB.RemoveSuspectActualLRPCallCount()).To(Equal(0))
			})
		})

		Describe("database error cases", func() {
			Context("when removing ActualLRPs from the database returns an unrecoverable error", func() {
				BeforeEach(func() {
					fakeActualLRPDB.RemoveActualLRPReturns(models.NewUnrecoverableError(nil))
				})

				It("logs and writes to the exit channel", func() {
					Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
				})

				It("does not make any additional attempts to remove the ActualLRP and emits no events", func() {
					Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(0))
					Expect(fakeSuspectDB.RemoveSuspectActualLRPCallCount()).To(Equal(0))
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})
			})

			Context("when fetching the ActualLRPs from the database returns an unrecoverable error", func() {
				BeforeEach(func() {
					fakeActualLRPDB.ActualLRPsReturns(nil, models.NewUnrecoverableError(nil))
				})

				It("logs and writes to the exit channel", func() {
					Expect(modelErr.Type).To(Equal(models.Error_Unrecoverable))
				})

				It("does not make any attempts to remove the ActualLRP and emits no events", func() {
					Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(0))
					Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(0))
					Expect(fakeSuspectDB.RemoveSuspectActualLRPCallCount()).To(Equal(0))
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})
			})

			Context("when removing ActualLRPs from the database returns a recoverable error", func() {
				BeforeEach(func() {
					fakeActualLRPDB.RemoveActualLRPReturns(errors.New("boom!"))
				})

				It("returns an error but does not keep the container", func() {
					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(Equal("boom!"))
				})

				It("does not make any additional attempts to remove the ActualLRP", func() {
					Expect(fakeSuspectDB.RemoveSuspectActualLRPCallCount()).To(Equal(0))
					Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(0))
				})

				It("emits no events because nothing was removed", func() {
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})
			})

			Context("when fetching the AcutalLRPs from the database returns a recoverable error ", func() {
				BeforeEach(func() {
					fakeActualLRPDB.ActualLRPsReturns(nil, errors.New("i failed"))
				})

				It("returns an error but does not keep the container", func() {
					Expect(err).NotTo(BeNil())
					Expect(err.Error()).To(Equal("i failed"))
				})

				It("does not make any additional attempts to remove the ActualLRP", func() {
					Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(0))
					Expect(fakeSuspectDB.RemoveSuspectActualLRPCallCount()).To(Equal(0))
					Expect(fakeEvacuationDB.RemoveEvacuatingActualLRPCallCount()).To(Equal(0))
				})

				It("does not emit any events", func() {
					Consistently(actualHub.EmitCallCount).Should(Equal(0))
				})
			})
		})
	})
})
