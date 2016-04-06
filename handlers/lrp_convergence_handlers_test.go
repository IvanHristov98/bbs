package handlers_test

import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/cloudfoundry-incubator/auctioneer"
	"github.com/cloudfoundry-incubator/auctioneer/auctioneerfakes"
	"github.com/cloudfoundry-incubator/bbs/db/fakes"
	"github.com/cloudfoundry-incubator/bbs/events/eventfakes"
	"github.com/cloudfoundry-incubator/bbs/fake_bbs"
	"github.com/cloudfoundry-incubator/bbs/handlers"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/bbs/models/test/model_helpers"
	"github.com/cloudfoundry-incubator/rep/repfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/lager"
)

var _ = Describe("LRP Convergence Handlers", func() {
	var (
		logger               lager.Logger
		fakeLRPDB            *fakes.FakeLRPDB
		responseRecorder     *httptest.ResponseRecorder
		fakeAuctioneerClient *auctioneerfakes.FakeClient

		keysToAuction []*auctioneer.LRPStartRequest
		keysToRetire  []*models.ActualLRPKey

		retiringActualLRP1 *models.ActualLRP
		retiringActualLRP2 *models.ActualLRP

		cellID  string
		cellSet models.CellSet

		handler *handlers.LRPConvergenceHandler
	)

	BeforeEach(func() {
		fakeLRPDB = new(fakes.FakeLRPDB)
		fakeAuctioneerClient = new(auctioneerfakes.FakeClient)
		logger = lager.NewLogger("test")

		request1 := auctioneer.NewLRPStartRequestFromModel(model_helpers.NewValidDesiredLRP("to-auction-1"), 1, 2)
		request2 := auctioneer.NewLRPStartRequestFromModel(model_helpers.NewValidDesiredLRP("to-auction-2"), 0, 4)
		keysToAuction = []*auctioneer.LRPStartRequest{&request1, &request2}

		retiringActualLRP1 = model_helpers.NewValidActualLRP("to-retire-1", 0)
		retiringActualLRP2 = model_helpers.NewValidActualLRP("to-retire-2", 1)
		keysToRetire = []*models.ActualLRPKey{&retiringActualLRP1.ActualLRPKey, &retiringActualLRP2.ActualLRPKey}

		cellID = "cell-id"
		instanceKey := models.NewActualLRPInstanceKey("instance-guid", cellID)

		retiringActualLRP1.CellId = cellID
		retiringActualLRP1.ActualLRPInstanceKey = instanceKey
		retiringActualLRP1.State = models.ActualLRPStateClaimed
		group1 := &models.ActualLRPGroup{Instance: retiringActualLRP1}

		retiringActualLRP2.CellId = cellID
		retiringActualLRP2.ActualLRPInstanceKey = instanceKey
		retiringActualLRP2.State = models.ActualLRPStateClaimed
		group2 := &models.ActualLRPGroup{Instance: retiringActualLRP2}

		fakeLRPDB.ActualLRPGroupByProcessGuidAndIndexStub = func(_ lager.Logger, processGuid string, _ int32) (*models.ActualLRPGroup, error) {
			if processGuid == retiringActualLRP1.ProcessGuid {
				return group1, nil
			}
			if processGuid == retiringActualLRP2.ProcessGuid {
				return group2, nil
			}

			return nil, models.ErrResourceNotFound
		}

		fakeLRPDB.ConvergeLRPsReturns(keysToAuction, keysToRetire)

		logger.RegisterSink(lager.NewWriterSink(GinkgoWriter, lager.DEBUG))
		responseRecorder = httptest.NewRecorder()

		fakeServiceClient = new(fake_bbs.FakeServiceClient)
		fakeRepClientFactory = new(repfakes.FakeClientFactory)
		fakeRepClient = new(repfakes.FakeClient)
		fakeRepClientFactory.CreateClientReturns(fakeRepClient)
		fakeServiceClient.CellByIdReturns(nil, errors.New("hi"))

		cellPresence := models.NewCellPresence("cell-id", "1.1.1.1", "z1", models.CellCapacity{}, nil, nil)
		cellSet = models.CellSet{"cell-id": &cellPresence}
		fakeServiceClient.CellsReturns(cellSet, nil)

		actualHub := &eventfakes.FakeHub{}
		retirer := handlers.NewActualLRPRetirer(fakeLRPDB, actualHub, fakeRepClientFactory, fakeServiceClient)
		handler = handlers.NewLRPConvergenceHandler(logger, fakeLRPDB, fakeAuctioneerClient, fakeServiceClient, retirer, 2)
	})

	JustBeforeEach(func() {
		handler.ConvergeLRPs(responseRecorder, nil)
	})

	It("calls ConvergeLRPs", func() {
		Expect(responseRecorder.Code).To(Equal(http.StatusOK))
		Expect(fakeLRPDB.ConvergeLRPsCallCount()).To(Equal(1))
		_, actualCellSet := fakeLRPDB.ConvergeLRPsArgsForCall(0)
		Expect(actualCellSet).To(BeEquivalentTo(cellSet))
	})

	Context("when fetching the cells fails", func() {
		BeforeEach(func() {
			fakeServiceClient.CellsReturns(nil, errors.New("kaboom"))
		})

		It("does not call ConvergeLRPs", func() {
			Expect(responseRecorder.Code).To(Equal(http.StatusOK))
			Expect(fakeLRPDB.ConvergeLRPsCallCount()).To(Equal(0))
		})
	})

	Context("when fetching the cells returns ErrResourceNotFound", func() {
		BeforeEach(func() {
			fakeServiceClient.CellsReturns(nil, models.ErrResourceNotFound)
		})

		It("calls ConvergeLRPs with an empty CellSet", func() {
			Expect(responseRecorder.Code).To(Equal(http.StatusOK))
			Expect(fakeLRPDB.ConvergeLRPsCallCount()).To(Equal(1))
			_, actualCellSet := fakeLRPDB.ConvergeLRPsArgsForCall(0)
			Expect(actualCellSet).To(BeEquivalentTo(models.CellSet{}))
		})
	})

	It("auctions off the returned keys", func() {
		Expect(fakeAuctioneerClient.RequestLRPAuctionsCallCount()).To(Equal(1))

		startAuctions := fakeAuctioneerClient.RequestLRPAuctionsArgsForCall(0)
		Expect(startAuctions).To(HaveLen(2))
		Expect(startAuctions).To(ConsistOf(keysToAuction))
	})

	It("auctions off the returned keys", func() {
		Expect(fakeAuctioneerClient.RequestLRPAuctionsCallCount()).To(Equal(1))

		startAuctions := fakeAuctioneerClient.RequestLRPAuctionsArgsForCall(0)
		Expect(startAuctions).To(HaveLen(2))
		Expect(startAuctions).To(ConsistOf(keysToAuction))
	})

	Describe("stopping extra LRPs", func() {
		var (
			cellPresence models.CellPresence
		)

		Context("when the cell", func() {
			Context("is present", func() {
				BeforeEach(func() {
					cellPresence = models.NewCellPresence(
						cellID,
						"cell1.addr",
						"the-zone",
						models.NewCellCapacity(128, 1024, 6),
						[]string{},
						[]string{},
					)

					fakeServiceClient.CellByIdReturns(&cellPresence, nil)
				})

				It("stops the LRPs", func() {
					Expect(fakeRepClientFactory.CreateClientCallCount()).To(Equal(2))
					Expect(fakeRepClientFactory.CreateClientArgsForCall(0)).To(Equal(cellPresence.RepAddress))
					Expect(fakeRepClientFactory.CreateClientArgsForCall(1)).To(Equal(cellPresence.RepAddress))

					Expect(fakeServiceClient.CellByIdCallCount()).To(Equal(2))
					_, fetchedCellID := fakeServiceClient.CellByIdArgsForCall(0)
					Expect(fetchedCellID).To(Equal(cellID))
					_, fetchedCellID = fakeServiceClient.CellByIdArgsForCall(1)
					Expect(fetchedCellID).To(Equal(cellID))

					Expect(fakeRepClient.StopLRPInstanceCallCount()).Should(Equal(2))

					stoppedKeys := make([]models.ActualLRPKey, 2)
					stoppedInstanceKeys := make([]models.ActualLRPInstanceKey, 2)

					for i := 0; i < 2; i++ {
						stoppedKey, stoppedInstanceKey := fakeRepClient.StopLRPInstanceArgsForCall(i)
						stoppedKeys[i] = stoppedKey
						stoppedInstanceKeys[i] = stoppedInstanceKey
					}

					Expect(stoppedKeys).To(ContainElement(retiringActualLRP1.ActualLRPKey))
					Expect(stoppedInstanceKeys).To(ContainElement(retiringActualLRP1.ActualLRPInstanceKey))

					Expect(stoppedKeys).To(ContainElement(retiringActualLRP2.ActualLRPKey))
					Expect(stoppedInstanceKeys).To(ContainElement(retiringActualLRP2.ActualLRPInstanceKey))
				})
			})

			Context("is not present", func() {
				BeforeEach(func() {
					fakeServiceClient.CellByIdReturns(nil,
						&models.Error{
							Type:    models.Error_ResourceNotFound,
							Message: "cell not found",
						})
				})

				Context("removing the actualLRP succeeds", func() {
					It("removes the LRPs", func() {
						Expect(fakeLRPDB.RemoveActualLRPCallCount()).To(Equal(2))
						deletedLRPGuids := make([]string, 2)
						deletedLRPIndicies := make([]int32, 2)

						for i := 0; i < 2; i++ {
							_, deletedLRPGuid, deletedLRPIndex := fakeLRPDB.RemoveActualLRPArgsForCall(i)
							deletedLRPGuids[i] = deletedLRPGuid
							deletedLRPIndicies[i] = deletedLRPIndex
						}

						Expect(deletedLRPGuids).To(ContainElement(retiringActualLRP1.ProcessGuid))
						Expect(deletedLRPIndicies).To(ContainElement(retiringActualLRP1.Index))

						Expect(deletedLRPGuids).To(ContainElement(retiringActualLRP2.ProcessGuid))
						Expect(deletedLRPIndicies).To(ContainElement(retiringActualLRP2.Index))
					})
				})
			})
		})
	})
})
