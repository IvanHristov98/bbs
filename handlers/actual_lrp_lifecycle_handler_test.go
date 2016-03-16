package handlers_test

import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/cloudfoundry-incubator/auctioneer"
	"github.com/cloudfoundry-incubator/auctioneer/auctioneerfakes"
	"github.com/cloudfoundry-incubator/bbs/db/fakes"
	"github.com/cloudfoundry-incubator/bbs/fake_bbs"
	"github.com/cloudfoundry-incubator/bbs/handlers"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/rep/repfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/lager"
)

var _ = Describe("ActualLRP Lifecycle Handlers", func() {
	var (
		logger               lager.Logger
		fakeActualLRPDB      *fakes.FakeActualLRPDB
		fakeDesiredLRPDB     *fakes.FakeDesiredLRPDB
		fakeAuctioneerClient *auctioneerfakes.FakeClient
		responseRecorder     *httptest.ResponseRecorder
		handler              *handlers.ActualLRPLifecycleHandler

		actualLRP models.ActualLRP

		fakeServiceClient    *fake_bbs.FakeServiceClient
		fakeRepClientFactory *repfakes.FakeClientFactory
		fakeRepClient        *repfakes.FakeClient
	)

	BeforeEach(func() {
		fakeActualLRPDB = new(fakes.FakeActualLRPDB)
		fakeAuctioneerClient = new(auctioneerfakes.FakeClient)
		fakeDesiredLRPDB = new(fakes.FakeDesiredLRPDB)
		logger = lager.NewLogger("test")
		logger.RegisterSink(lager.NewWriterSink(GinkgoWriter, lager.DEBUG))
		responseRecorder = httptest.NewRecorder()

		fakeServiceClient = new(fake_bbs.FakeServiceClient)
		fakeRepClientFactory = new(repfakes.FakeClientFactory)
		fakeRepClient = new(repfakes.FakeClient)
		fakeRepClientFactory.CreateClientReturns(fakeRepClient)

		handler = handlers.NewActualLRPLifecycleHandler(logger, fakeActualLRPDB, fakeDesiredLRPDB, fakeAuctioneerClient, fakeRepClientFactory, fakeServiceClient)
	})

	Describe("ClaimActualLRP", func() {
		var (
			processGuid       = "process-guid"
			index       int32 = 1
			instanceKey models.ActualLRPInstanceKey
			requestBody interface{}
		)

		BeforeEach(func() {
			instanceKey = models.NewActualLRPInstanceKey(
				"instance-guid-0",
				"cell-id-0",
			)
			requestBody = &instanceKey
			requestBody = &models.ClaimActualLRPRequest{
				ProcessGuid:          processGuid,
				Index:                index,
				ActualLrpInstanceKey: &instanceKey,
			}
			actualLRP = models.ActualLRP{
				ActualLRPKey: models.NewActualLRPKey(
					processGuid,
					1,
					"domain-0",
				),
				State: models.ActualLRPStateUnclaimed,
				Since: 1138,
			}
		})

		JustBeforeEach(func() {
			request := newTestRequest(requestBody)
			handler.ClaimActualLRP(responseRecorder, request)
		})

		Context("when claiming the actual lrp in the DB succeeds", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ClaimActualLRPReturns(nil)
			})

			It("response with no error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(BeNil())
			})

			It("claims the actual lrp by process guid and index", func() {
				Expect(fakeActualLRPDB.ClaimActualLRPCallCount()).To(Equal(1))
				_, actualProcessGuid, actualIndex, actualInstanceKey := fakeActualLRPDB.ClaimActualLRPArgsForCall(0)
				Expect(actualProcessGuid).To(Equal(processGuid))
				Expect(actualIndex).To(BeEquivalentTo(index))
				Expect(*actualInstanceKey).To(Equal(instanceKey))
			})
		})

		Context("when claiming the actual lrp fails", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ClaimActualLRPReturns(models.ErrUnknownError)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrUnknownError))
			})
		})

		Context("when we cannot find the resource", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ClaimActualLRPReturns(models.ErrResourceNotFound)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrResourceNotFound))
			})
		})
	})

	Describe("StartActualLRP", func() {
		var (
			processGuid = "process-guid"
			index       = int32(1)

			key         models.ActualLRPKey
			instanceKey models.ActualLRPInstanceKey
			netInfo     models.ActualLRPNetInfo

			requestBody interface{}
		)

		BeforeEach(func() {
			key = models.NewActualLRPKey(
				processGuid,
				index,
				"domain-0",
			)
			instanceKey = models.NewActualLRPInstanceKey(
				"instance-guid-0",
				"cell-id-0",
			)
			netInfo = models.NewActualLRPNetInfo("1.1.1.1", models.NewPortMapping(10, 20))
			requestBody = &models.StartActualLRPRequest{
				ActualLrpKey:         &key,
				ActualLrpInstanceKey: &instanceKey,
				ActualLrpNetInfo:     &netInfo,
			}

			actualLRP = models.ActualLRP{
				ActualLRPKey: key,
				State:        models.ActualLRPStateUnclaimed,
				Since:        1138,
			}
		})

		JustBeforeEach(func() {
			request := newTestRequest(requestBody)
			handler.StartActualLRP(responseRecorder, request)
		})

		Context("when starting the actual lrp in the DB succeeds", func() {
			BeforeEach(func() {
				fakeActualLRPDB.StartActualLRPReturns(nil)
			})

			It("response with no error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(BeNil())
			})

			It("starts the actual lrp by process guid and index", func() {
				Expect(fakeActualLRPDB.StartActualLRPCallCount()).To(Equal(1))
				_, actualKey, actualInstanceKey, actualNetInfo := fakeActualLRPDB.StartActualLRPArgsForCall(0)
				Expect(*actualKey).To(Equal(key))
				Expect(*actualInstanceKey).To(Equal(instanceKey))
				Expect(*actualNetInfo).To(Equal(netInfo))
			})
		})

		Context("when starting the actual lrp fails", func() {
			BeforeEach(func() {
				fakeActualLRPDB.StartActualLRPReturns(models.ErrUnknownError)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrUnknownError))
			})
		})

		Context("when we cannot find the resource", func() {
			BeforeEach(func() {
				fakeActualLRPDB.StartActualLRPReturns(models.ErrResourceNotFound)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrResourceNotFound))
			})
		})
	})

	Describe("CrashActualLRP", func() {
		var (
			processGuid  = "process-guid"
			index        = int32(1)
			instanceGuid = "instance-guid"
			cellId       = "cell-id"

			key          models.ActualLRPKey
			instanceKey  models.ActualLRPInstanceKey
			errorMessage string

			requestBody interface{}
		)

		BeforeEach(func() {
			key = models.NewActualLRPKey(
				processGuid,
				index,
				"domain-0",
			)
			instanceKey = models.NewActualLRPInstanceKey(instanceGuid, cellId)
			errorMessage = "something went wrong"
			requestBody = &models.CrashActualLRPRequest{
				ActualLrpKey:         &key,
				ActualLrpInstanceKey: &instanceKey,
				ErrorMessage:         errorMessage,
			}
		})

		JustBeforeEach(func() {
			request := newTestRequest(requestBody)
			handler.CrashActualLRP(responseRecorder, request)
		})

		Context("when crashing the actual lrp in the DB succeeds", func() {
			var desiredLRP *models.DesiredLRP

			BeforeEach(func() {
				desiredLRP = &models.DesiredLRP{
					ProcessGuid: "process-guid",
					Domain:      "some-domain",
					RootFs:      "some-stack",
					MemoryMb:    128,
					DiskMb:      512,
				}

				fakeDesiredLRPDB.DesiredLRPByProcessGuidReturns(desiredLRP, nil)
				fakeActualLRPDB.CrashActualLRPReturns(true, nil)
			})

			It("response with no error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(BeNil())
			})

			It("crashes the actual lrp by process guid and index", func() {
				Expect(fakeActualLRPDB.CrashActualLRPCallCount()).To(Equal(1))
				_, actualKey, actualInstanceKey, actualErrorMessage := fakeActualLRPDB.CrashActualLRPArgsForCall(0)
				Expect(*actualKey).To(Equal(key))
				Expect(*actualInstanceKey).To(Equal(instanceKey))
				Expect(actualErrorMessage).To(Equal(errorMessage))
			})

			Describe("restarting the instance", func() {
				Context("when the actual LRP should be restarted", func() {
					It("request an auction", func() {
						Expect(responseRecorder.Code).To(Equal(http.StatusOK))
						response := &models.ActualLRPLifecycleResponse{}
						err := response.Unmarshal(responseRecorder.Body.Bytes())
						Expect(err).NotTo(HaveOccurred())

						Expect(response.Error).To(BeNil())

						Expect(fakeDesiredLRPDB.DesiredLRPByProcessGuidCallCount()).To(Equal(1))
						_, processGuid := fakeDesiredLRPDB.DesiredLRPByProcessGuidArgsForCall(0)
						Expect(processGuid).To(Equal("process-guid"))

						Expect(fakeAuctioneerClient.RequestLRPAuctionsCallCount()).To(Equal(1))
						startRequests := fakeAuctioneerClient.RequestLRPAuctionsArgsForCall(0)
						Expect(startRequests).To(HaveLen(1))
						schedulingInfo := desiredLRP.DesiredLRPSchedulingInfo()
						expectedStartRequest := auctioneer.NewLRPStartRequestFromSchedulingInfo(&schedulingInfo, 1)
						Expect(startRequests[0]).To(BeEquivalentTo(&expectedStartRequest))
					})
				})

				Context("when the actual lrp should not be restarted (e.g., crashed)", func() {
					BeforeEach(func() {
						fakeActualLRPDB.CrashActualLRPReturns(false, nil)
					})

					It("does not request an auction", func() {
						Expect(responseRecorder.Code).To(Equal(http.StatusOK))
						response := &models.ActualLRPLifecycleResponse{}
						err := response.Unmarshal(responseRecorder.Body.Bytes())
						Expect(err).NotTo(HaveOccurred())
						Expect(response.Error).To(BeNil())

						Expect(fakeAuctioneerClient.RequestLRPAuctionsCallCount()).To(Equal(0))
					})
				})

				Context("when fetching the desired lrp fails", func() {
					BeforeEach(func() {
						fakeDesiredLRPDB.DesiredLRPByProcessGuidReturns(nil, errors.New("error occured"))
					})

					It("fails and does not request an auction", func() {
						Expect(responseRecorder.Code).To(Equal(http.StatusOK))
						response := &models.ActualLRPLifecycleResponse{}
						err := response.Unmarshal(responseRecorder.Body.Bytes())
						Expect(err).NotTo(HaveOccurred())
						Expect(response.Error.Error()).To(Equal("error occured"))

						Expect(fakeAuctioneerClient.RequestLRPAuctionsCallCount()).To(Equal(0))
					})
				})

				Context("when requesting the auction fails", func() {
					BeforeEach(func() {
						fakeAuctioneerClient.RequestLRPAuctionsReturns(errors.New("some else bid higher"))
					})

					It("returns an error", func() {
						Expect(responseRecorder.Code).To(Equal(http.StatusOK))
						response := &models.ActualLRPLifecycleResponse{}
						err := response.Unmarshal(responseRecorder.Body.Bytes())
						Expect(err).NotTo(HaveOccurred())
						Expect(response.Error.Error()).To(Equal("some else bid higher"))
					})
				})
			})
		})

		Context("when crashing the actual lrp fails", func() {
			BeforeEach(func() {
				fakeActualLRPDB.CrashActualLRPReturns(false, models.ErrUnknownError)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrUnknownError))
			})
		})

		Context("when we cannot find the resource", func() {
			BeforeEach(func() {
				fakeActualLRPDB.CrashActualLRPReturns(false, models.ErrResourceNotFound)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrResourceNotFound))
			})
		})
	})

	Describe("RetireActualLRP", func() {
		var (
			request     *http.Request
			response    *models.ActualLRPLifecycleResponse
			processGuid = "process-guid"
			index       = int32(1)

			key models.ActualLRPKey

			requestBody interface{}

			actualLRPGroup *models.ActualLRPGroup
		)

		BeforeEach(func() {
			key = models.NewActualLRPKey(
				processGuid,
				index,
				"domain-0",
			)

			requestBody = &models.RetireActualLRPRequest{
				ActualLrpKey: &key,
			}

			actualLRP = models.ActualLRP{
				ActualLRPKey: key,
				State:        models.ActualLRPStateUnclaimed,
				Since:        1138,
			}

			actualLRPGroup = &models.ActualLRPGroup{
				Instance: &actualLRP,
			}
		})

		JustBeforeEach(func() {
			request = newTestRequest(requestBody)
			handler.RetireActualLRP(responseRecorder, request)

			response = &models.ActualLRPLifecycleResponse{}
			err := response.Unmarshal(responseRecorder.Body.Bytes())
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when finding the actualLRP fails", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ActualLRPGroupByProcessGuidAndIndexReturns(nil, errors.New("could not find lrp"))
			})

			It("returns an error and does not retry", func() {
				Expect(response.Error.Message).To(Equal("could not find lrp"))
				Expect(fakeActualLRPDB.ActualLRPGroupByProcessGuidAndIndexCallCount()).To(Equal(1))
			})
		})

		Context("when there is no instance in the actual lrp group", func() {
			BeforeEach(func() {
				actualLRPGroup.Instance = nil
				fakeActualLRPDB.ActualLRPGroupByProcessGuidAndIndexReturns(actualLRPGroup, nil)
			})

			It("returns an error and does not retry", func() {
				Expect(response.Error).To(Equal(models.ErrResourceNotFound))
				Expect(fakeActualLRPDB.ActualLRPGroupByProcessGuidAndIndexCallCount()).To(Equal(1))
			})
		})

		Context("with an Unclaimed LRP", func() {
			BeforeEach(func() {
				fakeActualLRPDB.ActualLRPGroupByProcessGuidAndIndexReturns(actualLRPGroup, nil)
			})

			It("removes the LRP", func() {
				Expect(response.Error).To(BeNil())
				Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(1))

				_, deletedLRPGuid, deletedLRPIndex := fakeActualLRPDB.RemoveActualLRPArgsForCall(0)
				Expect(deletedLRPGuid).To(Equal(processGuid))
				Expect(deletedLRPIndex).To(Equal(index))
			})

			Context("when removing the actual lrp fails", func() {
				BeforeEach(func() {
					fakeActualLRPDB.RemoveActualLRPReturns(errors.New("boom!"))
				})

				It("retries removing up to RetireActualLRPRetryAttempts times", func() {
					Expect(response.Error.Message).To(Equal("boom!"))
					Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(5))
					Expect(fakeActualLRPDB.ActualLRPGroupByProcessGuidAndIndexCallCount()).To(Equal(5))
				})
			})
		})

		Context("when the LRP is crashed", func() {
			BeforeEach(func() {
				actualLRPGroup.Instance.State = models.ActualLRPStateCrashed
				fakeActualLRPDB.ActualLRPGroupByProcessGuidAndIndexReturns(actualLRPGroup, nil)
			})

			It("removes the LRP", func() {
				Expect(response.Error).To(BeNil())
				Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(1))

				_, deletedLRPGuid, deletedLRPIndex := fakeActualLRPDB.RemoveActualLRPArgsForCall(0)
				Expect(deletedLRPGuid).To(Equal(processGuid))
				Expect(deletedLRPIndex).To(Equal(index))
			})

			Context("when removing the actual lrp fails", func() {
				BeforeEach(func() {
					fakeActualLRPDB.RemoveActualLRPReturns(errors.New("boom!"))
				})

				It("retries removing up to RetireActualLRPRetryAttempts times", func() {
					Expect(response.Error.Message).To(Equal("boom!"))
					Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(5))
					Expect(fakeActualLRPDB.ActualLRPGroupByProcessGuidAndIndexCallCount()).To(Equal(5))
				})
			})
		})

		Context("when the LRP is Claimed or Running", func() {
			var (
				cellID       string
				cellPresence models.CellPresence
				instanceKey  models.ActualLRPInstanceKey
			)

			BeforeEach(func() {
				cellID = "cell-id"
				instanceKey = models.NewActualLRPInstanceKey("instance-guid", cellID)

				actualLRP.CellId = cellID
				actualLRP.ActualLRPInstanceKey = instanceKey
				actualLRPGroup.Instance.State = models.ActualLRPStateClaimed
				fakeActualLRPDB.ActualLRPGroupByProcessGuidAndIndexReturns(actualLRPGroup, nil)
			})

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
						Expect(fakeRepClientFactory.CreateClientCallCount()).To(Equal(1))
						Expect(fakeRepClientFactory.CreateClientArgsForCall(0)).To(Equal(cellPresence.RepAddress))

						Expect(fakeServiceClient.CellByIdCallCount()).To(Equal(1))
						_, fetchedCellID := fakeServiceClient.CellByIdArgsForCall(0)
						Expect(fetchedCellID).To(Equal(cellID))

						Expect(fakeRepClient.StopLRPInstanceCallCount()).Should(Equal(1))
						stoppedKey, stoppedInstanceKey := fakeRepClient.StopLRPInstanceArgsForCall(0)
						Expect(stoppedKey).To(Equal(key))
						Expect(stoppedInstanceKey).To(Equal(instanceKey))
					})

					Context("Stopping the LRP fails", func() {
						BeforeEach(func() {
							fakeRepClient.StopLRPInstanceReturns(errors.New("Failed to stop app"))
						})

						It("retries to stop the app", func() {
							Expect(response.Error.Error()).To(Equal("Failed to stop app"))
							Expect(fakeRepClient.StopLRPInstanceCallCount()).Should(Equal(5))
						})
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
							Expect(response.Error).To(BeNil())
							Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(1))

							_, deletedLRPGuid, deletedLRPIndex := fakeActualLRPDB.RemoveActualLRPArgsForCall(0)
							Expect(deletedLRPGuid).To(Equal(processGuid))
							Expect(deletedLRPIndex).To(Equal(index))
						})
					})

					Context("removing the actualLRP fails", func() {
						BeforeEach(func() {
							fakeActualLRPDB.RemoveActualLRPReturns(errors.New("failed to delete actual LRP"))
						})

						It("returns an error and does not retry", func() {
							Expect(response.Error.Message).To(Equal("failed to delete actual LRP"))
							Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(1))
						})
					})
				})

				Context("the cell is present, but returns an error on lookup", func() {
					BeforeEach(func() {
						fakeServiceClient.CellByIdReturns(nil, errors.New("cell error"))
					})

					It("returns an error and retries", func() {
						Expect(response.Error.Error()).To(Equal("cell error"))
						Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(0))
						Expect(fakeServiceClient.CellByIdCallCount()).To(Equal(1))
					})
				})
			})
		})
	})

	Describe("FailActualLRP", func() {
		var (
			request     *http.Request
			processGuid = "process-guid"
			index       = int32(1)

			key          models.ActualLRPKey
			errorMessage string

			requestBody interface{}
		)

		BeforeEach(func() {
			key = models.NewActualLRPKey(
				processGuid,
				index,
				"domain-0",
			)
			errorMessage = "something went wrong"
			requestBody = &models.FailActualLRPRequest{
				ActualLrpKey: &key,
				ErrorMessage: errorMessage,
			}

			actualLRP = models.ActualLRP{
				ActualLRPKey: key,
				State:        models.ActualLRPStateUnclaimed,
				Since:        1138,
			}
		})

		JustBeforeEach(func() {
			request = newTestRequest(requestBody)
			handler.FailActualLRP(responseRecorder, request)
		})

		Context("when failing the actual lrp in the DB succeeds", func() {
			BeforeEach(func() {
				fakeActualLRPDB.FailActualLRPReturns(nil)
			})

			It("fails the actual lrp by process guid and index", func() {
				Expect(fakeActualLRPDB.FailActualLRPCallCount()).To(Equal(1))
				_, actualKey, actualErrorMessage := fakeActualLRPDB.FailActualLRPArgsForCall(0)
				Expect(*actualKey).To(Equal(key))
				Expect(actualErrorMessage).To(Equal(errorMessage))

				Expect(responseRecorder.Code).To(Equal(http.StatusOK))

				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(BeNil())
			})
		})

		Context("when failing the actual lrp fails", func() {
			BeforeEach(func() {
				fakeActualLRPDB.FailActualLRPReturns(models.ErrUnknownError)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrUnknownError))
			})
		})

		Context("when we cannot find the resource", func() {
			BeforeEach(func() {
				fakeActualLRPDB.FailActualLRPReturns(models.ErrResourceNotFound)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrResourceNotFound))
			})
		})
	})

	Describe("RemoveActualLRP", func() {
		var (
			processGuid       = "process-guid"
			index       int32 = 1

			instanceKey models.ActualLRPInstanceKey

			requestBody interface{}
		)

		BeforeEach(func() {
			requestBody = &models.RemoveActualLRPRequest{
				ProcessGuid: processGuid,
				Index:       index,
			}

			instanceKey = models.NewActualLRPInstanceKey(
				"instance-guid-0",
				"cell-id-0",
			)
			actualLRP = models.ActualLRP{
				ActualLRPKey: models.NewActualLRPKey(
					processGuid,
					1,
					"domain-0",
				),
				State: models.ActualLRPStateUnclaimed,
				Since: 1138,
			}
		})

		JustBeforeEach(func() {
			request := newTestRequest(requestBody)
			handler.RemoveActualLRP(responseRecorder, request)
		})

		Context("when removing the actual lrp in the DB succeeds", func() {
			var removedActualLRP models.ActualLRP

			BeforeEach(func() {
				removedActualLRP = actualLRP
				removedActualLRP.ActualLRPInstanceKey = instanceKey
				fakeActualLRPDB.RemoveActualLRPReturns(nil)
			})

			It("removes the actual lrp by process guid and index", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				Expect(fakeActualLRPDB.RemoveActualLRPCallCount()).To(Equal(1))
				_, actualProcessGuid, idx := fakeActualLRPDB.RemoveActualLRPArgsForCall(0)
				Expect(actualProcessGuid).To(Equal(processGuid))
				Expect(idx).To(BeEquivalentTo(index))
			})

			It("response with no error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(BeNil())
			})
		})

		Context("when removing the actual lrp fails", func() {
			BeforeEach(func() {
				fakeActualLRPDB.RemoveActualLRPReturns(models.ErrUnknownError)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrUnknownError))
			})
		})

		Context("when we cannot find the resource", func() {
			BeforeEach(func() {
				fakeActualLRPDB.RemoveActualLRPReturns(models.ErrResourceNotFound)
			})

			It("responds with an error", func() {
				Expect(responseRecorder.Code).To(Equal(http.StatusOK))
				response := &models.ActualLRPLifecycleResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(Equal(models.ErrResourceNotFound))
			})
		})
	})
})
