package sqldb_test

import (
	"time"

	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/bbs/models/test/model_helpers"
	"code.cloudfoundry.org/bbs/test_helpers"
	"code.cloudfoundry.org/lager/lagertest"

	mfakes "code.cloudfoundry.org/diego-logging-client/testhelpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("New LRPConvergence", func() {
	type event struct {
		name  string
		value int
	}

	getMetricsEmitted := func(metronClient *mfakes.FakeIngressClient) func() []event {
		return func() []event {
			var events []event
			for i := 0; i < metronClient.SendMetricCallCount(); i++ {
				name, value, _ := metronClient.SendMetricArgsForCall(i)
				events = append(events, event{
					name:  name,
					value: value,
				})
			}
			return events
		}
	}

	actualLRPKeyWithSchedulingInfo := func(desiredLRP *models.DesiredLRP, index int) *models.ActualLRPKeyWithSchedulingInfo {
		schedulingInfo := desiredLRP.DesiredLRPSchedulingInfo()
		lrpKey := models.NewActualLRPKey(desiredLRP.ProcessGuid, int32(index), desiredLRP.Domain)

		lrp := &models.ActualLRPKeyWithSchedulingInfo{
			Key:            &lrpKey,
			SchedulingInfo: &schedulingInfo,
		}
		return lrp
	}

	var (
		cellSet models.CellSet
	)

	BeforeEach(func() {
		cellSet = models.NewCellSetFromList([]*models.CellPresence{
			{CellId: "existing-cell"},
		})
	})

	XDescribe("general metrics", func() {
		It("emits metrics for lrps", func() {
			convergenceLogger := lagertest.NewTestLogger("convergence")
			sqlDB.ConvergeLRPs(convergenceLogger, cellSet)
			Expect(fakeMetronClient.SendMetricCallCount()).To(Equal(10))
			name, value, _ := fakeMetronClient.SendMetricArgsForCall(4)
			Expect(name).To(Equal("LRPsUnclaimed"))
			Expect(value).To(Equal(32)) // 16 fresh + 5 expired + 11 evac
			name, value, _ = fakeMetronClient.SendMetricArgsForCall(5)
			Expect(name).To(Equal("LRPsClaimed"))
			Expect(value).To(Equal(7))
			name, value, _ = fakeMetronClient.SendMetricArgsForCall(6)
			Expect(name).To(Equal("LRPsRunning"))
			Expect(value).To(Equal(1))
			name, value, _ = fakeMetronClient.SendMetricArgsForCall(7)
			Expect(name).To(Equal("CrashedActualLRPs"))
			Expect(value).To(Equal(2))
			name, value, _ = fakeMetronClient.SendMetricArgsForCall(8)
			Expect(name).To(Equal("CrashingDesiredLRPs"))
			Expect(value).To(Equal(1))
			name, value, _ = fakeMetronClient.SendMetricArgsForCall(9)
			Expect(name).To(Equal("LRPsDesired"))
			Expect(value).To(Equal(38))
			Consistently(convergenceLogger).ShouldNot(gbytes.Say("failed-.*"))
		})
	})

	Describe("convergence counters", func() {
		It("bumps the convergence counter", func() {
			Expect(fakeMetronClient.IncrementCounterCallCount()).To(Equal(0))
			sqlDB.ConvergeLRPs(logger, models.CellSet{})
			Expect(fakeMetronClient.IncrementCounterCallCount()).To(Equal(1))
			Expect(fakeMetronClient.IncrementCounterArgsForCall(0)).To(Equal("ConvergenceLRPRuns"))
			sqlDB.ConvergeLRPs(logger, models.CellSet{})
			Expect(fakeMetronClient.IncrementCounterCallCount()).To(Equal(2))
			Expect(fakeMetronClient.IncrementCounterArgsForCall(1)).To(Equal("ConvergenceLRPRuns"))
		})

		It("reports the duration that it took to converge", func() {
			sqlDB.ConvergeLRPs(logger, models.CellSet{})

			Eventually(fakeMetronClient.SendDurationCallCount).Should(Equal(1))
			name, value, _ := fakeMetronClient.SendDurationArgsForCall(0)
			Expect(name).To(Equal("ConvergenceLRPDuration"))
			Expect(value).NotTo(BeZero())
		})
	})

	Describe("pruning evacuating lrps", func() {
		var (
			processGuid, domain string
		)

		BeforeEach(func() {
			domain = "some-domain"
			processGuid = "desired-with-evacuating-actual"
			desiredLRP := model_helpers.NewValidDesiredLRP(processGuid)
			desiredLRP.Domain = domain
			desiredLRP.Instances = 2
			err := sqlDB.DesireLRP(logger, desiredLRP)
			Expect(err).NotTo(HaveOccurred())
			_, err = sqlDB.CreateUnclaimedActualLRP(logger, &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain})
			Expect(err).NotTo(HaveOccurred())
			_, _, err = sqlDB.ClaimActualLRP(logger, processGuid, 0, &models.ActualLRPInstanceKey{InstanceGuid: "ig-1", CellId: "existing-cell"})
			Expect(err).NotTo(HaveOccurred())

			_, err = db.Exec(`UPDATE actual_lrps SET evacuating = true`)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the cell is present", func() {
			It("keeps evacuating actual lrps with available cells", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groups).To(HaveLen(1))
			})
		})

		Context("when the cell isn't present", func() {
			BeforeEach(func() {
				cellSet = models.NewCellSet()
			})

			It("clears out evacuating actual lrps with missing cells", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())
				Expect(groups).To(BeEmpty())
			})

			It("return an ActualLRPRemovedEvent", func() {
				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groups).To(HaveLen(1))

				result := sqlDB.ConvergeLRPs(logger, cellSet)

				Expect(result.Events).To(ContainElement(models.NewActualLRPRemovedEvent(groups[0])))
			})
		})
	})

	Context("when there are fresh domains", func() {
		BeforeEach(func() {
			Expect(sqlDB.UpsertDomain(logger, "some-domain", 5)).To(Succeed())
			Expect(sqlDB.UpsertDomain(logger, "other-domain", 5)).To(Succeed())
		})

		It("emits domain freshness metric for each domain", func() {
			sqlDB.ConvergeLRPs(logger, cellSet)

			Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
				name:  "Domain.some-domain",
				value: 1,
			}))

			Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
				name:  "Domain.other-domain",
				value: 1,
			}))
		})
	})

	Context("when there are expired domains", func() {
		var (
			expiredDomain = "expired-domain"
		)

		BeforeEach(func() {
			fakeClock.Increment(-10 * time.Second)
			sqlDB.UpsertDomain(logger, expiredDomain, 5)
			fakeClock.Increment(10 * time.Second)
		})

		It("clears out expired domains", func() {
			fetchDomains := func() []string {
				rows, err := db.Query("SELECT domain FROM domains")
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()

				var domain string
				var results []string
				for rows.Next() {
					err = rows.Scan(&domain)
					Expect(err).NotTo(HaveOccurred())
					results = append(results, domain)
				}
				return results
			}

			Expect(fetchDomains()).To(ContainElement(expiredDomain))

			sqlDB.ConvergeLRPs(logger, cellSet)

			Expect(fetchDomains()).NotTo(ContainElement(expiredDomain))
		})

	})

	Context("when there are unclaimed LRPs", func() {
		var (
			domain      string
			processGuid string
		)

		BeforeEach(func() {
			domain = "some-domain"
			processGuid = "desired-with-unclaimed-actuals"
			desiredLRPWithStaleActuals := model_helpers.NewValidDesiredLRP(processGuid)
			desiredLRPWithStaleActuals.Domain = domain
			desiredLRPWithStaleActuals.Instances = 1
			err := sqlDB.DesireLRP(logger, desiredLRPWithStaleActuals)
			Expect(err).NotTo(HaveOccurred())
			_, err = sqlDB.CreateUnclaimedActualLRP(logger, &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the domain is fresh", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})

			It("returns an empty convergence result", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result).To(BeZero())
			})
		})

		Context("when the ActualLRP's presence is set to evacuating", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())

				queryStr := `UPDATE actual_lrps SET evacuating = ? WHERE process_guid = ?`
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				_, err := db.Exec(queryStr, true, processGuid)
				Expect(err).NotTo(HaveOccurred())
			})

			It("ignores the evacuating LRPs and emits LRP missing metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsMissing",
					value: 1,
				}))
			})

			It("removes the evacuating lrps", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())
				Expect(groups).To(BeEmpty())
			})

			It("return ActualLRPRemoveEvent", func() {
				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groups).To(HaveLen(1))

				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.Events).To(ConsistOf(models.NewActualLRPRemovedEvent(groups[0])))
			})
		})
	})

	Context("when there is a suspect LRP and ordinary LRP present", func() {
		BeforeEach(func() {
			// add suspect and ordinary lrps that are running on different cells
		})

		It("should return the suspect lrp key in the SuspectLRPKeysToRetire", func() {
			Fail("not implemented")
		})
	})

	Context("when there are claimed LRPs", func() {
		var (
			domain      string
			processGuid string
		)

		BeforeEach(func() {
			domain = "some-domain"
			processGuid = "desired-with-claimed-actuals"
			desiredLRPWithStaleActuals := model_helpers.NewValidDesiredLRP(processGuid)
			desiredLRPWithStaleActuals.Domain = domain
			desiredLRPWithStaleActuals.Instances = 1
			err := sqlDB.DesireLRP(logger, desiredLRPWithStaleActuals)
			Expect(err).NotTo(HaveOccurred())
			_, err = sqlDB.CreateUnclaimedActualLRP(logger, &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain})
			Expect(err).NotTo(HaveOccurred())
			_, _, err = sqlDB.ClaimActualLRP(logger, processGuid, 0, &models.ActualLRPInstanceKey{InstanceGuid: "instance-guid", CellId: "existing-cell"})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the domain is fresh", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
			})

			It("does not retire the extra lrps", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.KeysToRetire).To(BeEmpty())
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})
		})
	})

	Context("when there are stale unclaimed LRPs", func() {
		var (
			domain      string
			processGuid string
		)

		BeforeEach(func() {
			domain = "some-domain"
			processGuid = "desired-with-stale-actuals"
			desiredLRPWithStaleActuals := model_helpers.NewValidDesiredLRP(processGuid)
			desiredLRPWithStaleActuals.Domain = domain
			desiredLRPWithStaleActuals.Instances = 2
			err := sqlDB.DesireLRP(logger, desiredLRPWithStaleActuals)
			Expect(err).NotTo(HaveOccurred())
			fakeClock.Increment(-models.StaleUnclaimedActualLRPDuration)
			_, err = sqlDB.CreateUnclaimedActualLRP(logger, &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain})
			Expect(err).NotTo(HaveOccurred())
			_, err = sqlDB.CreateUnclaimedActualLRP(logger, &models.ActualLRPKey{ProcessGuid: processGuid, Index: 1, Domain: domain})
			Expect(err).NotTo(HaveOccurred())
			fakeClock.Increment(models.StaleUnclaimedActualLRPDuration + 2)
		})

		Context("when the domain is fresh", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
			})

			It("returns start requests", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				unstartedLRPKeys := result.UnstartedLRPKeys
				Expect(unstartedLRPKeys).NotTo(BeEmpty())
				Expect(logger).To(gbytes.Say("creating-start-request.*reason\":\"stale-unclaimed-lrp"))

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(unstartedLRPKeys).To(ContainElement(actualLRPKeyWithSchedulingInfo(desiredLRP, 0)))
				Expect(unstartedLRPKeys).To(ContainElement(actualLRPKeyWithSchedulingInfo(desiredLRP, 1)))
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})

			It("emits stale unclaimed LRP metrics", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsUnclaimed",
					value: 2,
				}))
			})
		})

		Context("when the domain is expired", func() {
			BeforeEach(func() {
				fakeClock.Increment(-10 * time.Second)
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
				fakeClock.Increment(10 * time.Second)
			})

			It("returns start requests", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				unstartedLRPKeys := result.UnstartedLRPKeys
				Expect(unstartedLRPKeys).NotTo(BeEmpty())
				Expect(logger).To(gbytes.Say("creating-start-request.*reason\":\"stale-unclaimed-lrp"))

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(unstartedLRPKeys).To(ContainElement(actualLRPKeyWithSchedulingInfo(desiredLRP, 0)))
				Expect(unstartedLRPKeys).To(ContainElement(actualLRPKeyWithSchedulingInfo(desiredLRP, 1)))
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})

			It("emits stale unclaimed LRP metrics", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsUnclaimed",
					value: 2,
				}))
			})
		})

		Context("when the ActualLRPs presence is set to evacuating", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())

				queryStr := `UPDATE actual_lrps SET evacuating = ?`
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				_, err := db.Exec(queryStr, true)
				Expect(err).NotTo(HaveOccurred())
			})

			It("ignores the evacuating LRPs and emits LRP missing metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsMissing",
					value: 2,
				}))
			})

			It("returns the lrp keys in the MissingLRPKeys", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				expectedSched := desiredLRP.DesiredLRPSchedulingInfo()
				Expect(result.MissingLRPKeys).To(ContainElement(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain},
					SchedulingInfo: &expectedSched,
				}))
			})

			// it is the responsibility of the caller to create new LRPs
			It("prune the evacuating LRPs and does not create new ones", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())
				Expect(groups).To(BeEmpty())
			})

			It("return ActualLRPRemovedEvent for the removed evacuating LRPs", func() {
				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())
				Expect(groups).To(HaveLen(2))

				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.Events).To(ConsistOf(
					models.NewActualLRPRemovedEvent(groups[0]),
					models.NewActualLRPRemovedEvent(groups[1]),
				))
			})
		})
	})

	Context("when there is an ActualLRP on a missing cell", func() {
		var (
			domain      string
			processGuid string
		)

		BeforeEach(func() {
			domain = "some-domain"
			processGuid = "desired-with-missing-cell-actuals"
			desiredLRPWithMissingCellActuals := model_helpers.NewValidDesiredLRP(processGuid)
			desiredLRPWithMissingCellActuals.Domain = domain
			err := sqlDB.DesireLRP(logger, desiredLRPWithMissingCellActuals)
			Expect(err).NotTo(HaveOccurred())
			_, err = sqlDB.CreateUnclaimedActualLRP(logger, &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain})
			Expect(err).NotTo(HaveOccurred())
			_, _, err = sqlDB.ClaimActualLRP(logger, processGuid, 0, &models.ActualLRPInstanceKey{InstanceGuid: "actual-with-missing-cell", CellId: "other-cell"})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the domain is fresh", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
			})

			It("returns the start requests and actual lrp keys for actuals with missing cells", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				keysWithMissingCells := result.KeysWithMissingCells

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				actualLRPGroup, err := sqlDB.ActualLRPGroupByProcessGuidAndIndex(logger, processGuid, 0)
				Expect(err).NotTo(HaveOccurred())
				expectedSched := desiredLRP.DesiredLRPSchedulingInfo()
				Expect(keysWithMissingCells).To(ContainElement(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &actualLRPGroup.Instance.ActualLRPKey,
					SchedulingInfo: &expectedSched,
				}))
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})
		})

		Context("when the domain is expired", func() {
			BeforeEach(func() {
				fakeClock.Increment(-10 * time.Second)
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
				fakeClock.Increment(10 * time.Second)
			})

			It("return ActualLRPKeys for actuals with missing cells", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				keysWithMissingCells := result.KeysWithMissingCells

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				actualLRPGroup, err := sqlDB.ActualLRPGroupByProcessGuidAndIndex(logger, processGuid, 0)
				Expect(err).NotTo(HaveOccurred())
				expectedSched := desiredLRP.DesiredLRPSchedulingInfo()
				Expect(keysWithMissingCells).To(ContainElement(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &actualLRPGroup.Instance.ActualLRPKey,
					SchedulingInfo: &expectedSched,
				}))
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})
		})

		Context("when the lrp is evacuating", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())

				queryStr := `UPDATE actual_lrps SET evacuating = ?`
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				_, err := db.Exec(queryStr, true)
				Expect(err).NotTo(HaveOccurred())
			})

			It("ignores the evacuating LRPs and emits LRP missing metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsMissing",
					value: 1,
				}))
			})

			It("returns the start requests and actual lrp keys for actuals with missing cells", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				expectedSched := desiredLRP.DesiredLRPSchedulingInfo()
				Expect(result.MissingLRPKeys).To(ContainElement(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain},
					SchedulingInfo: &expectedSched,
				}))
			})

			It("removes the evacuating lrp", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())
				Expect(groups).To(BeEmpty())
			})
		})

		It("logs the missing cells", func() {
			sqlDB.ConvergeLRPs(logger, cellSet)
			Expect(logger).To(gbytes.Say(`detected-missing-cells.*cell_ids":\["other-cell"\]`))
		})

		Context("when there are no missing cells", func() {
			BeforeEach(func() {
				cellSet = models.NewCellSetFromList([]*models.CellPresence{
					{CellId: "existing-cell"},
					{CellId: "other-cell"},
				})
			})

			It("does not log missing cells", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(logger).ToNot(gbytes.Say("detected-missing-cells"))
			})
		})
	})

	Context("when there are extra ActualLRPs for a DesiredLRP", func() {
		var (
			domain      string
			processGuid string
		)

		BeforeEach(func() {
			domain = "some-domain"
			processGuid = "desired-with-extra-actuals"
			desiredLRPWithExtraActuals := model_helpers.NewValidDesiredLRP(processGuid)
			desiredLRPWithExtraActuals.Domain = domain
			desiredLRPWithExtraActuals.Instances = 1
			err := sqlDB.DesireLRP(logger, desiredLRPWithExtraActuals)
			Expect(err).NotTo(HaveOccurred())
			_, err = sqlDB.CreateUnclaimedActualLRP(logger, &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain})
			Expect(err).NotTo(HaveOccurred())
			_, err = sqlDB.CreateUnclaimedActualLRP(logger, &models.ActualLRPKey{ProcessGuid: processGuid, Index: 4, Domain: domain})
			Expect(err).NotTo(HaveOccurred())
			_, _, err = sqlDB.ClaimActualLRP(logger, processGuid, 0, &models.ActualLRPInstanceKey{InstanceGuid: "not-extra-actual", CellId: "existing-cell"})
			Expect(err).NotTo(HaveOccurred())
			_, _, err = sqlDB.ClaimActualLRP(logger, processGuid, 4, &models.ActualLRPInstanceKey{InstanceGuid: "extra-actual", CellId: "existing-cell"})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the domain is fresh", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
			})

			It("returns extra ActualLRPs to be retired", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				keysToRetire := result.KeysToRetire

				actualLRPKey := models.ActualLRPKey{ProcessGuid: processGuid, Index: 4, Domain: domain}
				Expect(keysToRetire).To(ContainElement(&actualLRPKey))
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})

			It("emits LRPsExtra metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsExtra",
					value: 1,
				}))
			})
		})

		Context("when the domain is expired", func() {
			BeforeEach(func() {
				fakeClock.Increment(-10 * time.Second)
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
				fakeClock.Increment(10 * time.Second)
			})

			It("returns an empty convergence result", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result).To(BeZero())
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})

			It("emits a zero for the LRPsExtra metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsExtra",
					value: 0,
				}))
			})
		})

		Context("when the ActualLRP's presence is set to evacuating", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())

				queryStr := `UPDATE actual_lrps SET evacuating = ? WHERE process_guid = ?`
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				_, err := db.Exec(queryStr, true, processGuid)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns the lrp keys to be started", func() {
				schedulingInfos, err := sqlDB.DesiredLRPSchedulingInfos(logger, models.DesiredLRPFilter{ProcessGuids: []string{processGuid}})
				Expect(err).NotTo(HaveOccurred())

				Expect(schedulingInfos).To(HaveLen(1))

				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.MissingLRPKeys).To(ConsistOf(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain},
					SchedulingInfo: schedulingInfos[0],
				}))
			})

			It("remoes the extra key to retire", func() {
				group, err := sqlDB.ActualLRPGroupByProcessGuidAndIndex(logger, processGuid, 4)
				Expect(err).NotTo(HaveOccurred())

				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.KeysToRetire).To(ConsistOf(group.Evacuating.ActualLRPKey))
			})

			It("return an ActualLRPRemoved Event", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groups).To(HaveLen(1))
			})

			It("return an ActualLRPRemoved Event", func() {
				group, err := sqlDB.ActualLRPGroupByProcessGuidAndIndex(logger, processGuid, 4)
				Expect(err).NotTo(HaveOccurred())

				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.Events).To(ConsistOf(
					models.NewActualLRPRemovedEvent(group),
				))
			})

			It("emits a LRPsMissing metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsMissing",
					value: 1,
				}))
			})
		})
	})

	Context("when there are no ActualLRPs for a DesiredLRP", func() {
		var (
			domain      string
			processGuid string
		)

		BeforeEach(func() {
			processGuid = "desired-with-missing-all-actuals" + "-" + domain
			desiredLRPWithMissingAllActuals := model_helpers.NewValidDesiredLRP(processGuid)
			desiredLRPWithMissingAllActuals.Domain = domain
			desiredLRPWithMissingAllActuals.Instances = 1
			err := sqlDB.DesireLRP(logger, desiredLRPWithMissingAllActuals)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("and the domain is fresh", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
			})

			It("emits a LRPsMissing metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsMissing",
					value: 1,
				}))
			})

			It("return ActualLRPKeys for missing actuals", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				expectedSched := desiredLRP.DesiredLRPSchedulingInfo()
				Expect(result.MissingLRPKeys).To(ContainElement(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain},
					SchedulingInfo: &expectedSched,
				}))
			})
		})

		Context("and the domain is expired", func() {
			BeforeEach(func() {
				fakeClock.Increment(-10 * time.Second)
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
				fakeClock.Increment(10 * time.Second)
			})

			It("emits a LRPsMissing metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsMissing",
					value: 1,
				}))
			})

			It("return ActualLRPKeys for missing actuals", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				expectedSched := desiredLRP.DesiredLRPSchedulingInfo()
				Expect(result.MissingLRPKeys).To(ContainElement(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain},
					SchedulingInfo: &expectedSched,
				}))
			})
		})
	})

	Context("when the ActualLRPs are crashed and restartable", func() {
		var (
			domain      string
			processGuid string
		)

		BeforeEach(func() {
			processGuid = "desired-with-restartable-crashed-actuals" + "-" + domain
			desiredLRPWithRestartableCrashedActuals := model_helpers.NewValidDesiredLRP(processGuid)
			desiredLRPWithRestartableCrashedActuals.Domain = domain
			desiredLRPWithRestartableCrashedActuals.Instances = 2
			err := sqlDB.DesireLRP(logger, desiredLRPWithRestartableCrashedActuals)
			Expect(err).NotTo(HaveOccurred())

			for i := int32(0); i < 2; i++ {
				crashedActualLRPKey := models.NewActualLRPKey(processGuid, i, domain)
				_, err = sqlDB.CreateUnclaimedActualLRP(logger, &crashedActualLRPKey)
				Expect(err).NotTo(HaveOccurred())
				instanceGuid := "restartable-crashed-actual" + "-" + domain
				_, _, err = sqlDB.ClaimActualLRP(logger, processGuid, i, &models.ActualLRPInstanceKey{InstanceGuid: instanceGuid, CellId: "existing-cell"})
				Expect(err).NotTo(HaveOccurred())
				actualLRPNetInfo := models.NewActualLRPNetInfo("some-address", "container-address", models.NewPortMapping(2222, 4444))
				_, _, err = sqlDB.StartActualLRP(logger, &crashedActualLRPKey, &models.ActualLRPInstanceKey{InstanceGuid: instanceGuid, CellId: "existing-cell"}, &actualLRPNetInfo)
				Expect(err).NotTo(HaveOccurred())
				_, _, _, err = sqlDB.CrashActualLRP(logger, &crashedActualLRPKey, &models.ActualLRPInstanceKey{InstanceGuid: instanceGuid, CellId: "existing-cell"}, "whatever")
				Expect(err).NotTo(HaveOccurred())
			}

			// we cannot use CrashedActualLRPs, otherwise it will transition the LRP
			// to unclaimed since ShouldRestartCrash will return true on the first
			// crash
			queryStr := `
				UPDATE actual_lrps
				SET state = ?
			`
			if test_helpers.UsePostgres() {
				queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
			}
			_, err = db.Exec(queryStr, models.ActualLRPStateCrashed)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the domain is fresh", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
			})

			It("emit CrashedActualLRPs", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "CrashedActualLRPs",
					value: 2,
				}))
			})

			It("add the keys to UnstartedLRPKeys", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				expectedSched := desiredLRP.DesiredLRPSchedulingInfo()
				Expect(result.UnstartedLRPKeys).To(ContainElement(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain},
					SchedulingInfo: &expectedSched,
				}))

			})
		})

		Context("when the domain is expired", func() {
			BeforeEach(func() {
				fakeClock.Increment(-10 * time.Second)
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
				fakeClock.Increment(10 * time.Second)
			})

			It("emit CrashedActualLRPs", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "CrashedActualLRPs",
					value: 2,
				}))
			})

			It("add the keys to UnstartedLRPKeys", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				expectedSched := desiredLRP.DesiredLRPSchedulingInfo()
				Expect(result.UnstartedLRPKeys).To(ContainElement(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain},
					SchedulingInfo: &expectedSched,
				}))
			})
		})

		Context("when the the lrps are evacuating", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())

				queryStr := `UPDATE actual_lrps SET evacuating = ?`
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				_, err := db.Exec(queryStr, true)
				Expect(err).NotTo(HaveOccurred())
			})

			It("emits a LRPsMissing metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsMissing",
					value: 2,
				}))
			})

			// it is the responsibility of the caller to create new LRPs
			It("prune the evacuating LRPs and does not create new ones", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())
				Expect(groups).To(BeEmpty())
			})

			It("return ActualLRPKeys for missing actuals", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)

				desiredLRP, err := sqlDB.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				expectedSched := desiredLRP.DesiredLRPSchedulingInfo()
				Expect(result.MissingLRPKeys).To(ContainElement(&models.ActualLRPKeyWithSchedulingInfo{
					Key:            &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain},
					SchedulingInfo: &expectedSched,
				}))
			})

			It("return ActualLRPRemovedEvent for the removed evacuating LRPs", func() {
				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())
				Expect(groups).To(HaveLen(2))

				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.Events).To(ConsistOf(
					models.NewActualLRPRemovedEvent(groups[0]),
					models.NewActualLRPRemovedEvent(groups[1]),
				))
			})
		})
	})

	Context("when the ActualLRPs are crashed and non-restartable", func() {
		var (
			domain      string
			processGuid string
		)

		BeforeEach(func() {
			processGuid = "desired-with-non-restartable-crashed-actuals" + "-" + domain
			desiredLRPWithRestartableCrashedActuals := model_helpers.NewValidDesiredLRP(processGuid)
			desiredLRPWithRestartableCrashedActuals.Domain = domain
			desiredLRPWithRestartableCrashedActuals.Instances = 2
			err := sqlDB.DesireLRP(logger, desiredLRPWithRestartableCrashedActuals)
			Expect(err).NotTo(HaveOccurred())

			for i := int32(0); i < 2; i++ {
				crashedActualLRPKey := models.NewActualLRPKey(processGuid, i, domain)
				_, err = sqlDB.CreateUnclaimedActualLRP(logger, &crashedActualLRPKey)
				Expect(err).NotTo(HaveOccurred())
				instanceGuid := "restartable-crashed-actual" + "-" + domain
				_, _, err = sqlDB.ClaimActualLRP(logger, processGuid, i, &models.ActualLRPInstanceKey{InstanceGuid: instanceGuid, CellId: "existing-cell"})
				Expect(err).NotTo(HaveOccurred())
				actualLRPNetInfo := models.NewActualLRPNetInfo("some-address", "container-address", models.NewPortMapping(2222, 4444))
				_, _, err = sqlDB.StartActualLRP(logger, &crashedActualLRPKey, &models.ActualLRPInstanceKey{InstanceGuid: instanceGuid, CellId: "existing-cell"}, &actualLRPNetInfo)
				Expect(err).NotTo(HaveOccurred())
			}

			// we cannot use CrashedActualLRPs, otherwise it will transition the LRP
			// to unclaimed since ShouldRestartCrash will return true on the first
			// crash
			queryStr := `
			UPDATE actual_lrps
			SET crash_count = ?, state = ?
			`
			if test_helpers.UsePostgres() {
				queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
			}
			_, err = db.Exec(queryStr, models.DefaultMaxRestarts+1, models.ActualLRPStateCrashed)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the domain is fresh", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
			})

			It("emit CrashedActualLRPs", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "CrashedActualLRPs",
					value: 2,
				}))
			})

			It("returns an empty convergence result", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result).To(BeZero())
			})
		})

		Context("when the domain is expired", func() {
			BeforeEach(func() {
				fakeClock.Increment(-10 * time.Second)
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
				fakeClock.Increment(10 * time.Second)
			})

			It("emit CrashedActualLRPs", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "CrashedActualLRPs",
					value: 2,
				}))
			})

			It("does not add the keys to UnstartedLRPKeys", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.UnstartedLRPKeys).To(BeEmpty())
			})
		})
	})

	Context("there is an ActualLRP without a corresponding DesiredLRP", func() {
		var (
			processGuid, domain string
		)

		BeforeEach(func() {
			domain = "some-domain"
			processGuid = "actual-with-no-desired"
			actualLRPWithNoDesired := &models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain}
			_, err := sqlDB.CreateUnclaimedActualLRP(logger, actualLRPWithNoDesired)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when the domain is fresh", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
			})

			It("returns extra ActualLRPs to be retired", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				keysToRetire := result.KeysToRetire

				actualLRPKey := models.ActualLRPKey{ProcessGuid: processGuid, Index: 0, Domain: domain}
				Expect(keysToRetire).To(ContainElement(&actualLRPKey))
			})

			It("returns the no lrp keys to be started", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.UnstartedLRPKeys).To(BeEmpty())
				Expect(result.MissingLRPKeys).To(BeEmpty())
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})

			It("emits LRPsExtra metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsExtra",
					value: 1,
				}))
			})
		})

		Context("when the domain is expired", func() {
			BeforeEach(func() {
				fakeClock.Increment(-10 * time.Second)
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())
				fakeClock.Increment(10 * time.Second)
			})

			It("does not return extra ActualLRPs to be retired", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.KeysToRetire).To(BeEmpty())
			})

			It("returns the no lrp keys to be started", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.UnstartedLRPKeys).To(BeEmpty())
				Expect(result.MissingLRPKeys).To(BeEmpty())
			})

			It("does not touch the ActualLRPs in the database", func() {
				groupsBefore, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				sqlDB.ConvergeLRPs(logger, cellSet)

				groupsAfter, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groupsAfter).To(Equal(groupsBefore))
			})

			It("emits zero value for LRPsExtra metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsExtra",
					value: 0,
				}))
			})
		})

		Context("when the the lrps are evacuating", func() {
			BeforeEach(func() {
				Expect(sqlDB.UpsertDomain(logger, domain, 5)).To(Succeed())

				queryStr := `UPDATE actual_lrps SET evacuating = ?`
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				_, err := db.Exec(queryStr, true)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns the no lrp keys to be started", func() {
				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.UnstartedLRPKeys).To(BeEmpty())
				Expect(result.MissingLRPKeys).To(BeEmpty())
			})

			It("removes the evacuating LRPs", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())
				Expect(groups).To(BeEmpty())
			})

			It("return an ActualLRPRemoved Event", func() {
				groups, err := sqlDB.ActualLRPGroupsByProcessGuid(logger, processGuid)
				Expect(err).NotTo(HaveOccurred())

				Expect(groups).To(HaveLen(1))

				result := sqlDB.ConvergeLRPs(logger, cellSet)
				Expect(result.Events).To(ConsistOf(
					models.NewActualLRPRemovedEvent(groups[0]),
				))
			})

			It("emits LRPsExtra metric", func() {
				sqlDB.ConvergeLRPs(logger, cellSet)

				Eventually(getMetricsEmitted(fakeMetronClient)).Should(ContainElement(event{
					name:  "LRPsExtra",
					value: 0,
				}))
			})
		})
	})
})
