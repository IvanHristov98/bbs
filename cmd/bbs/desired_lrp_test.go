package main_test

import (
	"github.com/cloudfoundry-incubator/bbs/cmd/bbs/testrunner"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/bbs/models/test/model_helpers"
	"github.com/tedsuo/ifrit/ginkgomon"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DesiredLRP API", func() {
	var (
		desiredLRPs         map[string][]*models.DesiredLRP
		schedulingInfos     []*models.DesiredLRPSchedulingInfo
		expectedDesiredLRPs []*models.DesiredLRP
		actualDesiredLRPs   []*models.DesiredLRP

		filter models.DesiredLRPFilter

		getErr error
	)

	BeforeEach(func() {
		bbsRunner = testrunner.New(bbsBinPath, bbsArgs)
		bbsProcess = ginkgomon.Invoke(bbsRunner)
		filter = models.DesiredLRPFilter{}
		expectedDesiredLRPs = []*models.DesiredLRP{}
		actualDesiredLRPs = []*models.DesiredLRP{}
		desiredLRPs = etcdHelper.CreateDesiredLRPsInDomains(map[string]int{
			"domain-1": 2,
			"domain-2": 3,
		})
	})

	AfterEach(func() {
		ginkgomon.Kill(bbsProcess)
	})

	Describe("DesiredLRPs", func() {
		JustBeforeEach(func() {
			actualDesiredLRPs, getErr = client.DesiredLRPs(filter)
		})

		It("responds without error", func() {
			Expect(getErr).NotTo(HaveOccurred())
		})

		It("has the correct number of responses", func() {
			Expect(actualDesiredLRPs).To(HaveLen(5))
		})

		Context("when not filtering", func() {
			It("returns all desired lrps from the bbs", func() {
				for _, domainLRPs := range desiredLRPs {
					for _, lrp := range domainLRPs {
						expectedDesiredLRPs = append(expectedDesiredLRPs, lrp)
					}
				}
				Expect(actualDesiredLRPs).To(ConsistOf(expectedDesiredLRPs))
			})
		})

		Context("when filtering by domain", func() {
			var domain string
			BeforeEach(func() {
				domain = "domain-1"
				filter = models.DesiredLRPFilter{Domain: domain}
			})

			It("has the correct number of responses", func() {
				Expect(actualDesiredLRPs).To(HaveLen(2))
			})

			It("returns only the desired lrps in the requested domain", func() {
				for _, lrp := range desiredLRPs[domain] {
					expectedDesiredLRPs = append(expectedDesiredLRPs, lrp)
				}
				Expect(actualDesiredLRPs).To(ConsistOf(expectedDesiredLRPs))
			})
		})
	})

	Describe("DesiredLRPByProcessGuid", func() {
		var (
			desiredLRP         *models.DesiredLRP
			expectedDesiredLRP *models.DesiredLRP
		)

		JustBeforeEach(func() {
			expectedDesiredLRP = desiredLRPs["domain-1"][0]
			desiredLRP, getErr = client.DesiredLRPByProcessGuid(expectedDesiredLRP.GetProcessGuid())
		})

		It("responds without error", func() {
			Expect(getErr).NotTo(HaveOccurred())
		})

		It("returns all desired lrps from the bbs", func() {
			Expect(desiredLRP).To(Equal(expectedDesiredLRP))
		})
	})

	Describe("DesiredLRPSchedulingInfos", func() {
		JustBeforeEach(func() {
			schedulingInfos, getErr = client.DesiredLRPSchedulingInfos(filter)
		})

		It("responds without error", func() {
			Expect(getErr).NotTo(HaveOccurred())
		})

		It("has the correct number of responses", func() {
			Expect(schedulingInfos).To(HaveLen(5))
		})

		Context("when not filtering", func() {
			It("returns all scheduling infos from the bbs", func() {
				expectedSchedulingInfos := []*models.DesiredLRPSchedulingInfo{}
				for _, domainLRPs := range desiredLRPs {
					for _, lrp := range domainLRPs {
						schedulingInfo := lrp.DesiredLRPSchedulingInfo()
						expectedSchedulingInfos = append(expectedSchedulingInfos, &schedulingInfo)
					}
				}
				Expect(schedulingInfos).To(ConsistOf(expectedSchedulingInfos))
			})
		})

		Context("when filtering by domain", func() {
			var domain string
			BeforeEach(func() {
				domain = "domain-1"
				filter = models.DesiredLRPFilter{Domain: domain}
			})

			It("has the correct number of responses", func() {
				Expect(schedulingInfos).To(HaveLen(2))
			})

			It("returns only the scheduling infos in the requested domain", func() {
				expectedSchedulingInfos := []*models.DesiredLRPSchedulingInfo{}
				for _, lrp := range desiredLRPs[domain] {
					schedulingInfo := lrp.DesiredLRPSchedulingInfo()
					expectedSchedulingInfos = append(expectedSchedulingInfos, &schedulingInfo)
				}
				Expect(schedulingInfos).To(ConsistOf(expectedSchedulingInfos))
			})
		})
	})

	Describe("DesireLRP", func() {
		var (
			desiredLRP *models.DesiredLRP

			desireErr error
		)

		BeforeEach(func() {
			desiredLRP = model_helpers.NewValidDesiredLRP("super-lrp")
		})

		JustBeforeEach(func() {
			desireErr = client.DesireLRP(desiredLRP)
		})

		FIt("creates the desired LRP in the system", func() {
			Expect(desireErr).NotTo(HaveOccurred())
			// persistedDesiredLRP, err := client.DesiredLRPByProcessGuid("super-lrp")
			// Expect(err).NotTo(HaveOccurred())
			// Expect(persistedDesiredLRP.DesiredLRPKey()).To(Equal(desiredLRP.DesiredLRPKey()))
			// Expect(persistedDesiredLRP.DesiredLRPResource()).To(Equal(desiredLRP.DesiredLRPResource()))
			// Expect(persistedDesiredLRP.Annotation).To(Equal(desiredLRP.Annotation))
			// Expect(persistedDesiredLRP.Instances).To(Equal(desiredLRP.Instances))
			// Expect(persistedDesiredLRP.DesiredLRPRunInfo(time.Unix(42, 0))).To(Equal(desiredLRP.DesiredLRPRunInfo(time.Unix(42, 0))))
			// Expect(persistedDesiredLRP.Action.RunAction.SuppressLogOutput).To(BeFalse())
		})

		Context("when suppressing log output", func() {
			BeforeEach(func() {
				desiredLRP.Action.RunAction.SuppressLogOutput = true
			})

			It("has an action with SuppressLogOutput set to true", func() {
				Expect(desireErr).NotTo(HaveOccurred())
				persistedDesiredLRP, err := client.DesiredLRPByProcessGuid("super-lrp")
				Expect(err).NotTo(HaveOccurred())
				Expect(persistedDesiredLRP.Action.RunAction.SuppressLogOutput).To(BeTrue())
			})
		})

		Context("when not suppressing log output", func() {
			BeforeEach(func() {
				desiredLRP.Action.RunAction.SuppressLogOutput = false
			})

			It("has an action with SuppressLogOutput set to false", func() {
				Expect(desireErr).NotTo(HaveOccurred())
				persistedDesiredLRP, err := client.DesiredLRPByProcessGuid("super-lrp")
				Expect(err).NotTo(HaveOccurred())
				Expect(persistedDesiredLRP.Action.RunAction.SuppressLogOutput).To(BeFalse())
			})
		})
	})

	Describe("RemoveDesiredLRP", func() {
		var (
			desiredLRP *models.DesiredLRP

			removeErr error
		)

		JustBeforeEach(func() {
			desiredLRP = model_helpers.NewValidDesiredLRP("super-lrp")
			err := client.DesireLRP(desiredLRP)
			Expect(err).NotTo(HaveOccurred())
			removeErr = client.RemoveDesiredLRP("super-lrp")
		})

		It("creates the desired LRP in the system", func() {
			Expect(removeErr).NotTo(HaveOccurred())
			_, err := client.DesiredLRPByProcessGuid("super-lrp")
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(models.ErrResourceNotFound))
		})
	})

	Describe("UpdateDesiredLRP", func() {
		var (
			desiredLRP *models.DesiredLRP

			updateErr error
		)

		JustBeforeEach(func() {
			desiredLRP = model_helpers.NewValidDesiredLRP("super-lrp")
			err := client.DesireLRP(desiredLRP)
			Expect(err).NotTo(HaveOccurred())
			three := int32(3)
			updateErr = client.UpdateDesiredLRP("super-lrp", &models.DesiredLRPUpdate{Instances: &three})
		})

		It("creates the desired LRP in the system", func() {
			Expect(updateErr).NotTo(HaveOccurred())
			persistedDesiredLRP, err := client.DesiredLRPByProcessGuid("super-lrp")
			Expect(err).NotTo(HaveOccurred())
			Expect(persistedDesiredLRP.Instances).To(Equal(int32(3)))
		})
	})
})
