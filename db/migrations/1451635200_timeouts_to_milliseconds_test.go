package migrations_test

import (
	"crypto/rand"
	"encoding/json"
	"time"

	etcddb "github.com/cloudfoundry-incubator/bbs/db/etcd"
	"github.com/cloudfoundry-incubator/bbs/db/migrations"
	"github.com/cloudfoundry-incubator/bbs/encryption"
	"github.com/cloudfoundry-incubator/bbs/format"
	"github.com/cloudfoundry-incubator/bbs/migration"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/bbs/models/test/model_helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/lager/lagertest"
)

var _ = Describe("Change Timeouts to Milliseconds Migration", func() {
	var (
		migration  migration.Migration
		serializer format.Serializer
		cryptor    encryption.Cryptor
		db         *etcddb.ETCDDB

		logger *lagertest.TestLogger
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")

		encryptionKey, err := encryption.NewKey("label", "passphrase")
		Expect(err).NotTo(HaveOccurred())
		keyManager, err := encryption.NewKeyManager(encryptionKey, nil)
		Expect(err).NotTo(HaveOccurred())
		cryptor = encryption.NewCryptor(keyManager, rand.Reader)
		serializer = format.NewSerializer(cryptor)
		migration = migrations.NewTimeoutMilliseconds()
		db = etcddb.NewETCD(format.ENCRYPTED_PROTO, 1, 1, 1*time.Minute, cryptor, storeClient, fakeClock)
	})

	It("appends itself to the migration list", func() {
		Expect(migrations.Migrations).To(ContainElement(migration))
	})

	Describe("Version", func() {
		It("returns the timestamp from which it was created", func() {
			Expect(migration.Version()).To(BeEquivalentTo(1451635200))
		})
	})

	Describe("Down", func() {
		It("returns a not implemented error", func() {
			Expect(migration.Down(logger)).To(HaveOccurred())
		})
	})

	Describe("Up", func() {

		var (
			taskGuid string

			migrationErr error
		)

		JustBeforeEach(func() {
			migration.SetStoreClient(storeClient)
			migration.SetCryptor(cryptor)
			migration.SetClock(fakeClock)
			migrationErr = migration.Up(logger)
		})

		Describe("Task Migration", func() {
			BeforeEach(func() {
				taskGuid = "task-guid-1"
				oldTask := model_helpers.NewValidTask(taskGuid)
				oldTask.Action = models.WrapAction(&models.TimeoutAction{Action: model_helpers.NewValidAction(),
					DeprecatedTimeoutNs: 5 * int64(time.Second),
					TimeoutMs:           99999, // this must be set to pass validation on marshalling
				})

				taskData, err := serializer.Marshal(logger, format.ENCRYPTED_PROTO, oldTask)
				Expect(err).NotTo(HaveOccurred())
				_, err = storeClient.Set(etcddb.TaskSchemaPath(oldTask), taskData, 0)
				Expect(err).NotTo(HaveOccurred())
			})

			It("changes task timeoutAction timeout to milliseconds", func() {
				Expect(migrationErr).NotTo(HaveOccurred())
				task, err := db.TaskByGuid(logger, taskGuid)
				Expect(err).NotTo(HaveOccurred())
				Expect(task.Action.GetTimeoutAction().GetTimeoutMs()).To(Equal(int64(5000)))
			})
		})

		Describe("DesiredLRP Migration", func() {
			var (
				processGuid string
				desiredLRP  *models.DesiredLRP
			)

			BeforeEach(func() {
				processGuid = "process-guid-1"
				desiredLRP = model_helpers.NewValidDesiredLRP(processGuid)
				desiredLRP.DeprecatedStartTimeoutS = 15
				desiredLRP.Action = models.WrapAction(&models.TimeoutAction{Action: models.WrapAction(&models.RunAction{Path: "ls", User: "name"}),
					DeprecatedTimeoutNs: 4 * int64(time.Second),
					TimeoutMs:           99999, // this must be set to pass validation on marshalling
				})

				desiredLRP.Setup = models.WrapAction(&models.TimeoutAction{Action: models.WrapAction(&models.RunAction{Path: "ls", User: "name"}),
					DeprecatedTimeoutNs: 7 * int64(time.Second),
					TimeoutMs:           99999, // this must be set to pass validation on marshalling
				})
				desiredLRP.Monitor = models.WrapAction(models.EmitProgressFor(
					&models.TimeoutAction{
						Action:              models.WrapAction(models.Try(models.Parallel(models.Serial(&models.RunAction{Path: "ls", User: "name"})))),
						DeprecatedTimeoutNs: 10 * int64(time.Second),
						TimeoutMs:           99999, // this must be set to pass validation on marshalling
					},
					"start-message",
					"success-message",
					"failure-message",
				))

				schedulingInfo, runInfo := desiredLRP.CreateComponents(fakeClock.Now())
				runInfo.DeprecatedStartTimeoutS = 15

				_, err := json.Marshal(desiredLRP.Routes)
				Expect(err).NotTo(HaveOccurred())

				schedInfoData, err := serializer.Marshal(logger, format.ENCRYPTED_PROTO, &schedulingInfo)
				Expect(err).NotTo(HaveOccurred())
				_, err = storeClient.Set(etcddb.DesiredLRPSchedulingInfoSchemaPath(processGuid), schedInfoData, 0)
				Expect(err).NotTo(HaveOccurred())
				runInfoData, err := serializer.Marshal(logger, format.ENCRYPTED_PROTO, &runInfo)
				Expect(err).NotTo(HaveOccurred())
				_, err = storeClient.Set(etcddb.DesiredLRPRunInfoSchemaPath(processGuid), runInfoData, 0)
				Expect(err).NotTo(HaveOccurred())

				encoder := format.NewEncoder(cryptor)
				encryptedVolumePlacement, err := serializer.Marshal(logger, format.ENCRYPTED_PROTO, schedulingInfo.VolumePlacement)
				Expect(err).NotTo(HaveOccurred())
				_, err = encoder.Decode(encryptedVolumePlacement)
				Expect(err).NotTo(HaveOccurred())
			})

			It("changes desiredLRP startTimeout to milliseconds", func() {
				Expect(migrationErr).NotTo(HaveOccurred())
				desiredLRP, err := db.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).ToNot(HaveOccurred())
				Expect(desiredLRP.GetStartTimeoutMs()).To(Equal(int64(15000)))
			})

			It("changes monitor action startTimeout to milliseconds", func() {
				Expect(migrationErr).NotTo(HaveOccurred())
				desiredLRP, err := db.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).ToNot(HaveOccurred())
				Expect(desiredLRP.GetMonitor().GetEmitProgressAction().GetAction().GetTimeoutAction().GetTimeoutMs()).To(Equal(int64(10000)))
			})

			It("changes action startTimeout to milliseconds", func() {
				Expect(migrationErr).NotTo(HaveOccurred())
				desiredLRP, err := db.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).ToNot(HaveOccurred())
				Expect(desiredLRP.GetAction().GetTimeoutAction().GetTimeoutMs()).To(Equal(int64(4000)))
			})

			It("changes setup startTimeout to milliseconds", func() {
				Expect(migrationErr).NotTo(HaveOccurred())
				desiredLRP, err := db.DesiredLRPByProcessGuid(logger, processGuid)
				Expect(err).ToNot(HaveOccurred())
				Expect(desiredLRP.GetSetup().GetTimeoutAction().GetTimeoutMs()).To(Equal(int64(7000)))
			})
		})
	})
})
