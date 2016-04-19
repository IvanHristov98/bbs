package migration_test

import (
	"errors"
	"os"

	"github.com/cloudfoundry-incubator/bbs/db/etcd"
	"github.com/cloudfoundry-incubator/bbs/db/fakes"
	"github.com/cloudfoundry-incubator/bbs/encryption"
	fakeencryption "github.com/cloudfoundry-incubator/bbs/encryption/fakes"
	"github.com/cloudfoundry-incubator/bbs/migration"
	"github.com/cloudfoundry-incubator/bbs/migration/migrationfakes"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry/dropsonde/metric_sender/fake"
	"github.com/cloudfoundry/dropsonde/metrics"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/clock"
	"github.com/pivotal-golang/lager/lagertest"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

var _ = Describe("Migration Manager", func() {
	var (
		manager          ifrit.Runner
		migrationProcess ifrit.Process

		logger     *lagertest.TestLogger
		fakeDB     *fakes.FakeDB
		migrations []migration.Migration

		ready          chan struct{}
		signals        chan os.Signal
		runErrChan     chan error
		migrationsDone chan struct{}

		dbVersion     *models.Version
		fakeMigration *migrationfakes.FakeMigration

		storeClient etcd.StoreClient
		cryptor     encryption.Cryptor

		sender *fake.FakeMetricSender
	)

	BeforeEach(func() {
		sender = fake.NewFakeMetricSender()
		metrics.Initialize(sender, nil)

		runErrChan = make(chan error, 1)
		ready = make(chan struct{})
		signals = make(chan os.Signal)
		migrationsDone = make(chan struct{})

		dbVersion = &models.Version{}

		logger = lagertest.NewTestLogger("test")
		fakeDB = &fakes.FakeDB{}
		fakeDB.VersionReturns(dbVersion, nil)

		storeClient = etcd.NewStoreClient(nil)
		cryptor = &fakeencryption.FakeCryptor{}

		fakeMigration = &migrationfakes.FakeMigration{}
		migrations = []migration.Migration{fakeMigration}
	})

	JustBeforeEach(func() {
		manager = migration.NewManager(logger, fakeDB, cryptor, storeClient, migrations, migrationsDone, clock.NewClock())
		migrationProcess = ifrit.Background(manager)
	})

	AfterEach(func() {
		ginkgomon.Kill(migrationProcess)
	})

	Context("when no etcd store is present", func() {
		BeforeEach(func() {
			storeClient = nil
		})

		It("closes the ready channel immediately", func() {
			Eventually(migrationProcess.Ready).Should(BeClosed())
		})

		It("exits after being signalled", func() {
			ginkgomon.Interrupt(migrationProcess)
			Eventually(migrationProcess.Wait).Should(Receive(BeNil()))
		})
	})

	It("fetches the migration version from the database", func() {
		Eventually(fakeDB.VersionCallCount).Should(Equal(1))
		Consistently(fakeDB.VersionCallCount).Should(Equal(1))

		ginkgomon.Interrupt(migrationProcess)
		Eventually(migrationProcess.Wait).Should(Receive(BeNil()))
	})

	Context("when there is no version", func() {
		BeforeEach(func() {
			fakeDB.VersionReturns(nil, models.ErrResourceNotFound)
			fakeMigration.VersionReturns(9)
		})

		It("creates a version with the correct target version and does not run any migrations", func() {
			Eventually(fakeDB.SetVersionCallCount).Should(Equal(1))

			_, version := fakeDB.SetVersionArgsForCall(0)
			Expect(version.CurrentVersion).To(BeEquivalentTo(9))
			Expect(version.TargetVersion).To(BeEquivalentTo(9))

			Expect(fakeMigration.UpCallCount()).To(Equal(0))
		})
	})

	Context("when fetching the version fails", func() {
		BeforeEach(func() {
			fakeDB.VersionReturns(nil, errors.New("kablamo"))
		})

		It("fails early", func() {
			var err error
			Eventually(migrationProcess.Wait()).Should(Receive(&err))
			Expect(err).To(MatchError("kablamo"))
			Expect(migrationProcess.Ready()).ToNot(BeClosed())
			Expect(migrationsDone).NotTo(BeClosed())
		})
	})

	Context("when the current version is newer than bbs migration version", func() {
		BeforeEach(func() {
			dbVersion.CurrentVersion = 100
			dbVersion.TargetVersion = 100
			fakeMigration.VersionReturns(99)
		})

		It("shuts down wihtout signalling ready", func() {
			var err error
			Eventually(migrationProcess.Wait()).Should(Receive(&err))
			Expect(err).To(MatchError("Existing DB version (100) exceeds bbs version (99)"))
			Expect(migrationProcess.Ready()).ToNot(BeClosed())
			Expect(migrationsDone).NotTo(BeClosed())
		})
	})

	Context("when the current version is the same as the bbs migration version", func() {
		BeforeEach(func() {
			dbVersion.CurrentVersion = 100
			dbVersion.TargetVersion = 100
			fakeMigration.VersionReturns(100)
		})

		It("signals ready and does not change the version", func() {
			Eventually(migrationProcess.Ready()).Should(BeClosed())
			Expect(migrationsDone).To(BeClosed())
			Consistently(fakeDB.SetVersionCallCount).Should(Equal(0))
		})

		Context("and the target version is greater than the bbs migration version", func() {
			BeforeEach(func() {
				dbVersion.TargetVersion = 101
			})

			It("sets the target version to the current version and signals ready", func() {
				Eventually(migrationProcess.Ready()).Should(BeClosed())
				Expect(migrationsDone).To(BeClosed())

				Eventually(fakeDB.SetVersionCallCount).Should(Equal(1))

				_, version := fakeDB.SetVersionArgsForCall(0)
				Expect(version.CurrentVersion).To(BeEquivalentTo(100))
				Expect(version.TargetVersion).To(BeEquivalentTo(100))
			})
		})

		Context("and the target version is less than the bbs migration version", func() {
			BeforeEach(func() {
				dbVersion.TargetVersion = 99
			})

			It("shuts down wihtout signalling ready", func() {
				var err error
				Eventually(migrationProcess.Wait()).Should(Receive(&err))
				Expect(err).To(MatchError("Existing DB target version (99) exceeds current version (100)"))
				Expect(migrationProcess.Ready()).ToNot(BeClosed())
				Expect(migrationsDone).ToNot(BeClosed())
			})
		})
	})

	Context("when the current version is older than bbs migration version", func() {
		var fakeMigration102 *migrationfakes.FakeMigration

		BeforeEach(func() {
			fakeMigration102 = &migrationfakes.FakeMigration{}
			fakeMigration102.VersionReturns(102)

			dbVersion.CurrentVersion = 99
			dbVersion.TargetVersion = 99
			fakeMigration.VersionReturns(100)

			migrations = []migration.Migration{fakeMigration102, fakeMigration}
		})

		It("reports the duration that it took to migrate", func() {
			Eventually(migrationProcess.Ready()).Should(BeClosed())
			Expect(migrationsDone).To(BeClosed())

			reportedDuration := sender.GetValue("MigrationDuration")
			Expect(reportedDuration.Value).NotTo(BeZero())
			Expect(reportedDuration.Unit).To(Equal("nanos"))
		})

		It("it sorts the migrations and runs them sequentially", func() {
			Eventually(migrationProcess.Ready()).Should(BeClosed())
			Expect(migrationsDone).To(BeClosed())
			Consistently(fakeDB.SetVersionCallCount).Should(Equal(2))

			_, version := fakeDB.SetVersionArgsForCall(0)
			Expect(version).To(Equal(&models.Version{CurrentVersion: 99, TargetVersion: 102}))

			_, version = fakeDB.SetVersionArgsForCall(1)
			Expect(version).To(Equal(&models.Version{CurrentVersion: 102, TargetVersion: 102}))

			Expect(fakeMigration.UpCallCount()).To(Equal(1))
			Expect(fakeMigration102.UpCallCount()).To(Equal(1))

			Expect(fakeMigration.DownCallCount()).To(Equal(0))
			Expect(fakeMigration102.DownCallCount()).To(Equal(0))
		})

		It("sets the store client on the migration", func() {
			Eventually(migrationProcess.Ready()).Should(BeClosed())
			Expect(migrationsDone).To(BeClosed())
			Expect(fakeMigration.SetStoreClientCallCount()).To(Equal(1))
			actualStoreClient := fakeMigration.SetStoreClientArgsForCall(0)
			Expect(actualStoreClient).To(Equal(storeClient))
		})

		It("sets the cryptor on the migration", func() {
			Eventually(migrationProcess.Ready()).Should(BeClosed())
			Expect(migrationsDone).To(BeClosed())
			Expect(fakeMigration.SetCryptorCallCount()).To(Equal(1))
			actualCryptor := fakeMigration.SetCryptorArgsForCall(0)
			Expect(actualCryptor).To(Equal(cryptor))
		})

		Context("when the target version is greater than the bbs migration version", func() {
			BeforeEach(func() {
				dbVersion.TargetVersion = 103
			})

			It("runs the migrations up to the bbs migration version", func() {
				Eventually(migrationProcess.Ready()).Should(BeClosed())
				Expect(migrationsDone).To(BeClosed())
				Consistently(fakeDB.SetVersionCallCount).Should(Equal(2))

				_, version := fakeDB.SetVersionArgsForCall(0)
				Expect(version).To(Equal(&models.Version{CurrentVersion: 99, TargetVersion: 102}))

				_, version = fakeDB.SetVersionArgsForCall(1)
				Expect(version).To(Equal(&models.Version{CurrentVersion: 102, TargetVersion: 102}))

				Expect(fakeMigration.UpCallCount()).To(Equal(1))
				Expect(fakeMigration102.UpCallCount()).To(Equal(1))

				Expect(fakeMigration.DownCallCount()).To(Equal(0))
				Expect(fakeMigration102.DownCallCount()).To(Equal(0))
			})
		})
	})

	Context("when there are no migrations", func() {
		BeforeEach(func() {
			migrations = []migration.Migration{}
		})

		Context("when there are no migrations", func() {
			BeforeEach(func() {
				migrations = []migration.Migration{}
			})

			Context("and there is an existing version", func() {
				BeforeEach(func() {
					dbVersion.CurrentVersion = 100
					dbVersion.TargetVersion = 100
				})

				It("treats the bbs migration version as 0", func() {
					var err error
					Eventually(migrationProcess.Wait()).Should(Receive(&err))
					Expect(err).To(MatchError("Existing DB version (100) exceeds bbs version (0)"))
					Expect(migrationProcess.Ready()).ToNot(BeClosed())
				})
			})

			Context("and there is no existing version", func() {
				BeforeEach(func() {
					fakeDB.VersionReturns(nil, models.ErrResourceNotFound)
				})

				It("writes a zero version into the db", func() {
					Eventually(fakeDB.SetVersionCallCount).Should(Equal(1))

					_, version := fakeDB.SetVersionArgsForCall(0)
					Expect(version.CurrentVersion).To(BeEquivalentTo(0))
					Expect(version.CurrentVersion).To(BeEquivalentTo(0))
					Expect(version.TargetVersion).To(BeEquivalentTo(0))
				})
			})
		})
	})
})
