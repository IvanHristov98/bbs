package sqldb_test

import (
	"encoding/json"

	"github.com/cloudfoundry-incubator/bbs/db/sqldb"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/bbs/test_helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = FDescribe("Version", func() {
	Describe("SetVersion", func() {
		Context("when the version is not set", func() {
			It("sets the version into the database", func() {
				expectedVersion := &models.Version{CurrentVersion: 99, TargetVersion: 100}
				err := sqlDB.SetVersion(logger, expectedVersion)
				Expect(err).NotTo(HaveOccurred())

				queryStr := "SELECT value FROM configurations WHERE id = ?"
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				rows, err := db.Query(queryStr, sqldb.VersionID)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()

				Expect(rows.Next()).To(BeTrue())

				var versionData string
				err = rows.Scan(&versionData)
				Expect(err).NotTo(HaveOccurred())

				var actualVersion models.Version
				err = json.Unmarshal([]byte(versionData), &actualVersion)
				Expect(err).NotTo(HaveOccurred())

				Expect(actualVersion).To(Equal(*expectedVersion))
			})
		})

		Context("when a version is already set", func() {
			var existingVersion *models.Version
			BeforeEach(func() {
				existingVersion = &models.Version{CurrentVersion: 99, TargetVersion: 100}
				versionJSON, err := json.Marshal(existingVersion)
				Expect(err).NotTo(HaveOccurred())

				queryStr := `
				  INSERT INTO configurations (id, value) VALUES (?, ?)
					  ON CONFLICT (id) DO UPDATE SET value = ?`
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				_, err = db.Exec(queryStr, sqldb.VersionID, versionJSON, versionJSON)
				Expect(err).NotTo(HaveOccurred())
			})

			It("updates the version in the db", func() {
				version := &models.Version{CurrentVersion: 20, TargetVersion: 1001}

				err := sqlDB.SetVersion(logger, version)
				Expect(err).NotTo(HaveOccurred())

				queryStr := "SELECT value FROM configurations WHERE id = ?"
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				rows, err := db.Query(queryStr, sqldb.VersionID)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()

				Expect(rows.Next()).To(BeTrue())

				var versionData string
				err = rows.Scan(&versionData)
				Expect(err).NotTo(HaveOccurred())

				var actualVersion models.Version
				err = json.Unmarshal([]byte(versionData), &actualVersion)
				Expect(err).NotTo(HaveOccurred())

				Expect(actualVersion).To(Equal(*version))
			})
		})
	})

	Describe("Version", func() {
		Context("when the version exists", func() {
			It("retrieves the version from the database", func() {
				expectedVersion := &models.Version{CurrentVersion: 199, TargetVersion: 200}
				value, err := json.Marshal(expectedVersion)
				Expect(err).NotTo(HaveOccurred())

				queryStr := `
					INSERT INTO configurations (id, value) VALUES (?, ?)
					  ON CONFLICT (id) DO UPDATE SET value = ?`
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				_, err = db.Exec(queryStr,
					sqldb.VersionID, value, value)

				Expect(err).NotTo(HaveOccurred())

				version, err := sqlDB.Version(logger)
				Expect(err).NotTo(HaveOccurred())

				Expect(*version).To(Equal(*expectedVersion))
			})
		})

		Context("when the version key does not exist", func() {
			BeforeEach(func() {
				_, err := db.Exec(`DELETE FROM configurations`)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns a ErrResourceNotFound", func() {
				version, err := sqlDB.Version(logger)
				Expect(err).To(MatchError(models.ErrResourceNotFound))
				Expect(version).To(BeNil())
			})
		})

		Context("when the version key is not valid json", func() {
			It("returns a ErrDeserialize", func() {
				queryStr := `
				  INSERT INTO configurations (id, value) VALUES (?, ?)
					  ON CONFLICT (id) DO UPDATE SET value = ?`
				if test_helpers.UsePostgres() {
					queryStr = test_helpers.ReplaceQuestionMarks(queryStr)
				}
				_, err := db.Exec(queryStr, sqldb.VersionID, "{{", "{{")
				Expect(err).NotTo(HaveOccurred())

				_, err = sqlDB.Version(logger)
				Expect(err).To(MatchError(models.ErrDeserialize))
			})
		})
	})
})
