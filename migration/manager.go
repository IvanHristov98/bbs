package migration

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cloudfoundry-incubator/bbs/db"
	"github.com/cloudfoundry-incubator/bbs/db/etcd"
	"github.com/cloudfoundry-incubator/bbs/encryption"
	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/runtime-schema/metric"
	"github.com/pivotal-golang/clock"
	"github.com/pivotal-golang/lager"
)

const (
	migrationDuration = metric.Duration("MigrationDuration")
)

type Manager struct {
	logger         lager.Logger
	etcdDB         db.DB
	storeClient    etcd.StoreClient
	sqlDB          db.DB
	rawSQLDB       *sql.DB
	cryptor        encryption.Cryptor
	migrations     []Migration
	migrationsDone chan<- struct{}
	clock          clock.Clock
}

func NewManager(
	logger lager.Logger,
	etcdDB db.DB,
	etcdStoreClient etcd.StoreClient,
	sqlDB db.DB,
	rawSQLDB *sql.DB,
	cryptor encryption.Cryptor,
	migrations Migrations,
	migrationsDone chan<- struct{},
	clock clock.Clock,
) Manager {
	sort.Sort(migrations)

	return Manager{
		logger:         logger,
		etcdDB:         etcdDB,
		storeClient:    etcdStoreClient,
		sqlDB:          sqlDB,
		rawSQLDB:       rawSQLDB,
		cryptor:        cryptor,
		migrations:     migrations,
		migrationsDone: migrationsDone,
		clock:          clock,
	}
}

func (m Manager) Run(signals <-chan os.Signal, ready chan<- struct{}) error {
	logger := m.logger.Session("migration-manager")
	logger.Info("starting")

	lastETCDMigrationVersion := m.lastETCDMigrationVersion()

	var maxMigrationVersion int64
	if len(m.migrations) > 0 {
		maxMigrationVersion = m.migrations[len(m.migrations)-1].Version()
	}

	version, err := m.resolveStoredVersion(logger)
	if err != nil {
		return err
	}

	if !m.hasSQLConfigured() {
		logger.Info("no-sql-configuration")
		maxMigrationVersion = lastETCDMigrationVersion
	}

	if version == nil {
		if m.hasETCDConfigured() && !m.hasSQLConfigured() {
			logger.Info("fresh-etcd-skipping-migrations")
			err = m.writeVersion(lastETCDMigrationVersion, lastETCDMigrationVersion)
			if err != nil {
				return err
			}

			m.finishAndWait(logger, signals, ready)
			return nil
		} else if m.hasSQLConfigured() {
			logger.Info("sql-is-configured")
			version = &models.Version{
				CurrentVersion: lastETCDMigrationVersion,
				TargetVersion:  maxMigrationVersion,
			}
			err = m.writeVersion(lastETCDMigrationVersion, maxMigrationVersion)
			if err != nil {
				return err
			}
		} else {
			err := errors.New("no database configured")
			logger.Error("no-database-configured", err)
			return err
		}
	}

	if version.TargetVersion < version.CurrentVersion {
		return fmt.Errorf(
			"Existing DB target version (%d) exceeds current version (%d)",
			version.TargetVersion,
			version.CurrentVersion,
		)
	}

	if version.CurrentVersion > maxMigrationVersion {
		return fmt.Errorf(
			"Existing DB version (%d) exceeds bbs version (%d)",
			version.CurrentVersion,
			maxMigrationVersion,
		)
	}

	if version.TargetVersion != maxMigrationVersion {
		if version.TargetVersion > maxMigrationVersion {
			version.TargetVersion = maxMigrationVersion
		}

		logger.Info("running-migrations", lager.Data{
			"from-version": version.CurrentVersion,
			"to-version":   maxMigrationVersion,
		})

		m.writeVersion(version.CurrentVersion, maxMigrationVersion)
	}

	migrateStart := m.clock.Now()
	if version.CurrentVersion != maxMigrationVersion {
		lastVersion := version.CurrentVersion
		nextVersion := version.CurrentVersion

		for _, currentMigration := range m.migrations {
			if maxMigrationVersion < currentMigration.Version() {
				break
			}

			if lastVersion < currentMigration.Version() {
				if nextVersion > currentMigration.Version() {
					return fmt.Errorf(
						"Existing DB target version (%d) exceeds pending migration version (%d)",
						nextVersion,
						currentMigration.Version(),
					)
				}
				nextVersion = currentMigration.Version()

				logger.Info("running-migration", lager.Data{
					"CurrentVersion":   lastVersion,
					"NextVersion":      nextVersion,
					"MigrationVersion": currentMigration.Version(),
				})

				currentMigration.SetCryptor(m.cryptor)
				currentMigration.SetStoreClient(m.storeClient)
				currentMigration.SetRawSQLDB(m.rawSQLDB)
				currentMigration.SetClock(m.clock)

				err = currentMigration.Up(m.logger)
				if err != nil {
					return err
				}

				lastVersion = currentMigration.Version()
				logger.Debug("completed-migration")
			}
		}

		err = m.writeVersion(lastVersion, nextVersion)
		if err != nil {
			return err
		}
	}

	logger.Debug("migrations-finished")
	err = migrationDuration.Send(time.Since(migrateStart))
	if err != nil {
		logger.Error("failed-to-send-migration-duration-metric", err)
	}

	m.finishAndWait(logger, signals, ready)
	return nil
}

func (m *Manager) findMaxTargetVersion() (int, int64) {
	if len(m.migrations) > 0 {
		if m.rawSQLDB == nil {
			for i, migration := range m.migrations {
				if migration.RequiresSQL() {
					return i, m.migrations[i-1].Version()
				}
			}
		}
		return len(m.migrations), m.migrations[len(m.migrations)-1].Version()
	}
	return 0, 0
}

func (m *Manager) lastETCDMigrationVersion() int64 {
	if len(m.migrations) > 0 {
		for i, migration := range m.migrations {
			if migration.RequiresSQL() {
				if i == 0 {
					return 0
				}
				return m.migrations[i-1].Version()
			}
		}
		return m.migrations[len(m.migrations)-1].Version()
	}
	return 0
}

// returns nil, nil if no version is found
func (m *Manager) resolveStoredVersion(logger lager.Logger) (*models.Version, error) {
	var (
		version *models.Version
		err     error
	)

	if m.hasSQLConfigured() {
		version, err = m.sqlDB.Version(logger)
		if err == nil {
			return version, nil
		} else if models.ConvertError(err) != models.ErrResourceNotFound {
			return nil, err
		}
	}

	if m.hasETCDConfigured() {
		version, err = m.etcdDB.Version(logger)
		if err != nil {
			if models.ConvertError(err) == models.ErrResourceNotFound {
				return nil, nil // totally fresh deploy
			}
			return nil, err
		}
		return version, nil
	}
	return nil, nil
}

func (m *Manager) finishAndWait(logger lager.Logger, signals <-chan os.Signal, ready chan<- struct{}) {
	close(ready)
	close(m.migrationsDone)
	logger.Info("finished-migrations")
	defer logger.Info("exited")

	select {
	case <-signals:
		return
	}
}

func (m *Manager) writeVersion(currentVersion, targetVersion int64) error {
	if m.hasSQLConfigured() {
		err := m.sqlDB.SetVersion(m.logger, &models.Version{
			CurrentVersion: currentVersion,
			TargetVersion:  targetVersion,
		})

		if err != nil {
			return err
		}
	}

	if m.hasETCDConfigured() {
		err := m.etcdDB.SetVersion(m.logger, &models.Version{
			CurrentVersion: currentVersion,
			TargetVersion:  targetVersion,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) hasETCDConfigured() bool {
	return m.storeClient != nil
}

func (m *Manager) hasSQLConfigured() bool {
	return m.rawSQLDB != nil
}

type Migrations []Migration

func (m Migrations) Len() int           { return len(m) }
func (m Migrations) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m Migrations) Less(i, j int) bool { return m[i].Version() < m[j].Version() }
