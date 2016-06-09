package sqldb

import (
	"database/sql"
	"fmt"

	"github.com/cloudfoundry-incubator/bbs/format"
	"github.com/pivotal-golang/lager"
)

const EncryptionKeyID = "encryption_key_label"

func (db *SQLDB) SetEncryptionKeyLabel(logger lager.Logger, label string) error {
	logger = logger.Session("set-encrption-key-label", lager.Data{"label": label})
	logger.Debug("starting")
	defer logger.Debug("complete")

	return db.setConfigurationValue(logger, EncryptionKeyID, label)
}

func (db *SQLDB) EncryptionKeyLabel(logger lager.Logger) (string, error) {
	logger = logger.Session("encrption-key-label")
	logger.Debug("starting")
	defer logger.Debug("complete")

	return db.getConfigurationValue(logger, EncryptionKeyID)
}

func (db *SQLDB) PerformEncryption(logger lager.Logger) error {
	errCh := make(chan error)
	go func() {
		errCh <- db.reEncrypt(logger, "tasks", "guid", "task_definition")
	}()
	go func() {
		errCh <- db.reEncrypt(logger, "desired_lrps", "process_guid", "run_info")
	}()
	go func() {
		errCh <- db.reEncrypt(logger, "desired_lrps", "process_guid", "volume_placement")
	}()
	go func() {
		errCh <- db.reEncrypt(logger, "actual_lrps", "process_guid", "net_info")
	}()

	for i := 0; i < 4; i++ {
		err := <-errCh
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *SQLDB) reEncrypt(logger lager.Logger, tableName, primaryKey, blobColumn string) error {
	logger = logger.WithData(
		lager.Data{"table-name": tableName, "primary-key": primaryKey, "blob-column": blobColumn},
	)
	rows, err := db.db.Query(fmt.Sprintf("SELECT %s FROM %s", primaryKey, tableName))
	if err != nil {
		return db.convertSQLError(err)
	}
	defer rows.Next()

	selectQuery := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s = $1 FOR UPDATE",
		blobColumn, tableName, primaryKey)
	updateQuery := fmt.Sprintf(
		"UPDATE %s SET %s = $1 WHERE %s = $2",
		tableName, blobColumn, primaryKey)
	for rows.Next() {
		var guid string
		err := rows.Scan(&guid)
		if err != nil {
			logger.Error("failed-to-scan-primary-key", err)
			continue
		}

		err = db.transact(logger, func(logger lager.Logger, tx *sql.Tx) error {
			var blob []byte
			row := tx.QueryRow(selectQuery, guid)
			err := row.Scan(&blob)
			if err != nil {
				logger.Error("failed-to-scan-blob", err)
				return nil
			}
			encoder := format.NewEncoder(db.cryptor)
			payload, err := encoder.Decode(blob)
			if err != nil {
				logger.Error("failed-to-decode-blob", err)
				return nil
			}
			encryptedPayload, err := encoder.Encode(format.BASE64_ENCRYPTED, payload)
			if err != nil {
				logger.Error("failed-to-encode-blob", err)
				return err
			}
			_, err = tx.Exec(updateQuery, encryptedPayload, guid)
			if err != nil {
				logger.Error("failed-to-update-blob", err)
				return db.convertSQLError(err)
			}
			return nil
		})

		if err != nil {
			return err
		}
	}
	return nil
}
