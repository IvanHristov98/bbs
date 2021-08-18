package sqldb

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"code.cloudfoundry.org/bbs/db/sqldb/helpers"
	"code.cloudfoundry.org/bbs/format"
	"code.cloudfoundry.org/lager"
)

const EncryptionKeyID = "encryption_key_label"

type primaryKey struct {
	attribNames []string
	attribTypes []reflect.Type
}

func (db *SQLDB) SetEncryptionKeyLabel(ctx context.Context, logger lager.Logger, label string) error {
	logger = logger.Session("db-set-encrption-key-label", lager.Data{"label": label})
	logger.Debug("starting")
	defer logger.Debug("complete")

	return db.setConfigurationValue(ctx, logger, EncryptionKeyID, label)
}

func (db *SQLDB) EncryptionKeyLabel(ctx context.Context, logger lager.Logger) (string, error) {
	logger = logger.Session("db-encrption-key-label")
	logger.Debug("starting")
	defer logger.Debug("complete")

	return db.getConfigurationValue(ctx, logger, EncryptionKeyID)
}

func (db *SQLDB) PerformEncryption(ctx context.Context, logger lager.Logger) error {
	errCh := make(chan error)

	funcs := []func(){
		func() {
			var guid string
			key := primaryKey{
				attribNames: []string{"guid"},
				attribTypes: []reflect.Type{reflect.TypeOf(guid)},
			}

			errCh <- db.reEncrypt(ctx, logger, tasksTable, key, true, "task_definition")
		},
		func() {
			var process_guid string
			key := primaryKey{
				attribNames: []string{"process_guid"},
				attribTypes: []reflect.Type{reflect.TypeOf(process_guid)},
			}

			errCh <- db.reEncrypt(ctx, logger, desiredLRPsTable, key, true, "run_info", "volume_placement", "routes")
		},
		func() {
			var process_guid string
			var instance_index int
			var presence int
			key := primaryKey{
				attribNames: []string{"process_guid", "instance_index", "presence"},
				attribTypes: []reflect.Type{reflect.TypeOf(process_guid), reflect.TypeOf(instance_index), reflect.TypeOf(presence)},
			}

			errCh <- db.reEncrypt(ctx, logger, actualLRPsTable, key, false, "net_info")
		},
	}

	for _, f := range funcs {
		go f()
	}

	for range funcs {
		err := <-errCh
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *SQLDB) reEncrypt(ctx context.Context, logger lager.Logger, tableName string, key primaryKey, encryptIfEmpty bool, blobColumns ...string) error {
	logger = logger.WithData(
		lager.Data{"table_name": tableName, "primary_key": key.attribNames, "blob_columns": blobColumns},
	)

	attributes := strings.Join(key.attribNames, ", ")
	logger.Debug("reencrypt-select-query", lager.Data{"query": fmt.Sprintf("SELECT %s FROM %s", attributes, tableName)})

	rows, err := db.db.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM %s", attributes, tableName))
	if err != nil {
		return err
	}
	defer rows.Close()

	recordKeys := [][]interface{}{}

	for rows.Next() {
		recordKeyAsPtr := make([]interface{}, len(key.attribNames))
		logger.Debug("cryptoguid-before", lager.Data{"guid": recordKeyAsPtr})

		// Convert pointers of unknown type to their values.
		for i := 0; i < len(key.attribNames); i++ {
			recordKeyAsPtr[i] = reflect.New(key.attribTypes[i]).Interface()
		}

		// var guid string
		err := rows.Scan(recordKeyAsPtr...)
		if err != nil {
			logger.Error("failed-to-scan-primary-key", err)
			continue
		}

		logger.Debug("cryptoguid-after", lager.Data{"guid": recordKeyAsPtr})

		recordKey := make([]interface{}, len(key.attribNames))

		// Convert pointers of unknown type to their values.
		for i := 0; i < len(key.attribNames); i++ {
			recordKeyAsPtrVal := reflect.ValueOf(recordKeyAsPtr[i])
			recordKey[i] = recordKeyAsPtrVal.Elem().Interface()
		}

		recordKeys = append(recordKeys, recordKey)
	}

	logger.Debug("cryptoguids", lager.Data{"length": len(recordKeys)})

	wheres := []string{}

	for i := range key.attribNames {
		wheres = append(wheres, fmt.Sprintf("%s = ?", key.attribNames[i]))
	}

	where := strings.Join(wheres, " AND ")
	logger.Debug("reencrypt-where", lager.Data{"where": where})

	for _, recordKey := range recordKeys {
		err = db.transact(ctx, logger, func(logger lager.Logger, tx helpers.Tx) error {
			blobs := make([]interface{}, len(blobColumns))

			logger.Debug("reencrypt-guid-range", lager.Data{"guid": recordKey})
			row := db.one(ctx, logger, tx, tableName, blobColumns, helpers.LockRow, where, recordKey...)
			for i := range blobColumns {
				var blob []byte
				blobs[i] = &blob
			}

			err := row.Scan(blobs...)
			if err != nil {
				logger.Error("failed-to-scan-blob", err)
				return nil
			}

			updatedColumnValues := map[string]interface{}{}

			for columnIdx := range blobs {
				// This type assertion should not fail because we set the value to be a pointer to a byte array above
				blobPtr := blobs[columnIdx].(*[]byte)
				blob := *blobPtr

				// don't encrypt column if it doesn't contain any data, see #132626553 for more info
				if !encryptIfEmpty && len(blob) == 0 {
					return nil
				}

				encoder := format.NewEncoder(db.cryptor)
				payload, err := encoder.Decode(blob)
				if err != nil {
					logger.Error("failed-to-decode-blob", err)
					return nil
				}

				logger.Debug("reencrypt-payload", lager.Data{"payload": payload})

				encryptedPayload, err := encoder.Encode(payload)
				if err != nil {
					logger.Error("failed-to-encode-blob", err)
					return err
				}

				columnName := blobColumns[columnIdx]
				updatedColumnValues[columnName] = encryptedPayload
			}
			_, err = db.update(ctx, logger, tx, tableName,
				updatedColumnValues,
				where, recordKey...,
			)
			if err != nil {
				logger.Error("failed-to-update-blob", err)
				return err
			}
			return nil
		})

		if err != nil {
			return err
		}
	}
	return nil
}
