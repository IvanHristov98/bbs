package sqldb

import (
	"database/sql"

	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/pivotal-golang/lager"
)

const taskColumns = `tasks.guid, tasks.domain, tasks.updated_at, tasks.created_at,
	tasks.first_completed_at, tasks.state, tasks.cell_id, tasks.result,
	tasks.failed, tasks.failure_reason, tasks.task_definition`

func (db *SQLDB) DesireTask(logger lager.Logger, taskDef *models.TaskDefinition, taskGuid, domain string) error {
	logger = logger.Session("desire-task-sql", lager.Data{"task_guid": taskGuid})
	logger.Debug("starting")
	defer logger.Debug("complete")

	taskDefData, err := db.serializeModel(logger, taskDef)
	if err != nil {
		logger.Error("failed-serializing-task-definition", err)
		return err
	}

	now := db.clock.Now().UnixNano()

	_, err = db.db.Exec(
		`INSERT INTO tasks (guid, domain, created_at, updated_at, first_completed_at, state, task_definition)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		taskGuid,
		domain,
		now,
		now,
		0,
		models.Task_Pending,
		taskDefData,
	)

	if err != nil {
		logger.Error("failed-inserting-task", err)
		return db.convertSQLError(err)
	}

	return nil
}

func (db *SQLDB) Tasks(logger lager.Logger, taskFilter models.TaskFilter) ([]*models.Task, error) {
	logger = logger.Session("tasks-sql", lager.Data{"filter": taskFilter})
	logger.Debug("starting")
	defer logger.Debug("complete")

	var rows *sql.Rows
	var err error

	if taskFilter.Domain != "" && taskFilter.CellID != "" {
		rows, err = db.db.Query("SELECT "+taskColumns+" FROM tasks WHERE domain = $1 AND cell_id = $2", taskFilter.Domain, taskFilter.CellID)
	} else if taskFilter.Domain != "" {
		rows, err = db.db.Query("SELECT "+taskColumns+" FROM tasks WHERE domain = $1", taskFilter.Domain)
	} else if taskFilter.CellID != "" {
		rows, err = db.db.Query("SELECT "+taskColumns+" FROM tasks WHERE cell_id = $1", taskFilter.CellID)
	} else {
		rows, err = db.db.Query("SELECT " + taskColumns + " FROM tasks")
	}
	if err != nil {
		logger.Error("failed-query", err)
		return nil, db.convertSQLError(err)
	}
	defer rows.Close()

	results := []*models.Task{}
	for rows.Next() {
		task, err := db.fetchTask(logger, rows, db.db)
		if err != nil {
			logger.Error("failed-fetch", err)
			return nil, err
		}
		results = append(results, task)
	}

	if rows.Err() != nil {
		logger.Error("failed-getting-next-row", rows.Err())
		return nil, db.convertSQLError(rows.Err())
	}

	return results, nil
}

func (db *SQLDB) TaskByGuid(logger lager.Logger, taskGuid string) (*models.Task, error) {
	logger = logger.Session("task-by-guid-sql", lager.Data{"task_guid": taskGuid})
	logger.Debug("starting")
	defer logger.Debug("complete")

	row := db.db.QueryRow("SELECT "+taskColumns+" FROM tasks WHERE guid = $1", taskGuid)
	return db.fetchTask(logger, row, db.db)
}

func (db *SQLDB) StartTask(logger lager.Logger, taskGuid, cellId string) (bool, error) {
	logger = logger.Session("start-task-sql", lager.Data{"task_guid": taskGuid, "cell_id": cellId})
	logger.Debug("starting")
	defer logger.Debug("complete")

	var started bool

	err := db.transact(logger, func(logger lager.Logger, tx *sql.Tx) error {
		task, err := db.fetchTaskForUpdate(logger, taskGuid, tx)
		if err != nil {
			logger.Error("failed-locking-task", err)
			return err
		}

		if task.State == models.Task_Running && task.CellId == cellId {
			logger.Debug("task-already-running-on-cell")
			return nil
		}

		if err = task.ValidateTransitionTo(models.Task_Running); err != nil {
			logger.Error("failed-to-transition-task-to-running", err)
			return err
		}

		now := db.clock.Now().UnixNano()
		_, err = tx.Exec(`
				UPDATE tasks SET state = $1, updated_at = $2, cell_id =$3
				WHERE guid = $4`,
			models.Task_Running,
			now,
			cellId,
			taskGuid,
		)
		if err != nil {
			logger.Error("failed-to-update-task", err)
			return db.convertSQLError(err)
		}

		started = true
		return nil
	})

	return started, err
}

func (db *SQLDB) CancelTask(logger lager.Logger, taskGuid string) (*models.Task, string, error) {
	logger = logger.Session("cancel-task-sql", lager.Data{"task_guid": taskGuid})
	logger.Debug("starting")
	defer logger.Debug("complete")

	var task *models.Task
	var cellID string

	err := db.transact(logger, func(logger lager.Logger, tx *sql.Tx) error {
		var err error
		task, err = db.fetchTaskForUpdate(logger, taskGuid, tx)
		if err != nil {
			logger.Error("failed-locking-task", err)
			return err
		}

		cellID = task.CellId

		if err = task.ValidateTransitionTo(models.Task_Completed); err != nil {
			if task.State != models.Task_Pending {
				logger.Error("failed-to-transition-task-to-completed", err)
				return err
			}
		}
		return db.completeTask(logger, task, true, "task was cancelled", "", tx)
	})

	return task, cellID, err
}

func (db *SQLDB) CompleteTask(logger lager.Logger, taskGuid, cellID string, failed bool, failureReason, taskResult string) (*models.Task, error) {
	logger = logger.Session("complete-task-sql", lager.Data{"task_guid": taskGuid, "cell_id": cellID})
	logger.Debug("starting")
	defer logger.Debug("complete")

	var task *models.Task

	err := db.transact(logger, func(logger lager.Logger, tx *sql.Tx) error {
		var err error
		task, err = db.fetchTaskForUpdate(logger, taskGuid, tx)
		if err != nil {
			logger.Error("failed-locking-task", err)
			return err
		}

		if task.CellId != cellID && task.State == models.Task_Running {
			logger.Error("failed-task-already-running-on-different-cell", err)
			return models.NewRunningOnDifferentCellError(cellID, task.CellId)
		}

		if err = task.ValidateTransitionTo(models.Task_Completed); err != nil {
			logger.Error("failed-to-transition-task-to-completed", err)
			return err
		}

		return db.completeTask(logger, task, failed, failureReason, taskResult, tx)
	})

	return task, err
}

func (db *SQLDB) FailTask(logger lager.Logger, taskGuid, failureReason string) (*models.Task, error) {
	logger = logger.Session("fail-task-sql", lager.Data{"task_guid": taskGuid})
	logger.Debug("starting")
	defer logger.Debug("complete")

	var task *models.Task

	err := db.transact(logger, func(logger lager.Logger, tx *sql.Tx) error {
		var err error
		task, err = db.fetchTaskForUpdate(logger, taskGuid, tx)
		if err != nil {
			logger.Error("failed-locking-task", err)
			return err
		}

		if err = task.ValidateTransitionTo(models.Task_Completed); err != nil {
			if task.State != models.Task_Pending {
				logger.Error("failed-to-transition-task-to-completed", err)
				return err
			}
		}

		return db.completeTask(logger, task, true, failureReason, "", tx)
	})

	return task, err
}

// The stager calls this when it wants to claim a completed task.  This ensures that only one
// stager ever attempts to handle a completed task
func (db *SQLDB) ResolvingTask(logger lager.Logger, taskGuid string) error {
	logger = logger.WithData(lager.Data{"task_guid": taskGuid})
	logger.Debug("starting")
	defer logger.Debug("complete")

	return db.transact(logger, func(logger lager.Logger, tx *sql.Tx) error {
		task, err := db.fetchTaskForUpdate(logger, taskGuid, tx)
		if err != nil {
			logger.Error("failed-locking-task", err)
			return err
		}

		if err = task.ValidateTransitionTo(models.Task_Resolving); err != nil {
			logger.Error("invalid-state-transition", err)
			return err
		}

		now := db.clock.Now().UnixNano()
		_, err = tx.Exec(
			`UPDATE tasks SET
		  state = $1, updated_at = $2
			WHERE guid = $3
			`,
			models.Task_Resolving,
			now,
			taskGuid,
		)
		if err != nil {
			logger.Error("failed-resolving-task", err)
			return db.convertSQLError(err)
		}

		return nil
	})
}

func (db *SQLDB) DeleteTask(logger lager.Logger, taskGuid string) error {
	logger = logger.Session("delete-task-sql", lager.Data{"task_guid": taskGuid})
	logger.Debug("starting")
	defer logger.Debug("complete")

	return db.transact(logger, func(logger lager.Logger, tx *sql.Tx) error {
		task, err := db.fetchTaskForUpdate(logger, taskGuid, tx)
		if err != nil {
			logger.Error("failed-locking-task", err)
			return err
		}

		if task.State != models.Task_Resolving {
			err = models.NewTaskTransitionError(task.State, models.Task_Resolving)
			logger.Error("invalid-state-transition", err)
			return err
		}

		_, err = tx.Exec(
			`DELETE FROM tasks WHERE guid = $1`,
			taskGuid,
		)
		if err != nil {
			logger.Error("failed-deleting-task", err)
			return db.convertSQLError(err)
		}

		return nil
	})
}

func (db *SQLDB) completeTask(logger lager.Logger, task *models.Task, failed bool, failureReason, result string, tx *sql.Tx) error {
	now := db.clock.Now().UnixNano()
	_, err := tx.Exec(
		`UPDATE tasks SET
		  state = $1, updated_at = $2, first_completed_at = $3,
			failed = $4, failure_reason = $5, result = $6, cell_id = $7
			WHERE guid = $8
			`,
		models.Task_Completed,
		now,
		now,
		failed,
		failureReason,
		result,
		"",
		task.TaskGuid,
	)
	if err != nil {
		logger.Error("failed-updating-task", err)
		return db.convertSQLError(err)
	}

	task.State = models.Task_Completed
	task.UpdatedAt = now
	task.FirstCompletedAt = now
	task.Failed = failed
	task.FailureReason = failureReason
	task.Result = result
	task.CellId = ""

	return nil
}

func (db *SQLDB) fetchTaskForUpdate(logger lager.Logger, taskGuid string, tx *sql.Tx) (*models.Task, error) {
	row := tx.QueryRow("SELECT "+taskColumns+" FROM tasks WHERE guid = $1 FOR UPDATE", taskGuid)
	return db.fetchTask(logger, row, tx)
}

func (db *SQLDB) fetchTask(logger lager.Logger, scanner RowScanner, tx Queryable) (*models.Task, error) {
	var guid, domain, cellID, failureReason string
	var result sql.NullString
	var createdAt, updatedAt, firstCompletedAt int64
	var state int32
	var failed bool
	var taskDefData []byte

	err := scanner.Scan(
		&guid,
		&domain,
		&updatedAt,
		&createdAt,
		&firstCompletedAt,
		&state,
		&cellID,
		&result,
		&failed,
		&failureReason,
		&taskDefData,
	)
	if err != nil {
		logger.Error("failed-scanning-row", err)
		return nil, models.ErrResourceNotFound
	}

	var taskDef models.TaskDefinition
	err = db.deserializeModel(logger, taskDefData, &taskDef)
	if err != nil {
		logger.Info("deleting-malformed-task-from-db", lager.Data{"guid": guid})
		_, err = tx.Exec(
			`DELETE FROM tasks WHERE guid = $1`,
			guid,
		)
		if err != nil {
			logger.Error("failed-deleting-task", err)
			return nil, db.convertSQLError(err)
		}
		return nil, models.ErrDeserialize
	}

	task := &models.Task{
		TaskGuid:         guid,
		Domain:           domain,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
		FirstCompletedAt: firstCompletedAt,
		State:            models.Task_State(state),
		CellId:           cellID,
		Result:           result.String,
		Failed:           failed,
		FailureReason:    failureReason,
		TaskDefinition:   &taskDef,
	}
	return task, nil
}
