package db

import (
	"context"
	"errors"
	"log"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	ErrFailedToTerminateContainer = errors.New("failed to terminate postgres container")
	ErrFailedToStartContainer     = errors.New("failed to start postgres container")
	ErrFailedToGetConnectionStr   = errors.New("failed to get connection string")
	ErrFailedToInitPool           = errors.New("failed to initialize db pool")
)

type DBInstance struct {
	Queries           *Queries
	postgresContainer *postgres.PostgresContainer
}

func GetDBInstance() (DBInstance, error) {
	ctx := context.Background()
	postgresContainer, err := postgres.Run(
		ctx,
		"postgres:16-alpine",
		postgres.BasicWaitStrategies(),
	)

	if err != nil {
		log.Println(err)
		return DBInstance{}, ErrFailedToStartContainer
	}

	dbURL, err := postgresContainer.ConnectionString(ctx)
	if err != nil {
		log.Println(ErrFailedToGetConnectionStr, err)
		return DBInstance{}, ErrFailedToGetConnectionStr
	}

	q, err := InitializePool(dbURL)
	if err != nil {
		log.Println(ErrFailedToInitPool, err)
		return DBInstance{}, ErrFailedToInitPool
	}

	return DBInstance{q, postgresContainer}, nil
}

func (si *DBInstance) ClearTables() error {
	qry := `
	TRUNCATE TABLE
		users
		sessions
	`

	if _, err := si.Queries.pool.Exec(context.Background(), qry); err != nil {
		return err
	}

	return nil
}

func (si *DBInstance) Terminate() error {
	if err := testcontainers.TerminateContainer(si.postgresContainer); err != nil {
		log.Println(ErrFailedToTerminateContainer, err)
		return ErrFailedToTerminateContainer
	}

	return nil
}
