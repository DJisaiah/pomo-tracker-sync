package db

import (
	"context"

	_ "github.com/jackc/pgx"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Queries struct {
	pool *pgxpool.Pool
}

func InitializePool(dsn string) (*Queries, error) {
	pool, err := pgxpool.New(context.Background(), dsn)
	q := &Queries{pool: pool}
	if err != nil {
		return nil, err
	}
	q.setupTables()

	return q, nil
}

func (q *Queries) setupTables() {
	q.setupUsers()
	q.setupSessions()
}
