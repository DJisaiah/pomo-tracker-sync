package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Queries struct {
	pool *pgxpool.Pool
}

func InitializePool(dbURL string) (*Queries, error) {
	pool, err := pgxpool.New(context.Background(), dbURL)
	q := &Queries{pool: pool}
	if err != nil {
		pool.Close()
		return nil, err
	}
	if err = q.setupTables(); err != nil {
		pool.Close()
		return nil, err
	}

	return q, nil
}

func (q *Queries) setupTables() error {
	err := q.setupUsers()
	if err != nil {
		return err
	}
	err = q.setupSessions()
	if err != nil {
		return err
	}

	return nil
}

func (q *Queries) Exec(ctx context.Context, sql string, args ...any) error {
	if _, err := q.pool.Exec(ctx, sql, args...); err != nil {
		return err
	}

	return nil
}

func (q *Queries) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	pr, err := q.pool.Query(
		ctx,
		sql,
		args...,
	)
	if err != nil {
		return nil, err
	}

	return pr, nil
}
