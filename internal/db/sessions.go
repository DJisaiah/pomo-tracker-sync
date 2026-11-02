package db

import (
	"context"
	"errors"
	"log"

	"github.com/jackc/pgx/v5"
)

var (
	ErrFailedToSetupSessionsTable = errors.New("Unable to setup sessions table")
)

func (q *Queries) setupSessions() error {
	qry := `
	CREATE TABLE IF NOT EXISTS sessions (
	user_uuid uuid NOT NULL,
	token_hash BYTEA UNIQUE NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	FOREIGN KEY(user_uuid)
		REFERENCES users(user_uuid)
		ON DELETE CASCADE
	)
	`

	if _, err := q.pool.Exec(context.Background(), qry); err != nil {
		log.Println("error creating sessions table:", err)
		return ErrFailedToSetupSessionsTable
	}

	return nil
}

// why do we not use as here at all? what's going on? TODO
func (q *Queries) UpdateRefreshToken(ac *AuthCrypt, as *AuthSuccess) error {
	qry := `
	INSERT INTO sessions(user_uuid, token_hash, expires_at)
	VALUES ($1, $2, $3)
	`

	if _, err := q.pool.Exec(
		context.Background(),
		qry,
		ac.UUID,
		ac.HashedRefreshToken,
		ac.TokenValidTil,
	); err != nil {
		log.Println("error updating refresh token:", err)
		return ErrFailedToLogin
	}

	return nil
}

func (q *Queries) FetchCryptByRefreshToken(rt []byte) (AuthCrypt, error) {
	qry := `
		SELECT
		u.user_uuid,
		u.username,
		u.encrypted_email,
		u.password_hash,
		u.password_salt,
		u.student,
		u.left_handed,
		s.token_hash,
		s.expires_at
		FROM users u
		JOIN sessions s ON s.user_uuid = u.user_uuid
		WHERE s.token_hash = $1
		ORDER BY u.id
		LIMIT 1;
		`
	pr, err := q.pool.Query(
		context.Background(),
		qry,
		rt,
	)
	if err != nil {
		log.Println("error fetching auth crypt by username:", err)
		return AuthCrypt{}, ErrFailedToFetchCrypt
	}

	ac, err := pgx.CollectExactlyOneRow(pr, pgx.RowToStructByNameLax[AuthCrypt])
	if err != nil {
		log.Println("error collecting auth crypt by refresh token:", err)
		return AuthCrypt{}, ErrFailedToFetchCrypt
	}
	return ac, nil //write this up //also check out why tests are failing (prob outdated sizes)
}
