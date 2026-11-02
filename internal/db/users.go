package db

import (
	"context"
	"errors"
	"log"

	"github.com/jackc/pgx/v5"
)

var ( // some of these error messages...should they be here?
	ErrFailedToSetupUsersTable = errors.New("Unable to setup users table")
	ErrUserAlreadyExists       = errors.New("User already exists")
	ErrInvalidPassword         = errors.New("Password is invalid")
	ErrInvalidUsername         = errors.New("Username is invalid")
	ErrInvalidEmail            = errors.New("Email is invalid")
	ErrFailedToRegister        = errors.New("Unable to register")
	ErrFailedToLogin           = errors.New("Unable to login")
	ErrInvalidLogin            = errors.New("Invalid login credentials")
	ErrFailedToFetchCrypt      = errors.New("Unable to fetch auth crypt")
)

func (q *Queries) setupUsers() error {
	qry := `
	CREATE TABLE IF NOT EXISTS users (
	id SERIAL,
	user_uuid uuid PRIMARY KEY,
	username VARCHAR(30) UNIQUE NOT NULL CHECK(LENGTH(TRIM(username)) >= 3),
	encrypted_email BYTEA UNIQUE NOT NULL,
	email_blind_index BYTEA UNIQUE NOT NULL,
	password_hash BYTEA NOT NULL,
	password_salt BYTEA NOT NULL,
	student BOOLEAN NOT NULL,
	left_handed BOOLEAN NOT NULL
	)
	`

	if _, err := q.pool.Exec(context.Background(), qry); err != nil {
		log.Println("error creating users table:", err)
		return ErrFailedToSetupUsersTable
	}

	return nil
}

// prob wont need this if i just catch the unique failure
func (q *Queries) exists(u string) error {
	//todo
	return nil
}

func (q *Queries) FetchCryptByEmail(lc *LoginConfig, eBI []byte) (AuthCrypt, error) {
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
	WHERE u.email_blind_index = $1
	ORDER BY u.id
	LIMIT 1;
	`
	pr, err := q.pool.Query(
		context.Background(),
		qry,
		eBI,
	)
	if err != nil {
		log.Println("error fetching auth crypt by email:", err)
		return AuthCrypt{}, ErrFailedToFetchCrypt
	}

	// auth crypt doesnt have struct tags from what i remember so check that out TODO
	ac, err := pgx.CollectExactlyOneRow(pr, pgx.RowToStructByNameLax[AuthCrypt])
	if err != nil {
		log.Println("error collecting auth crypt via email:", err)
		return AuthCrypt{}, ErrFailedToFetchCrypt
	}
	return ac, nil
}

func (q *Queries) FetchCryptByUsername(lc *LoginConfig) (AuthCrypt, error) {
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
		WHERE u.username = $1
		ORDER BY u.id
		LIMIT 1;
		`
	pr, err := q.pool.Query(
		context.Background(),
		qry,
		lc.Username,
	)
	if err != nil {
		log.Println("error fetching auth crypt by username:", err)
		return AuthCrypt{}, ErrFailedToFetchCrypt
	}

	ac, err := pgx.CollectExactlyOneRow(pr, pgx.RowToStructByNameLax[AuthCrypt])
	if err != nil {
		log.Println("error collecting auth crypt by username:", err)
		return AuthCrypt{}, ErrFailedToFetchCrypt
	}
	return ac, nil
}

func (q *Queries) AddUser(username string, ac *AuthCrypt) error {
	qry := `
	 	INSERT INTO users(
			user_uuid,
			username,
			encrypted_email,
			email_blind_index,
			password_hash,
			password_salt,
			student,
			left_handed
		)
	 	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	 `
	_, err := q.pool.Exec(
		context.Background(),
		qry,
		ac.UUID,
		username,
		ac.EmailCipherTextBlob,
		ac.EmailBlindIndex,
		ac.PasswordHash,
		ac.PasswordSalt,
		ac.Student,
		ac.LeftHanded)
	if err != nil {
		return ErrFailedToRegister
	}

	//TODO
	//err = q.storeToken(u.LoginCrypt.Token, u.LoginCrypt.ValidTil)

	//if err != nil {
	//	return ErrFailedToRegister
	//}

	return nil
}
