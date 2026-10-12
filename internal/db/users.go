package db

import (
	"context"
	"errors"
	"log"

	"github.com/jackc/pgx/v5"
)

var (
	ErrUserAlreadyExists  = errors.New("User already exists")
	ErrInvalidPassword    = errors.New("Password is invalid")
	ErrInvalidUsername    = errors.New("Username is invalid")
	ErrInvalidEmail       = errors.New("Email is invalid")
	ErrFailedToRegister   = errors.New("Unable to register")
	ErrFailedToLogin      = errors.New("Unable to login")
	ErrInvalidLogin       = errors.New("Invalid login credentials")
	ErrFailedToFetchCrypt = errors.New("Unable to fetch auth crypt")
)

func (q *Queries) setupUsers() {
	//todo
}

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
	u.encrypted_password,
	u.salt,
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
		u.encrypted_password,
		u.salt,
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

func (q *Queries) FetchCryptByRefreshToken(rt []byte) (AuthCrypt, error) {
	qry := `
		SELECT
		u.user_uuid,
		u.username,
		u.encrypted_email,
		u.encrypted_password,
		u.salt,
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

func (q *Queries) AddUser(ac *AuthCrypt) error {
	// qry := `
	// 	INSERT INTO users(email_bid, encrypted_email, username, encrypted_password, salt, student, left_handed)
	// 	VALUES ($1, $2, $3, $4, $5, $6, $7)
	// `
	// _, err := q.pool.Exec(
	// 	context.Background(),
	// 	qry,
	// 	u.LoginCrypt.EmailBlindIndex,
	// 	u.LoginDetails.Email, ??? this shouldnt be here
	// 	u.LoginDetails.Username,
	// 	u.LoginCrypt.PasswordHash,
	// 	u.LoginCrypt.PasswordSalt,
	// 	u.LoginDetails.Student,
	// 	u.LoginDetails.LeftHanded,
	// )
	// if err != nil {
	// 	return ErrFailedToRegister
	// }

	// err = q.storeToken(u.LoginCrypt.Token, u.LoginCrypt.ValidTil)

	// if err != nil {
	// 	return ErrFailedToRegister
	// }

	return nil
} //todo

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
