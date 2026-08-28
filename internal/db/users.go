package db

import (
	"context"
	"errors"
)

var (
	ErrUserAlreadyExists = errors.New("User already exists")
	ErrInvalidPassword   = errors.New("#TODO")
	ErrInvalidUsername   = errors.New("#TODO")
	ErrInvalidEmail      = errors.New("#TODO")
	ErrFailedToRegister  = errors.New("Unable to register")
)

func (q *Queries) setupUsers()

func (q *Queries) exists(u string) error

func Login() error

func (q *Queries) AddUser(u User) error {
	qry := `
		INSERT INTO users(email_bid, encrypted_email, username, encrypted_password, salt, student, left_handed)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := q.pool.Exec(
		context.Background(),
		qry,
		u.LoginCrypt.EmailBlindIndex,
		u.LoginDetails.Email,
		u.LoginDetails.Username,
		u.LoginCrypt.PasswordHash,
		u.LoginCrypt.PasswordSalt,
		u.LoginDetails.Student,
		u.LoginDetails.LeftHanded,
	)
	if err != nil {
		return ErrFailedToRegister
	}

	err = q.storeToken(u.LoginCrypt.Token, u.LoginCrypt.ValidTil)

	if err != nil {
		return ErrFailedToRegister
	}

	return nil
}

func (q *Queries) storeToken(t string, d string) error {
	qry := `
		INSERT INTO user_sessions()
	`
	return nil
}
