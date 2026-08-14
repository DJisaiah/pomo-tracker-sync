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

func ValidateEmail(e string) bool {
	result := true

	if len(e) < 3 || len(e) > 254 {
		return false
	}

	return result
}

func ValidatePassword(p string) bool

func ValidateUsername(u string) bool

func Login() error {
	return nil
}

// probably gonna remove some of this since engine check first
func (q *Queries) AddUser(u User) error {
	qry := `
		INSERT INTO users(username, password, salt, student, leftHanded)
		VALUES ($1, $2, $3, $4, $4)
	`
	_, err := q.pool.Exec(
		context.Background(),
		qry,
		u.LoginDetails.Username,
		u.LoginCrypt.PasswordHash,
		u.LoginCrypt.Salt,
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
