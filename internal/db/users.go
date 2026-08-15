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

func validLocalPart(c byte) bool {
	switch {
	case c >= 97 && c <= 122: // a-z
		return false
	case c >= 65 && c <= 90: // A-Z
		return false
	case c >= 48 && c <= 57: // 0-9
		return false
	case c == 46 || c == 95 || c == 45 || c == 43 || c == 37: // ._+-%
		return false
	default:
		return true
	}
}

// follows RFC 5322
func ValidateEmail(e string) bool {
	if len(e) < 3 || len(e) > 254 {
		return false
	}

	for i, bfATR := 0, true; i < len(e); i++ {
		c := e[i]
		if c < 33 || c > 126 {
			return false
		} else if c == '@' {
			if bfATR {
				return false
			}
			bfATR = false
		}

		if bfATR {
			if c == 0 || c > 64 {
				return false
			} else if !validLocalPart(c) {
				return false
			} else if i == 0 &&  {

			}
		}
	}

	return true
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
