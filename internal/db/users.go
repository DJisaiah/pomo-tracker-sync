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

func isAlpabetic(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func validPartChar(c byte, isDomain bool) bool {
	switch {
	case isAlpabetic(c):
		return true
	case (c >= '0' && c <= '9'):
		return true
	case !isDomain && (c == '.' || c == '_' || c == '-' || c == '+' || c == '%' || c == '@'):
		return true
	case isDomain && (c == '.' || c == '-'):
		return true
	default:
		return false
	}
}

func nextCharIs(e string, c byte, i int) bool {
	if i >= 0 && i < len(e)-1 {
		if e[i+1] == c {
			return true
		}
	}
	return false
}

func nextCharIsFn(e string, c byte, i int, fn func(byte) bool) bool {
	if i >= 0 && i < len(e)-1 {
		return fn(e[i+1])
	}
	return false
}

func prevCharIs(e string, c byte, i int) bool {
	if i > 0 && i < len(e) {
		if e[i-1] == c {
			return true
		}
	}
	return false
}

func prevCharIsFn(e string, i int, fn func(byte) bool) bool {
	if i > 0 && i < len(e) {
		return fn(e[i-1])
	}
	return false
}

// WHATWG HTML5 specification combined with OWASP defensive validation
// stdlib accepts legacy features which we don't want esp ito security
func ValidateEmail(e string) bool {
	l := len(e)
	if l < 3 || l > 254 {
		return false

	} else if !isAlphanumeric(e[0]) { // alphanumeric start
		return false
	} else if !isAlpabetic(e[l-1]) { // alphabetic end
		return false
	}

	atr, tld := false, false
	tldI := -1
	for i := 0; i < l; i++ {
		c := e[i]
		if !validPartChar(c, atr) { // local and domain character whitelist
			return false
		} else if c == '@' {
			if atr { // only 1 @ allowed
				return false
			} else if i < 1 || i > 64 { // Local part must be between 1 and 64 characters long
				return false
			} else if !prevCharIsFn(e, i, isAlphanumeric) { // Local part cannot end non alphanumeric
				return false
			} else if nextCharIs(e, '.', i) || nextCharIs(e, '-', i) { // cant start with a dot/hyphen after @
				return false
			}
			atr = true
			// hyphen rules
		} else if c == '-' && (prevCharIs(e, '.', i) || nextCharIs(e, '.', i)) {
			return false
		} else if !atr {
			if !isAlphanumeric(c) { // no adjacent symbols
				if !prevCharIsFn(e, i, isAlphanumeric) {
					return false
				}
			}
		} else if atr {
			if c == '.' {
				if nextCharIs(e, '.', i) { // cannot have consecutive dots
					return false
				}
				tldI = i + 1
				tld = true
			}
		}
	}

	if !atr {
		return false // minimum 1 @
	} else if !tld {
		return false // needs a top level domain
	} else if tld && (l-tldI < 2) { // tld must be at least 2 chars long
		return false
	} else if tld {
		for i := tldI; i < len(e); i++ {
			if !isAlpabetic(e[i]) {
				return false // tld must be alphabetic
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
