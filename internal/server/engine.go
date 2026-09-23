package server

import (
	"errors"
	"log"
	"strings"

	"github.com/DJisaiah/pomotracker-sync/internal/config"
	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/DJisaiah/pomotracker-sync/internal/validation"
)

var (
	ErrNilConfig      = errors.New("config is nil")
	ErrInvalidAESKey  = errors.New("AES master key must be 32 bytes")
	ErrInvalidHMACKey = errors.New("HMAC master key must be 32 bytes")
)

type serverActions struct {
	queries   *db.Queries
	crypt     *serverCrypt
	validator *validation.Validator
}

// s must be normalised first.
// otherwise could lead to unexpected results in blind index lookups.
func (hmC *hmacCipher) generate(s string) []byte {
	hmC.c.Reset()
	hmC.c.Write([]byte(s))
	return hmC.c.Sum(nil)
}

func StartServer(q *db.Queries, c *config.Config) error {
	sa, err := loadServerCrypt(c)
	if err != nil {
		return err
	}
	start(sa)
	return nil
}

func (sa *serverActions) validateAuthConfig(ac *db.AuthConfig) error {
	if !sa.validator.Email(ac.Email) {
		return db.ErrInvalidEmail
	} else if !sa.validator.Password(ac.Password) {
		return db.ErrInvalidPassword
	} else if !sa.validator.Username(ac.Username) {
		return db.ErrInvalidUsername
	}
	return nil
}

func (sa *serverActions) registerUser(ac *db.AuthConfig) (string, error) {
	err := sa.validateAuthConfig(ac)
	if err != nil {
		return "", err
	}

	ac.Email = strings.ToLower(ac.Email)

	lc, err := sa.crypt.generateUserCrypt(ac)
	if err != nil {
		return "", err
	}

	usr := db.User{
		LoginDetails: ac,
		LoginCrypt:   lc,
	}

	// handle this in handler TODO
	err = sa.queries.AddUser(usr)
	if err != nil {
		log.Printf("Failed to add user: %v", err)
		return "", err
	}

	return lc.RefreshToken, nil
}
