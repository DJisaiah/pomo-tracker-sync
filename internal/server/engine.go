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

type UserStore interface {
	AddUser(u db.NewUser) error
	FetchCrypt(lc db.LoginConfig) (db.AuthCrypt, error)
}

type serverActions struct {
	queries   UserStore
	crypt     *serverCrypt
	validator *validation.Validator
}

func StartServer(q UserStore, c *config.Config) error {
	sa, err := loadServerCrypt(c)
	if err != nil {
		return err
	}
	start(sa)
	return nil
}

func (sa *serverActions) validateRegisterConfig(ac *db.RegisterConfig) error {
	if !sa.validator.Email(ac.Email) {
		log.Printf("error validating email: %v", ac.Email)
		return db.ErrInvalidEmail
	} else if !sa.validator.Password(ac.Password) {
		log.Printf("error validating password: %v", ac.Password)
		return db.ErrInvalidPassword
	} else if !sa.validator.Username(ac.Username) {
		log.Printf("error validating username: %v", ac.Username)
		return db.ErrInvalidUsername
	}
	return nil
}

func (sa *serverActions) registerUser(ac *db.RegisterConfig) (string, error) {
	err := sa.validateRegisterConfig(ac)
	if err != nil {
		log.Printf("error validating auth config: %v", err)
		return "", err
	}

	ac.Email = strings.ToLower(ac.Email)

	lc, err := sa.crypt.generateUserCrypt(ac)
	if err != nil {
		log.Printf("error generating user crypt: %v", err)
		return "", err
	}

	usr := db.NewUser{
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
