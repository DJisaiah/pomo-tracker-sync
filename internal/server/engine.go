package server

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/DJisaiah/pomotracker-sync/internal/config"
	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/DJisaiah/pomotracker-sync/internal/validation"
)

var (
	ErrNilConfig                = errors.New("config is nil")
	ErrInvalidAESKey            = errors.New("AES master key must be 32 bytes")
	ErrInvalidHMACKey           = errors.New("HMAC master key must be 32 bytes")
	ErrFailedToFetchAccessToken = errors.New("Unable to fetch access token")
)

type UserStore interface {
	AddUser(u *db.AuthCrypt) error
	FetchCryptByUsername(lc *db.LoginConfig) (db.AuthCrypt, error)
	FetchCryptByEmail(lc *db.LoginConfig, eBI []byte) (db.AuthCrypt, error)
	FetchCryptByRefreshToken(rt []byte) (db.AuthCrypt, error)
	UpdateRefreshToken(ac *db.AuthCrypt, as *db.AuthSuccess) error
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
	switch {
	case !sa.validator.Email(ac.Email):
		log.Printf("error validating email")
		return db.ErrInvalidEmail
	case !sa.validator.Password(ac.Password):
		log.Printf("error validating password")
		return db.ErrInvalidPassword
	case !sa.validator.Username(ac.Username):
		log.Printf("error validating username")
		return db.ErrInvalidUsername
	default:
		return nil
	}
}

func (sa *serverActions) validateLoginConfig(lc *db.LoginConfig) error {
	switch {
	case !sa.validator.Password(lc.Password):
		log.Printf("error validating password")
		return db.ErrInvalidPassword
	case lc.Email == "" && !sa.validator.Username(lc.Username):
		log.Printf("error validating username")
		return db.ErrInvalidUsername
	case !sa.validator.Email(lc.Email):
		log.Printf("error validating email")
		return db.ErrInvalidEmail
	default:
		return nil
	}
}

func (sa *serverActions) loginUser(lc *db.LoginConfig) ([32]byte, error) {
	if err := sa.validateLoginConfig(lc); err != nil {
		log.Printf("error validating auth config: %v", err)
		return [32]byte{}, err
	}

	var ac db.AuthCrypt
	var err error
	if lc.Email == "" {
		ac, err = sa.queries.FetchCryptByEmail(lc, sa.crypt.generateEmailBlindIndex(lc.Email))
	} else {
		ac, err = sa.queries.FetchCryptByUsername(lc)
	}
	if err != nil {
		log.Printf("error fetching auth crypt: %v", err)
		//http.Error(w, ErrServerError.Error(), http.StatusInternalServerError)
		// move to handler
		return [32]byte{}, db.ErrFailedToLogin
	}

	tkn, err := sa.crypt.authenticateLogin(lc, &ac)
	if err != nil {
		log.Printf("error authenticating login: %v", err)
		return [32]byte{}, db.ErrInvalidLogin
	}

	if tkn.NewToken {
		err := sa.queries.UpdateRefreshToken(&ac, &tkn)
		if err != nil {
			log.Printf("error updating refresh token: %v", err)
			return [32]byte{}, db.ErrFailedToLogin
		}
	}

	return tkn.Token, nil
}

func (sa *serverActions) registerUser(rc *db.RegisterConfig) ([32]byte, error) {
	err := sa.validateRegisterConfig(rc)
	if err != nil {
		log.Printf("error validating auth config: %v", err)
		return [32]byte{}, err
	}

	rc.Email = strings.ToLower(rc.Email)

	ac, err := sa.crypt.generateUserCrypt(rc)
	if err != nil {
		log.Printf("error generating user crypt: %v", err)
		return [32]byte{}, err
	}

	// handle this in handler TODO
	// is this still todo?
	err = sa.queries.AddUser(ac)
	if err != nil {
		log.Printf("Failed to add user: %v", err)
		return [32]byte{}, err
	}

	return ac.RefreshToken, nil
}

func (sa *serverActions) requestAccessToken(at *registerOrLoginResponse) (accessTokenPayload, error) {
	ac, err := sa.queries.FetchCryptByRefreshToken(at.RefreshToken)
	if err != nil {
		log.Printf("error fetching auth crypt by refresh token: %v", err)
		return accessTokenPayload{}, db.ErrFailedToFetchCrypt
	}
	u, err := ac.UUID.MarshalText()
	if err != nil {
		log.Printf("error marshalling UUID for access token request: %v", err)
		return accessTokenPayload{}, db.ErrFailedToFetchCrypt
	}
	exp := time.Now().UTC().Add(30 * time.Minute)
	texp, err := exp.MarshalText()
	if err != nil {
		log.Printf("error marshalling expiration time for access token request: %v", err)
		return accessTokenPayload{}, db.ErrFailedToFetchCrypt
	}
	sig := sa.crypt.hmac.generateFromSlices([][]byte{u, texp})

	return accessTokenPayload{
		AccessToken: u,
		Signature:   sig,
		ExpiresAt:   exp,
	}, nil
}
