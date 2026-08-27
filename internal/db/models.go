package db

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	LoginDetails *AuthConfig
	LoginCrypt   *AuthCrypt
}

type AuthConfig struct {
	Email      string
	Username   string
	Password   string
	Student    bool
	LeftHanded bool
}

type AuthCrypt struct {
	UUID                uuid.UUID
	EmailBlindIndex     []byte
	EmailCipherTextBlob []byte
	PasswordHash        []byte
	PasswordSalt        []byte
	Token               string
	ValidTil            time.Time
}
