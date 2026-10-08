package db

import (
	"time"

	"github.com/google/uuid"
)

type NewUser struct {
	LoginDetails *RegisterConfig
	LoginCrypt   *AuthCrypt
}

type RegisterConfig struct {
	Email      string `json:"email" validate:"required"`
	Username   string `json:"username" validate:"required"`
	Password   string `json:"password" validate:"required"`
	Student    bool   `json:"student"`
	LeftHanded bool   `json:"leftHanded"`
}

type LoginConfig struct {
	Email      string `json:"email" validate:"required_without=Username,excluded_with=Username"`
	Username   string `json:"username" validate:"required_without=Email,excluded_with=Email"`
	Password   string `json:"password" validate:"required"`
	Student    bool   `json:"student"`
	LeftHanded bool   `json:"leftHanded"`
}

type AuthCrypt struct {
	UUID                uuid.UUID
	EmailBlindIndex     []byte
	EmailCipherTextBlob []byte
	PasswordHash        []byte
	PasswordSalt        []byte
	RefreshToken        string
	ValidTil            time.Time
}
