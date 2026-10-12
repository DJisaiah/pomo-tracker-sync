package db

import (
	"time"

	"github.com/google/uuid"
)

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
	Student             bool
	LeftHanded          bool
	HashedRefreshToken  [32]byte
	RefreshToken        [32]byte
	TokenValidTil       time.Time
}

type AuthSuccess struct {
	HashedToken   [32]byte
	Token         [32]byte
	NewToken      bool
	TokenValidTil time.Time
}
