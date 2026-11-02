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
	UUID                uuid.UUID `db:"user_uuid"`
	EmailBlindIndex     []byte    `db:"email_blind_index"`
	EmailCipherTextBlob []byte    `db:"encrypted_email"`
	PasswordHash        []byte    `db:"password_hash"`
	PasswordSalt        []byte    `db:"password_salt"`
	Student             bool
	LeftHanded          bool     `db:"left_handed"`
	HashedRefreshToken  [32]byte `db:"token_hash"`
	RefreshToken        [32]byte
	TokenValidTil       time.Time `db:"expires_at"`
}

type AuthSuccess struct {
	HashedToken   [32]byte
	Token         [32]byte
	NewToken      bool
	TokenValidTil time.Time
}
