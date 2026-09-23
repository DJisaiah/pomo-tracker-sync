package server

import (
	"slices"
	"testing"

	"github.com/DJisaiah/pomotracker-sync/internal/config"
	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/google/uuid"
)

func TestLoadServerCrypt(t *testing.T) {
	tests := []struct {
		name        string
		cryptConfig *config.Config
		wantErr     bool
	}{
		{"valid config 1", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 32),
			HMACMasterKey: make([]byte, 32),
			Queries:       nil,
		}, false},
		{"invalid config -> 31 byte slice AESMK", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 31),
			HMACMasterKey: make([]byte, 32),
			Queries:       nil,
		}, true},
		{"invalid config -> 31 byte slice HMACMK", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 32),
			HMACMasterKey: make([]byte, 31),
			Queries:       nil,
		}, true},
		{"invalid config -> empty config", &config.Config{}, true},
		{"invalid config -> nil config", nil, true},
		{"invalid config -> 33 byte slice AESMK", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 33),
			HMACMasterKey: nil,
			Queries:       nil,
		}, true},
		{"invalid config -> 33 byte slice HMACMK", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 32),
			HMACMasterKey: make([]byte, 33),
			Queries:       nil,
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadServerCrypt(tt.cryptConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadServerCrypt() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateUserCrypt(t *testing.T) {
	c := &config.Config{
		DBurl:         "",
		AESMasterKey:  make([]byte, 32),
		HMACMasterKey: make([]byte, 32),
		Queries:       nil,
	}
	sa, err := loadServerCrypt(c)
	if err != nil {
		t.Fatalf("Failed to run generate user crypt tests: LoadServerCrypt() error = %v", err)
	}
	tests := []struct {
		name       string
		authConfig *db.AuthConfig
		authCrypt  *db.AuthCrypt
		wantErr    bool
	}{
		{
			name: "valid authconfig 1",
			authConfig: &db.AuthConfig{
				Email:      "test@example.com",
				Username:   "test",
				Password:   "password",
				Student:    false,
				LeftHanded: false,
			},
			wantErr: false,
		},
		{
			name: "valid authconfig 2",
			authConfig: &db.AuthConfig{
				Email:      "jane@doe.com",
				Username:   "janedoe",
				Password:   "password2",
				Student:    true,
				LeftHanded: true,
			},
			wantErr: false,
		},
		{
			name: "invalid authconfig -> mismatching uuid",
			authConfig: &db.AuthConfig{
				Email:      "test@example.com",
				Username:   "test",
				Password:   "password",
				Student:    false,
				LeftHanded: true,
			},
			authCrypt: &db.AuthCrypt{
				UUID: func() uuid.UUID { u, _ := uuid.NewV7(); return u }(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac, err := sa.crypt.generateUserCrypt(tt.authConfig)
			if (err != nil) != tt.wantErr {
				t.Fatalf("generateUserCrypt() error = %v, wantErr = %v", err, tt.wantErr)
			}
			decryptedEmail, err := sa.crypt.aesGCM.Open(
				nil,
				ac.EmailCipherTextBlob[:12],
				ac.EmailCipherTextBlob[12:],
				ac.UUID[:],
			)
			if err != nil {
				t.Fatalf("Failed to decrypt email. aesGCM.Open() error = %v", err)
			}

			if string(decryptedEmail) != tt.authConfig.Email {
				t.Errorf("Decrypted email = %s, want %s", decryptedEmail, tt.authConfig.Email)
			}

			if eBI := sa.crypt.generateEmailBlindIndex(tt.authConfig.Email); !slices.Equal(eBI, ac.EmailBlindIndex) {
				t.Errorf("Blind index matching failed: HMAC verification failed. Got %s, want %s", string(eBI), string(ac.EmailBlindIndex))
			}

			if pH, _ := sa.crypt.generatePasswordHash(tt.authConfig.Password); slices.Equal(pH, ac.PasswordHash) {
				t.Errorf("Password hash with different salt, matches. Got %s, and %s", pH, ac.PasswordHash)
			}

			if !sa.crypt.verifyPassword(tt.authConfig.Password, ac.PasswordHash, ac.PasswordSalt) {
				t.Errorf("Password hash with same salt mismatches. verifyPassword() = false, want true")
			}

		})
	}
}
