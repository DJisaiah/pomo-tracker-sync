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
		ac, err := sa.crypt.generateUserCrypt(tt.authConfig)
		if (err != nil) && !tt.wantErr {
			t.Fatalf("generateUserCrypt() error = %v, wantErr = %v", err, tt.wantErr)
		}
		if tt.authCrypt != nil {
			ac.UUID = tt.authCrypt.UUID
		}
		t.Run(tt.name, func(t *testing.T) {
			assertEmailDecrypts(t, sa, ac, tt.wantErr)

			assertMismatchedUUIDFails(t, sa, ac, tt.authConfig.Email, tt.wantErr)

			assertBlindIndexMatches(t, sa, ac, tt.authConfig.Email)

			assertPasswordVerifies(t, sa, ac, tt.authConfig.Password)
		})
	}
}

func assertPasswordVerifies(t *testing.T, sa *serverActions, ac *db.AuthCrypt, password string) {
	if pH, _ := sa.crypt.generatePasswordHash(password); slices.Equal(pH, ac.PasswordHash) {
		t.Errorf("Password hash with different salt, matches. Got %s, and %s", pH, ac.PasswordHash)
	}

	if pH, _ := sa.crypt.generatePasswordHash("wrong-password"); slices.Equal(pH, ac.PasswordHash) {
		t.Errorf("Wrong password with different salt matches.")
	}

	if !sa.crypt.verifyPassword(password, ac.PasswordHash, ac.PasswordSalt) {
		t.Errorf("Password hash with same salt mismatches.")
	}

	if sa.crypt.verifyPassword("wrong-password", ac.PasswordHash, ac.PasswordSalt) {
		t.Errorf("Wrong password with same salt matches.")
	}
}

func assertBlindIndexMatches(t *testing.T, sa *serverActions, ac *db.AuthCrypt, email string) {
	if eBI := sa.crypt.generateEmailBlindIndex(email); !slices.Equal(eBI, ac.EmailBlindIndex) {
		t.Errorf("Blind index matching failed: HMAC verification failed. Got %s, want %s", string(eBI), string(ac.EmailBlindIndex))
	}
}

func assertMismatchedUUIDFails(t *testing.T, sa *serverActions, ac *db.AuthCrypt, email string, wantErr bool) {
	decryptedEmailBytes, _ := sa.crypt.aesGCM.Open(
		nil,
		ac.EmailCipherTextBlob[:12],
		ac.EmailCipherTextBlob[12:],
		ac.UUID[:],
	)
	dEmail := string(decryptedEmailBytes)
	if (dEmail != email) != wantErr {
		t.Errorf("Decrypted email = %s, want %s", dEmail, email)
	}
}

func assertEmailDecrypts(t *testing.T, sa *serverActions, ac *db.AuthCrypt, wantErr bool) {
	_, err := sa.crypt.aesGCM.Open(
		nil,
		ac.EmailCipherTextBlob[:12],
		ac.EmailCipherTextBlob[12:],
		ac.UUID[:],
	)
	if (err != nil) != wantErr {
		t.Fatalf("Failed to decrypt email. aesGCM.Open() error = %v", err)
	}
}
