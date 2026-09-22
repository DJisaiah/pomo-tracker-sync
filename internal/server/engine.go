package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"log"
	"strings"
	"time"

	"github.com/DJisaiah/pomotracker-sync/internal/config"
	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/DJisaiah/pomotracker-sync/internal/validation"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

var (
	ErrNilConfig      = errors.New("config is nil")
	ErrInvalidAESKey  = errors.New("AES master key must be 32 bytes")
	ErrInvalidHMACKey = errors.New("HMAC master key must be 32 bytes")
)

type hmacCipher struct {
	key []byte
	c   hash.Hash
}

type serverCrypt struct {
	aesMasterKey  []byte
	hashMasterKey []byte
	aesGCM        cipher.AEAD
	hmac          *hmacCipher
}

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

func LoadServerCrypt(c *config.Config) (*serverActions, error) {
	if c == nil {
		log.Println("config is nil")
		return nil, ErrNilConfig
	}
	queries, aesMasterKey, hashMasterKey := c.Queries, c.AESMasterKey, c.HMACMasterKey
	switch {
	case len(aesMasterKey) != 32:
		log.Println("AES master key must be 32 bytes")
		return nil, ErrInvalidAESKey
	case len(hashMasterKey) != 32:
		log.Println("HMAC master key must be 32 bytes")
		return nil, ErrInvalidHMACKey
	}
	aesC, err := aes.NewCipher(aesMasterKey)
	if err != nil {
		log.Println("Error creating AES cipher")
		return nil, err
	}
	aesGCMc, err := cipher.NewGCM(aesC)
	if err != nil {
		log.Println("Error creating AES-GCM cipher")
		return nil, err
	}

	v, err := validation.NewValidator()
	if err != nil {
		log.Println("Error creating validator")
		return nil, err
	}

	sa := serverActions{
		queries: queries,
		crypt: &serverCrypt{
			aesMasterKey:  aesMasterKey,
			hashMasterKey: hashMasterKey,
			aesGCM:        aesGCMc,
			hmac: &hmacCipher{
				key: hashMasterKey,
				c:   hmac.New(sha256.New, hashMasterKey),
			},
		},
		validator: v,
	}
	return &sa, nil
}

func StartServer(q *db.Queries, c *config.Config) error {
	sa, err := LoadServerCrypt(c)
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

func (sa *serverActions) generateUserCrypt(ac *db.AuthConfig) (*db.AuthCrypt, error) {
	uuid, err := uuid.NewV7()
	if err != nil {
		log.Printf("Failed to generate UUID: %v", err)
		return nil, err
	}

	tkn := rand.Text()
	vTil := time.Now().UTC().AddDate(0, 0, 14)

	slt := make([]byte, 32)
	rand.Read(slt)
	// recommended less memory intensive options for time, memory, and threads
	pH := argon2.IDKey([]byte(ac.Password), slt, 3, 64*1024, 4, 32)

	eBI := sa.crypt.hmac.generate(ac.Email)

	aesNonce := make([]byte, 12)
	rand.Read(aesNonce)
	// ciphertextblob consists of nonce + ciphertext + authtag
	dst := make([]byte, sa.crypt.aesGCM.NonceSize()+len(ac.Email)+sa.crypt.aesGCM.Overhead())
	dst = append(dst, aesNonce...)

	eCtB := sa.crypt.aesGCM.Seal(dst, aesNonce, []byte(ac.Email), uuid[:])

	return &db.AuthCrypt{
		UUID:                uuid,
		EmailBlindIndex:     eBI,
		EmailCipherTextBlob: eCtB,
		PasswordHash:        pH,
		PasswordSalt:        slt,
		RefreshToken:        tkn,
		ValidTil:            vTil,
	}, nil
}

func (sa *serverActions) registerUser(ac *db.AuthConfig) (string, error) {
	err := sa.validateAuthConfig(ac)
	if err != nil {
		return "", err
	}

	ac.Email = strings.ToLower(ac.Email)

	lc, err := sa.generateUserCrypt(ac)
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
