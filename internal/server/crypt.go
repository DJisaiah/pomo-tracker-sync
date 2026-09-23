package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"log"
	"time"

	"github.com/DJisaiah/pomotracker-sync/internal/config"
	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/DJisaiah/pomotracker-sync/internal/validation"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
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

func loadServerCrypt(c *config.Config) (*serverActions, error) {
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

func generatePasswordHashWithSpecificSalt(p string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 32)
		rand.Read(salt)
	}
	// recommended less memory intensive options for time, memory, and threads
	pH := argon2.IDKey([]byte(p), salt, 3, 64*1024, 4, 32)
	return pH, salt
}

func (sc *serverCrypt) generatePasswordHash(p string) ([]byte, []byte) {
	return generatePasswordHashWithSpecificSalt(p, nil)
}

func (sc *serverCrypt) generateEmailBlindIndex(e string) []byte {
	return sc.hmac.generate(e)
}

func (sc *serverCrypt) generateEmailCipherTextBlob(email string, uuid uuid.UUID) []byte {
	aesNonce := make([]byte, 12)
	rand.Read(aesNonce)
	// ciphertextblob consists of nonce + ciphertext + authtag
	dst := make([]byte, 0, sc.aesGCM.NonceSize()+len(email)+sc.aesGCM.Overhead())
	dst = append(dst, aesNonce...)

	eCtB := sc.aesGCM.Seal(dst, aesNonce, []byte(email), uuid[:])
	return eCtB
}

func (sc *serverCrypt) generateToken() (string, time.Time) {
	return rand.Text(), time.Now().UTC().AddDate(0, 0, 14)
}

func (sc *serverCrypt) generateUserCrypt(ac *db.AuthConfig) (*db.AuthCrypt, error) {
	uuid, err := uuid.NewV7()
	if err != nil {
		log.Printf("Failed to generate UUID: %v", err)
		return nil, err
	}

	tkn, vTil := sc.generateToken()

	pH, slt := sc.generatePasswordHash(ac.Password)

	eBI := sc.generateEmailBlindIndex(ac.Email)

	eCtB := sc.generateEmailCipherTextBlob(ac.Email, uuid)

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

func (sc *serverCrypt) verifyPassword(password string, hash []byte, salt []byte) bool {
	pH, _ := generatePasswordHashWithSpecificSalt(password, salt)
	return bytes.Equal(pH, hash)
}
