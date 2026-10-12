package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

// s must be normalised first.
// otherwise could lead to unexpected results in blind index lookups.

func (hmC *hmacCipher) generate(s string) []byte {
	hmC.c.Reset()
	hmC.c.Write([]byte(s))
	return hmC.c.Sum(nil)
}

func (hmC *hmacCipher) generateFromByte(b []byte) []byte {
	hmC.c.Reset()
	hmC.c.Write(b)
	return hmC.c.Sum(nil)
}

func (hmC *hmacCipher) generateFromSlices(b [][]byte) []byte {
	hmC.c.Reset()
	for _, i := range b {
		hmC.c.Write(i)
	}
	return hmC.c.Sum(nil)
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

func (sc *serverCrypt) generateToken() ([32]byte, time.Time) {
	b := [32]byte{}
	rand.Read(b[:])
	return b, time.Now().UTC().AddDate(0, 0, 14)
}

func (sc *serverCrypt) authenticateLogin(lc *db.LoginConfig, ac *db.AuthCrypt) (db.AuthSuccess, error) {
	// no need to check if email/username valid. can't fetch ac without it to begin with
	if (lc.LeftHanded != ac.LeftHanded) || (lc.Student != ac.Student) {
		return db.AuthSuccess{}, db.ErrFailedToLogin
	} else if !sc.verifyPassword(lc.Password, ac.PasswordHash, ac.PasswordSalt) {
		return db.AuthSuccess{}, db.ErrInvalidPassword
	}

	// if refresh token expires within 24hrs just generate a new one
	if time.Now().UTC().AddDate(0, 0, 1).Compare(ac.TokenValidTil) >= 0 {
		tkn, vTil := sc.generateToken()
		return db.AuthSuccess{
			Token:         tkn,
			NewToken:      true,
			TokenValidTil: vTil,
		}, nil
	}

	return db.AuthSuccess{
		HashedToken:   sha256.Sum256(ac.RefreshToken[:]),
		Token:         ac.RefreshToken,
		NewToken:      false,
		TokenValidTil: ac.TokenValidTil,
	}, nil
}

func (sc *serverCrypt) generateUserCrypt(rc *db.RegisterConfig) (*db.AuthCrypt, error) {
	uuid, err := uuid.NewV7()
	if err != nil {
		log.Printf("Failed to generate UUID: %v", err)
		return nil, err
	}

	tkn, vTil := sc.generateToken()
	hTkn := sha256.Sum256(tkn[:])

	pH, slt := sc.generatePasswordHash(rc.Password)

	eBI := sc.generateEmailBlindIndex(rc.Email)

	eCtB := sc.generateEmailCipherTextBlob(rc.Email, uuid)

	return &db.AuthCrypt{
		UUID:                uuid,
		EmailBlindIndex:     eBI,
		EmailCipherTextBlob: eCtB,
		PasswordHash:        pH,
		PasswordSalt:        slt,
		Student:             rc.Student,
		LeftHanded:          rc.LeftHanded,
		HashedRefreshToken:  hTkn,
		RefreshToken:        tkn,
		TokenValidTil:       vTil,
	}, nil
}

func (sc *serverCrypt) verifyPassword(password string, hash []byte, salt []byte) bool {
	pH, _ := generatePasswordHashWithSpecificSalt(password, salt)
	if subtle.ConstantTimeCompare(pH, hash) == 0 {
		return false
	}
	return true
}

func (sc *serverCrypt) verifyAccessToken(at accessTokenPayload) bool {
	s := sc.hmac.generateFromByte(at.AccessToken)
	if subtle.ConstantTimeCompare(at.AccessToken, s) == 0 {
		return false
	}
	return true
}
