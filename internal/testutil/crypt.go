package testutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"log"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type HMACCipher struct {
	key []byte
	c   hash.Hash
}

type DummyCrypt struct {
	AESMasterKey  []byte
	HashMasterKey []byte
	AESGCM        cipher.AEAD
	HMAC          *HMACCipher
}

func (hmC *HMACCipher) generate(s string) []byte {
	hmC.c.Reset()
	hmC.c.Write([]byte(s))
	return hmC.c.Sum(nil)
}

func NewDummyCrypt(aesMasterKey, hashMasterKey string) (DummyCrypt, error) {
	aK, err := hex.DecodeString(aesMasterKey)
	if err != nil {
		log.Println("Error decoding AES master key")
		return DummyCrypt{}, err
	}
	hK, err := hex.DecodeString(hashMasterKey)
	if err != nil {
		log.Println("Error decoding HMAC master key")
		return DummyCrypt{}, err
	}

	aesC, err := aes.NewCipher(aK)
	if err != nil {
		log.Println("Error creating AES cipher")
		return DummyCrypt{}, err
	}
	aesGCMc, err := cipher.NewGCM(aesC)
	if err != nil {
		log.Println("Error creating AES-GCM cipher")
		return DummyCrypt{}, err
	}

	hc := hmac.New(sha256.New, hK)

	return DummyCrypt{
		AESMasterKey:  aK,
		HashMasterKey: hK,
		AESGCM:        aesGCMc,
		HMAC:          &HMACCipher{hK, hc},
	}, nil
}

func (dc *DummyCrypt) verifyPassword(password string, hash, salt []byte) bool {
	pH := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return bytes.Equal(pH, hash)
}

func (dc *DummyCrypt) verifyEmail(id uuid.UUID, email string, encryptedEmail, blindIndex []byte) bool {
	// if there's no email then it must be via username (note that you could never get to this point without either)
	if email == "" {
		return true
	}
	aesNonce := make([]byte, 12)
	rand.Read(aesNonce)
	// ciphertextblob consists of nonce + ciphertext + authtag
	dst := make([]byte, 0, dc.AESGCM.NonceSize()+len(email)+dc.AESGCM.Overhead())
	dst = append(dst, aesNonce...)

	eCtB := dc.AESGCM.Seal(dst, aesNonce, []byte(email), id[:])
	return bytes.Equal(dc.HMAC.generate(email), blindIndex) && bytes.Equal(eCtB, encryptedEmail)
}

func (dc *DummyCrypt) VerifyCrypt(ac *db.AuthCrypt, lc *db.LoginConfig) bool {
	if (lc.LeftHanded != ac.LeftHanded) || (lc.Student != ac.Student) {
		return false
	} else if !dc.verifyEmail(ac.UUID, lc.Email, ac.EmailCipherTextBlob, ac.EmailBlindIndex) {

	} else if !dc.verifyPassword(lc.Password, ac.PasswordHash, ac.PasswordSalt) {
		return false
	}

	return true
}
