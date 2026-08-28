package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"log"
	"os"
	"strings"
	"time"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/DJisaiah/pomotracker-sync/internal/validation"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
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

func loadEnv() (string, []byte, []byte) {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	env, err := os.Open(".env")
	if err != nil {
		log.Fatal("Error opening .env file")
	}
	defer env.Close()

	dbURL, dbExists := os.LookupEnv("DATABASE_URL")
	if !dbExists {
		log.Fatal("Error connecting to db")
	}

	var aesMasterKey, hmacMasterKey []byte
	aesKEncoded, aesExists := os.LookupEnv("AES_MASTER_KEY")
	if !aesExists {
		b := make([]byte, 32)
		rand.Read(b)
		aesMasterKey = b
		env.WriteString(fmt.Sprintf("AES_MASTER_KEY=%s\n", base64.StdEncoding.EncodeToString(b)))
	} else {
		aesMasterKey, err = base64.StdEncoding.DecodeString(aesKEncoded)
		if err != nil {
			log.Fatal("Error decoding AES secret key")
		}
	}

	hmKEncoded, hskExists := os.LookupEnv("HASH_MASTER_KEY")
	if !hskExists {
		b := make([]byte, 32)
		rand.Read(b)
		hmacMasterKey = b
		env.WriteString(fmt.Sprintf("HASH_MASTER_KEY=%s\n", base64.StdEncoding.EncodeToString(b)))
	} else {
		hmacMasterKey, err = base64.StdEncoding.DecodeString(hmKEncoded)
		if err != nil {
			log.Fatal("Error decoding hash secret key")
		}
	}
	return dbURL, aesMasterKey, hmacMasterKey
}

func StartServer(q *db.Queries) {
	dbURL, aesMasterKey, hashMasterKey := loadEnv()
	aesC, err := aes.NewCipher(aesMasterKey)
	if err != nil {
		log.Fatal("Error creating AES cipher")
	}
	aesGCMc, err := cipher.NewGCM(aesC)
	if err != nil {
		log.Fatal("Error creating AES-GCM cipher")
	}

	q, err = db.InitializePool(dbURL)
	if err != nil {
		log.Printf("Failed to initialise pool: %v", err)
	}

	v, err := validation.NewValidator()
	if err != nil {
		log.Fatal("Error creating validator")
	}

	sa := serverActions{
		queries: q,
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
	start(&sa)
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

func (sa *serverActions) registerUser(ac *db.AuthConfig) (string, error) {
	err := sa.validateAuthConfig(ac)
	if err != nil {
		return "", err
	}

	ac.Email = strings.ToLower(ac.Email)
	ac.Username = strings.ToLower(ac.Username)

	uuid, err := uuid.NewV7()
	if err != nil {
		log.Printf("Failed to generate UUID: %v", err)
		return "", err
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

	usr := db.User{
		LoginDetails: ac,
		LoginCrypt: &db.AuthCrypt{
			UUID:                uuid,
			EmailBlindIndex:     eBI,
			EmailCipherTextBlob: eCtB,
			PasswordHash:        pH,
			PasswordSalt:        slt,
			Token:               tkn,
			ValidTil:            vTil,
		},
	}

	// handle this in handler TODO
	err = sa.queries.AddUser(usr)
	if err != nil {
		log.Printf("Failed to add user: %v", err)
	}

	return tkn, nil
}
