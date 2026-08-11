package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/argon2"
)

// built in only encodes doesnt give type that encodes
// finish next time
type hmacCipher struct {
	key []byte
}

type serverCrypt struct {
	ask []byte
	hsk []byte
	ac  cipher.Block
	hmc *hmacCipher
}

type serverActions struct {
	q  *db.Queries
	sc *serverCrypt
}

// s must be normalised first. #TODO
// otherwise could lead to unexpected results in blind index lookups.
func (c *hmacCipher) generate(s string) []byte {
	// should look into resetting this for concurrent use
	h := sha256.New
	ct := hmac.New(h, c.key)
	ct.Write([]byte(s))
	return ct.Sum(nil)
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

	dsn, dsnExists := os.LookupEnv("DATABASE_URL")
	if !dsnExists {
		log.Fatal("Error connecting to db")
	}

	var ask, hsk []byte
	askStr, aesExists := os.LookupEnv("AES_SECRET_KEY")
	if !aesExists {
		b := make([]byte, 32)
		rand.Read(b)
		ask = b
		env.WriteString(fmt.Sprintf("AES_SECRET_KEY=%s\n", base64.StdEncoding.EncodeToString(b)))
	} else {
		ask, err = base64.StdEncoding.DecodeString(askStr)
		if err != nil {
			log.Fatal("Error decoding AES secret key")
		}
	}

	hskStr, hskExists := os.LookupEnv("HASH_SECRET_KEY")
	if !hskExists {
		b := make([]byte, 32)
		rand.Read(b)
		hsk = b
		env.WriteString(fmt.Sprintf("HASH_SECRET_KEY=%s\n", base64.StdEncoding.EncodeToString(b)))
	} else {
		hsk, err = base64.StdEncoding.DecodeString(hskStr)
		if err != nil {
			log.Fatal("Error decoding hash secret key")
		}
	}
	return dsn, ask, hsk
}

func StartServer(q *db.Queries) {
	dsn, ask, hsk := loadEnv()
	ac, err := aes.NewCipher(ask)
	if err != nil {
		log.Fatal("Error creating AES cipher")
	}

	q, err = db.InitializePool(dsn)
	if err != nil {
		log.Printf("Failed to initialise pool: %v", err)
	}
	s := serverActions{
		q: q,
		sc: &serverCrypt{
			ask: ask,
			hsk: hsk,
			ac:  ac,
			hmc: &hmacCipher{
				key: hsk,
			},
		},
	}
	start(s)
}

func validateAuthConfig(ac *db.AuthConfig) error {
	if !db.ValidateEmail(ac.Email) {
		return db.ErrInvalidEmail
	} else if !db.ValidatePassword(ac.Password) {
		return db.ErrInvalidPassword
	} else if !db.ValidateUsername(ac.Username) {
		return db.ErrInvalidUsername
	}
	return nil
}

func (sa serverActions) registerUser(ac *db.AuthConfig) (string, string, error) {
	err := validateAuthConfig(ac)
	if err != nil {
		return "", "", err
	}

	var ect []byte
	tkn := rand.Text()
	vTil := "somedate"
	slt := make([]byte, 32)
	rand.Read(slt)
	pH := argon2.IDKey([]byte(ac.Password), slt, 3, 64*1024, 4, 32)
	// once all the email chars are valid, they just need to be lowercased
	sa.sc.ac.Encrypt(ect, []byte(strings.ToLower(ac.Email)))

	usr := db.User{
		LoginDetails: ac,
		LoginCrypt: &db.AuthCrypt{
			EmailCipherText: ect,
			PasswordHash:    pH,
			PasswordSalt:    slt,
			Token:           tkn,
			ValidTil:        vTil,
		},
	}

	err = sa.q.AddUser(usr)
	if err != nil {
		log.Printf("Failed to add user: %v", err)
	}

	return tkn, vTil, nil
}
