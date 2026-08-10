package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"hash"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/argon2"
)

// built in only encodes doesnt give type that encodes
// finish next time
type hmacCipher func(h hash.Hash, key []byte) []byte

type serverCrypt struct {
	ask []byte
	hsk []byte
	ac  *cipher.Block
	hmc *hmacCipher
}

type serverActions struct {
	q   *db.Queries
	sc  *serverCrypt
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

	q, err := db.InitializePool(dsn)
	if err != nil {
		log.Printf("Failed to initialise pool: %v", err)
	}
	s := serverActions{
		q: q,
		ask: ask,
		hsk: hsk,
		aesCipher: &ac,
	}
	start(s)
}

func (sa serverActions) registerUser(ac db.AuthConfig) (string, string, error) {
	tkn := rand.Text()
	vTil := "somedate"
	slt := make([]byte, 32)
	rand.Read(slt)
	pH := argon2.IDKey([]byte(ac.Password), slt, 3, 64*1024, 4, 32)
	ect := sa.

	usr := db.User{
		LoginDetails: ac,
		LoginCrypt: db.AuthCrypt{
			EmailCipherText: ,
			PasswordHash: pH,
			PasswordSalt: slt,
			Token:        tkn,
			ValidTil:     vTil,
		},
	}
	err := sa.q.AddUser(usr)
	if err != nil {
		return "", "", err
	}
	return tkn, vTil, nil
}
