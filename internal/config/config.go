package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/joho/godotenv"
)

var (
	ErrENVFileDoesNotExist = errors.New("ENV file does not exist")
	ErrDBURLNotFound       = errors.New("DB URL not found in env")
	ErrDecodingAESKey      = errors.New("Error decoding AES secret key")
	ErrDecodingHashKey     = errors.New("Error decoding hash secret key")
	ErrWritingToENVFile    = errors.New("Error writing to .env file")
)

type Config struct {
	DBurl         string
	AESMasterKey  []byte
	HMACMasterKey []byte
	Queries       *db.Queries
}

func Load() (*Config, error) {
	_, err := os.Stat("./.env")
	envExists := os.IsExist(err)
	if !envExists {
		return nil, ErrENVFileDoesNotExist
	}

	if err := godotenv.Load(); err != nil {
		log.Println("Error loading .env file")
		return nil, err
	}
	dbURL, dbURLExists := os.LookupEnv("DATABASE_URL")
	aesKEncoded, aesExists := os.LookupEnv("AES_MASTER_KEY")
	hmKEncoded, hskExists := os.LookupEnv("HASH_MASTER_KEY")

	env, err := os.Open(".env")
	if err != nil {
		log.Println("Error opening .env file")
		return nil, err
	}
	defer env.Close()

	var aesMasterKey, hmacMasterKey []byte
	switch {
	case !dbURLExists:
		log.Println("Error getting db url.")
		return nil, ErrDBURLNotFound
	case !aesExists:
		log.Println("Error loading AES master key. Generating it.")
		b := make([]byte, 32)
		rand.Read(b)
		aesMasterKey = b
		_, err := env.WriteString(fmt.Sprintf("AES_MASTER_KEY=%s\n", base64.StdEncoding.EncodeToString(b)))
		if err != nil {
			log.Println("Error writing AES master key to .env file")
			return nil, ErrWritingToENVFile
		}
		fallthrough
	case !hskExists:
		log.Println("Error loading hash master key. Generating it.")
		b := make([]byte, 32)
		rand.Read(b)
		hmacMasterKey = b
		_, err := env.WriteString(fmt.Sprintf("HASH_MASTER_KEY=%s\n", base64.StdEncoding.EncodeToString(b)))
		if err != nil {
			log.Println("Error writing HMAC master key to .env file")
			return nil, ErrWritingToENVFile
		}
	}

	queries, err := db.InitializePool(dbURL)
	if err != nil {
		log.Println("Error initializing database pool")
		return nil, err
	}

	aesMasterKey, err = base64.StdEncoding.DecodeString(aesKEncoded)
	if err != nil {
		log.Println("Error decoding AES secret key")
		return nil, ErrDecodingAESKey
	}

	hmacMasterKey, err = base64.StdEncoding.DecodeString(hmKEncoded)
	if err != nil {
		log.Println("Error decoding hash secret key")
		return nil, ErrDecodingHashKey
	}

	return &Config{dbURL, aesMasterKey, hmacMasterKey, queries}, nil
}
