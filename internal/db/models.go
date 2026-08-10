package db

type User struct {
	LoginDetails AuthConfig
	LoginCrypt   AuthCrypt
}

type AuthConfig struct {
	Email      string
	Username   string
	Password   string
	Student    bool
	LeftHanded bool
}

type AuthCrypt struct {
	EmailCipherText []byte
	PasswordHash    []byte
	PasswordSalt    []byte
	Token           string
	ValidTil        string
}
