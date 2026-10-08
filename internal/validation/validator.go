package validation

import (
	"log"

	"github.com/go-playground/validator/v10"
)

type Validator struct {
	commonPasswords     map[string]struct{}
	disallowedUsernames map[string]struct{}
	structVal           *validator.Validate
}

func NewValidator() (*Validator, error) {
	v := Validator{
		commonPasswords:     make(map[string]struct{}),
		disallowedUsernames: make(map[string]struct{}),
		structVal:           validator.New(),
	}
	if err := v.loadPasswords(); err != nil {
		log.Printf("Failed to load common passwords: %s", err)
		return nil, err
	}
	if err := v.loadUsernames(); err != nil {
		log.Printf("Failed to load disallowed usernames: %s", err)
		return nil, err
	}
	return &v, nil
}

func (v *Validator) Struct(s any) error {
	return v.structVal.Struct(s)
}
