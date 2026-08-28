package validation

import (
	"log"
)

type Validator struct {
	commonPasswords     map[string]struct{}
	disallowedUsernames map[string]struct{}
}

func NewValidator() (*Validator, error) {
	v := Validator{}
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
