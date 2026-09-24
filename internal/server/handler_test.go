package server_test

import (
	_ "encoding/json"
	_ "net/http"
	_ "net/http/httptest"
	"testing"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
)

func TestRegister(t *testing.T) {
	tests := []struct {
		name         string
		headerFields []string
		payload      *db.AuthConfig
		wantErr      bool
	}{
		{
			name:         "valid request 1",
			headerFields: []string{"Content-Type", "application/json"},
			payload: &db.AuthConfig{
				Email:      "test@example.com",
				Username:   "testuser",
				Password:   "password123",
				Student:    false,
				LeftHanded: false,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}
