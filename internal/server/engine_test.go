package server_test

import (
	"testing"

	"github.com/DJisaiah/pomotracker-sync/internal/config"
	"github.com/DJisaiah/pomotracker-sync/internal/server"
)

func TestLoadServerCrypt(t *testing.T) {
	tests := []struct {
		name        string
		cryptConfig *config.Config
		wantErr     bool
	}{
		{"valid config 1", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 32),
			HMACMasterKey: make([]byte, 32),
			Queries:       nil,
		}, false},
		{"invalid config -> 31 byte slice AESMK", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 31),
			HMACMasterKey: make([]byte, 32),
			Queries:       nil,
		}, true},
		{"invalid config -> 31 byte slice HMACMK", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 32),
			HMACMasterKey: make([]byte, 31),
			Queries:       nil,
		}, true},
		{"invalid config -> empty config", &config.Config{}, true},
		{"invalid config -> nil config", nil, true},
		{"invalid config -> 33 byte slice AESMK", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 33),
			HMACMasterKey: nil,
			Queries:       nil,
		}, true},
		{"invalid config -> 33 byte slice HMACMK", &config.Config{
			DBurl:         "",
			AESMasterKey:  make([]byte, 32),
			HMACMasterKey: make([]byte, 33),
			Queries:       nil,
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := server.LoadServerCrypt(tt.cryptConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadServerCrypt() error = %v", err)
			}
		})
	}
}
