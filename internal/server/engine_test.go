package server

import (
	"testing"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
)

func TestRegisterIntegration(t *testing.T) {

	tests := []struct {
		name           string
		setupQuery     string
		registerConfig db.RegisterConfig
		expectedErr    error
	}{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//q.pool.Ex
		})
	}
}
