package db_test

import (
	"testing"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
)

func TestUsers(t *testing.T) {
	si, err := db.GetServerInstance()
	if err != nil {
		t.Fatalf("failed to get server instance: %v", err)
	}

	tests := []struct {
		name string
		test func(t *testing.T, si *db.ServerInstance)
	}{
		{
			name: "Fetching Crypt by Username",
			test: TestfetchCryptByUsername,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.test(t, &si) })
	}

}

// second word lowercased to avoid go test running this w/o TestUsers
func TestfetchCryptByUsername(t *testing.T, si *db.ServerInstance) {
	t.Cleanup(func() {
		if err := si.ClearTables(); err != nil {
			t.Fatalf("failed to clear tables for fetching crypt by username: %v", err)
		}
	})

	initQry := `

	`

	si.Queries.Exec()
}
