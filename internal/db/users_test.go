package db_test

import (
	"context"
	"testing"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
	"github.com/DJisaiah/pomotracker-sync/internal/testutil"
)

//

const aesMasterKey string = "3f95e5b5d9afad22315af3fc4e235dad552af788d143d057ce4da22e202f48a5"
const hashMasterKey string = "9f2c7a41e8b05d36a1c4f7e92b8d03a65c1e4f7b2a9d8036e5c1b4a7f2d90e83"

func TestUsers(t *testing.T) {
	si, err := testutil.GetDBInstance()
	if err != nil {
		t.Fatalf("failed to get server instance: %v", err)
	}
	defer si.Terminate()

	dc, err := testutil.NewDummyCrypt(aesMasterKey, hashMasterKey)

	tests := []struct {
		name string
		test func(t *testing.T, dbI *testutil.DBInstance, dc *testutil.DummyCrypt)
	}{
		{
			name: "Fetching Crypt by Username",
			test: TestfetchCryptByUsername,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.test(t, &si, &dc) })
	}

}

// second word lowercased to avoid go test running this w/o TestUsers
func TestfetchCryptByUsername(t *testing.T, dbI *testutil.DBInstance, dc *testutil.DummyCrypt) {
	t.Cleanup(func() {
		if err := dbI.ClearTables(); err != nil {
			t.Fatalf("failed to clear tables for fetching crypt by username: %v", err)
		}
	})

	/*
	 * u1: pwd -> password1p2 email -> djisaiah_dev@hotmail.com
	 */
	initQry := `
	INSERT INTO users(
		user_uuid,
		username,
		encrypted_email,
		email_blind_index,
		password_hash,
		password_salt,
		student,
		left_handed
	)
	VALUES (
		'40e6215d-b5c6-4896-987c-f30f3678f608',
		'freakbob',
		'\xde4273d8e8eacaf57509235643ff7e36e77e34de06bb311d60ab13cb146ec4a0efcc07607f5aa5dc',
		'\x7e5f7f3363d5fa8c8b44c54572023ca20cbeac5b7e991450effbda9f8edbc8f4',
		'\x19$m=65536,t=3,p=1$gtOQuXe3sEo+ZSQUqzfiKw$Y05p3zSlbeqD6B1oBMTU2UF3kpZJ5f/bxdpD43phFsk',
		'82d390b977b7b04a3e652414ab37e22b',
		true,
		false
	)
	`
	if err := dbI.Queries.Exec(context.Background(), initQry); err != nil {
		t.Fatalf("failed to insert test user for fetching crypt by username: %v", err)
	}

	lc := db.LoginConfig{
		Username:   "freakbob",
		Password:   "password1p2",
		Student:    true,
		LeftHanded: false,
	}

	ac, err := dbI.Queries.FetchCryptByUsername(&lc)
	if err != nil {
		t.Fatalf("failed to fetch crypt by username: %v", err)
	}

	if !dc.VerifyCrypt(&ac, &lc) {
		t.Fatalf("fetched crypt does not match expected values")
	}

}
