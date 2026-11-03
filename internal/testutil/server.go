package testutil

import "github.com/DJisaiah/pomotracker-sync/internal/db"

type StubUserStore struct {
	ErrResult error
}

func (s *StubUserStore) AddUser(username string, ac *db.AuthCrypt) error {
	return s.ErrResult
}

func (s *StubUserStore) FetchCryptByEmail(lc *db.LoginConfig, eBI []byte) (db.AuthCrypt, error) {
	//todo
	return db.AuthCrypt{}, nil
}

func (s *StubUserStore) UpdateRefreshToken(ac *db.AuthCrypt, as *db.AuthSuccess) error {
	return nil //todo
}

func (s *StubUserStore) FetchCryptByUsername(lc *db.LoginConfig) (db.AuthCrypt, error) {
	// todo
	return db.AuthCrypt{}, nil
}

func (q *StubUserStore) FetchCryptByRefreshToken(rt []byte) (db.AuthCrypt, error) {
	return db.AuthCrypt{}, nil
}
