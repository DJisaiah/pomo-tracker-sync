package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DJisaiah/pomotracker-sync/internal/chars"
	"github.com/DJisaiah/pomotracker-sync/internal/config"
	"github.com/DJisaiah/pomotracker-sync/internal/db"
)

type stubUserStore struct {
	errResult error
}

func (s *stubUserStore) AddUser(u db.NewUser) error {
	return s.errResult
}

func (s *stubUserStore) FetchCrypt(lc db.LoginConfig) (db.AuthCrypt, error)

func TestRegister(t *testing.T) {

	tests := []struct {
		name             string
		requestType      string
		header           http.Header
		payload          string
		expectedStatus   int
		expectedResponse string
		stubErr          error
	}{
		{
			name:        "valid request 1",
			requestType: "POST",
			header:      http.Header{"Content-Type": {"application/json"}},
			payload: `{
				"email":      "test@example.com",
				"username":   "testuser",
				"password":   "agoodpassword12",
				"student":    false,
				"leftHanded": false
			}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:        "invalid request -> wrong Content-Type",
			requestType: "POST",
			header:      http.Header{"Content-Type": {"application/xml"}},
			payload: `{
				"email": "test@example.com",
				"username": "testuser",
				"password": "agoodpassword12",
				"student": false,
				"leftHanded": false
			}`,
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: ErrInvalidRequestType.Error(),
		},
		{
			name:        "invalid request -> wrong request type",
			requestType: "GET",
			header:      http.Header{"Content-Type": {"application/json"}},
			payload: `{
				"email": "test@example.com",
				"username": "testuser",
				"password": "agoodpassword12",
				"student": false,
				"leftHanded": false
			}`,
			expectedStatus:   http.StatusMethodNotAllowed,
			expectedResponse: ErrInvalidRequestType.Error(),
		},
		{
			name:             "invalid payload -> no payload",
			requestType:      "POST",
			header:           http.Header{"Content-Type": {"application/json"}},
			payload:          "",
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: ErrInvalidPayload.Error(),
		},
		{
			name:        "invalid payload -> bad password",
			requestType: "POST",
			header:      http.Header{"Content-Type": {"application/json"}},
			payload: `{
				"email":      "test@example.com",
				"username":   "testuser",
				"password":   "password1234567",
				"student":    false,
				"leftHanded": false
			}`,
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: db.ErrInvalidPassword.Error(),
		},
		{
			name:        "invalid payload -> bad email",
			requestType: "POST",
			header:      http.Header{"Content-Type": {"application/json"}},
			payload: `{
				"email":      "testexample.com",
				"username":   "testuser",
				"password":   "agoodpassword12",
				"student":    false,
				"leftHanded": false
			}`,
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: db.ErrInvalidEmail.Error(),
		},
		{
			name:        "invalid payload -> bad username",
			requestType: "POST",
			header:      http.Header{"Content-Type": {"application/json"}},
			payload: `{
				"email":      "test@example.com",
				"username":   "admin",
				"password":   "agoodpassword12",
				"student":    false,
				"leftHanded": false
			}`,
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: db.ErrInvalidUsername.Error(),
		},
		{
			name:        "invalid payload -> missing fields",
			requestType: "POST",
			header:      http.Header{"Content-Type": {"application/json"}},
			payload: `{
				"email":    "test@example.com",
				"username": "testuser"
			}`,
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: ErrInvalidPayload.Error(),
		},
		{
			name:        "invalid payload -> extra fields",
			requestType: "POST",
			header:      http.Header{"Content-Type": {"application/json"}},
			payload: `{
				"email":      "test@example.com",
				"username":   "admin",
				"password":   "agoodpassword12",
				"student":    false,
				"leftHanded": false,
				"extraField": "extra"
			}`,
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: ErrInvalidPayload.Error(),
		},
		{
			name:             "invalid request -> completely missing headers",
			requestType:      "POST",
			header:           http.Header{},
			payload:          `{"Email": "test@example.com", "Username": "testuser"}`,
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: ErrInvalidRequestType.Error(),
		},
		{
			name:             "invalid payload -> empty json object",
			requestType:      "POST",
			header:           http.Header{"Content-Type": {"application/json"}},
			payload:          `{}`,
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: ErrInvalidPayload.Error(),
		},
		{
			name:             "invalid payload -> malformed json",
			requestType:      "POST",
			header:           http.Header{"Content-Type": {"application/json"}},
			payload:          `{"Email":`,
			expectedStatus:   http.StatusBadRequest,
			expectedResponse: ErrInvalidPayload.Error(),
		},
		{
			name:        "valid payload -> fail to register",
			requestType: "POST",
			header:      http.Header{"Content-Type": {"application/json"}},
			payload: `{
				"email":      "test@example.com",
				"username":   "testuser",
				"password":   "agoodpassword12",
				"student":    false,
				"leftHanded": false
			}`,
			expectedStatus:   http.StatusInternalServerError,
			expectedResponse: db.ErrFailedToRegister.Error(),
			stubErr:          db.ErrFailedToRegister,
		},
		{
			name:        "valid payload -> user already exists",
			requestType: "POST",
			header:      http.Header{"Content-Type": {"application/json"}},
			payload: `{
				"email":      "test@example.com",
				"username":   "testuser",
				"password":   "agoodpassword12",
				"student":    false,
				"leftHanded": false
			}`,
			expectedStatus:   http.StatusConflict,
			expectedResponse: db.ErrUserAlreadyExists.Error(),
			stubErr:          db.ErrUserAlreadyExists,
		},
	}

	c := &config.Config{
		DBurl:         "",
		AESMasterKey:  make([]byte, 32),
		HMACMasterKey: make([]byte, 32),
		Queries:       nil,
	}
	sa, err := loadServerCrypt(c)
	if err != nil {
		t.Fatalf("failed to load server crypt: %v", err)
	}
	a := application{
		sa: sa,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stubErr != nil {
				sa.queries = &stubUserStore{errResult: tt.stubErr}
			}
			req := httptest.NewRequest(tt.requestType, "/", strings.NewReader(tt.payload))
			req.Header = tt.header
			w := httptest.NewRecorder()
			a.register(w, req)
			resp := w.Result()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			b, err := io.ReadAll(resp.Body)
			defer resp.Body.Close()
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}
			log.Printf("Response body: %s", b)

			if resp.StatusCode == http.StatusOK {
				if resp.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected content type application/json, got %s", resp.Header.Get("Content-Type"))
					return
				}
				var tokenResponse map[string]any
				err = json.Unmarshal(b, &tokenResponse)
				if err != nil {
					t.Fatalf("failed to unmarshal response body: %v", err)
				}

				token, ok := tokenResponse["refreshToken"]
				var refreshToken string
				if ok {
					refreshToken, ok = token.(string)
					if !ok {
						t.Fatalf("refresh token cannot be made a string")
					}
				} else {
					t.Fatalf("refresh token not found in response")
				}

				if len(refreshToken) != 26 {
					t.Errorf("expected refresh token length 26, got %d", len(refreshToken))
				}
				if !chars.StringHasFunc(refreshToken, chars.IsBase32) {
					t.Errorf("failed to decode refresh token (likely not base32 or else): %v", err)
				}
				if len(tokenResponse) > 1 {
					t.Errorf("expected 1 obj in token response, got %d", len(tokenResponse))
				}
				return
			}
			if strings.TrimSpace(string(b)) != tt.expectedResponse {
				t.Errorf("expected response body %s, got %s", tt.expectedResponse, b)
			}
		})
	}
}
