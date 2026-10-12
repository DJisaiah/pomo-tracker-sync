package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
)

var (
	ErrInvalidRequestType = errors.New("Invalid Request Type")
	ErrInvalidPayload     = errors.New("Invalid Payload")
	ErrServerError        = errors.New("Internal server error occured. Please try again later.")
)

type application struct {
	sa *serverActions
}

type registerOrLoginResponse struct {
	RefreshToken []byte `json:"refreshToken"`
}

type accessTokenPayload struct {
	// encoding/json makes auto encodes/decodes byte slices to/from base64
	// it does NOT do that for byte arrays; it rather makes them int arrays
	AccessToken []byte    `json:"accessToken"`
	Signature   []byte    `json:"signature"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func validRequest(r *http.Request, method string, contentType string) (int, error) {
	switch {
	case r.Method != method:
		return http.StatusMethodNotAllowed, ErrInvalidRequestType
	case r.Header.Get("Content-Type") != contentType:
		return http.StatusBadRequest, ErrInvalidRequestType
	default:
		return 0, nil
	}
}

func (app *application) decodeAndValidateJSON(b io.ReadCloser, v any) error {
	// decode and validate json into structs
	defer b.Close()
	jd := json.NewDecoder(b)
	jd.DisallowUnknownFields()
	if err := jd.Decode(v); err != nil {
		log.Printf("failed to decode payload in handler: %v\n", err)
		return ErrInvalidPayload
	}
	if err := app.sa.validator.Struct(v); err != nil {
		log.Printf("failed to validate payload in handler: %v\n", err)
		return err
	}
	return nil
}

func (app *application) login(w http.ResponseWriter, r *http.Request) {
	if status, err := validRequest(r, http.MethodPost, "application/json"); err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	var lc db.LoginConfig
	err := app.decodeAndValidateJSON(r.Body, &lc)
	if err != nil {
		http.Error(w, ErrInvalidPayload.Error(), http.StatusBadRequest)
		return
	}

	tkn, err := app.sa.loginUser(&lc)
	if err != nil {
		log.Printf("error in user login: %v", err)
		switch {
		case errors.Is(err, db.ErrInvalidLogin):
			http.Error(w, db.ErrInvalidLogin.Error(), http.StatusUnauthorized)
		case errors.Is(err, db.ErrInvalidEmail):
			http.Error(w, db.ErrInvalidEmail.Error(), http.StatusBadRequest)
		case errors.Is(err, db.ErrInvalidUsername):
			http.Error(w, db.ErrInvalidUsername.Error(), http.StatusBadRequest)
		case errors.Is(err, db.ErrInvalidPassword):
			http.Error(w, db.ErrInvalidPassword.Error(), http.StatusBadRequest)
		case errors.Is(err, db.ErrFailedToLogin):
			http.Error(w, db.ErrFailedToLogin.Error(), http.StatusInternalServerError)
		default:
			log.Printf("unresolved error in user login: %v", err)
			http.Error(w, ErrServerError.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	tokenResponse := registerOrLoginResponse{
		RefreshToken: tkn[:],
	}
	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
		log.Printf("unresolved error in token encoding for login: %v", err)
		http.Error(w, "something went wrong; cannot serialise token", http.StatusInternalServerError)
		return
	}
}

func (app *application) register(w http.ResponseWriter, r *http.Request) {
	if status, err := validRequest(r, http.MethodPost, "application/json"); err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	var rc db.RegisterConfig
	err := app.decodeAndValidateJSON(r.Body, &rc)
	if err != nil {
		http.Error(w, ErrInvalidPayload.Error(), http.StatusBadRequest)
		return
	}

	t, err := app.sa.registerUser(&rc)
	if err != nil {
		log.Printf("error in user registration: %v", err)
		switch {
		case errors.Is(err, db.ErrUserAlreadyExists):
			http.Error(w, db.ErrUserAlreadyExists.Error(), http.StatusConflict)
		case errors.Is(err, db.ErrInvalidEmail):
			http.Error(w, db.ErrInvalidEmail.Error(), http.StatusBadRequest)
		case errors.Is(err, db.ErrInvalidUsername):
			http.Error(w, db.ErrInvalidUsername.Error(), http.StatusBadRequest)
		case errors.Is(err, db.ErrInvalidPassword):
			http.Error(w, db.ErrInvalidPassword.Error(), http.StatusBadRequest)
		case errors.Is(err, db.ErrFailedToRegister):
			http.Error(w, db.ErrFailedToRegister.Error(), http.StatusInternalServerError)
		default:
			log.Printf("unresolved error in user registration: %v", err)
			http.Error(w, ErrServerError.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	tokenResponse := registerOrLoginResponse{
		RefreshToken: t[:],
	}
	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
		log.Printf("unresolved error in token encoding for registration: %v", err)
		http.Error(w, "something went wrong; cannot serialise token", http.StatusInternalServerError)
		return
	}
}

func (app *application) request(w http.ResponseWriter, r *http.Request) {
	if status, err := validRequest(r, http.MethodPost, "application/json"); err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	var rt registerOrLoginResponse
	err := app.decodeAndValidateJSON(r.Body, &rt)
	if err != nil {
		http.Error(w, ErrInvalidPayload.Error(), http.StatusBadRequest)
		return
	}

	atp, err := app.sa.requestAccessToken(&rt)
	if err != nil {
		log.Printf("error in user registration: %v", err)
		switch {
		case errors.Is(err, db.ErrInvalidEmail):
			http.Error(w, db.ErrInvalidEmail.Error(), http.StatusBadRequest)
		case errors.Is(err, db.ErrInvalidUsername):
			http.Error(w, db.ErrInvalidUsername.Error(), http.StatusBadRequest)
		case errors.Is(err, db.ErrInvalidPassword):
			http.Error(w, db.ErrInvalidPassword.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrFailedToFetchAccessToken):
			http.Error(w, db.ErrFailedToRegister.Error(), http.StatusInternalServerError)
		default:
			log.Printf("unresolved error in token fetching: %v", err)
			http.Error(w, ErrServerError.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(atp); err != nil {
		log.Printf("unresolved error in token encoding for access token request: %v", err)
		http.Error(w, "something went wrong; cannot serialise token", http.StatusInternalServerError)
		return
	}
}

func start(sa *serverActions) {
	app := application{sa: sa}
	mux := http.NewServeMux()
	// rewrite this to automate
	mux.HandleFunc("POST /register", app.register)
	mux.HandleFunc("POST /login", app.login)
	mux.HandleFunc("POST /request", app.request)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	err := srv.ListenAndServe()
	log.Fatal(err)
}
