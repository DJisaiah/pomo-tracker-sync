package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/DJisaiah/pomotracker-sync/internal/db"
)

var (
	ErrInvalidRequestType = errors.New("Invalid Request Type")
	ErrInvalidPayload     = errors.New("Invalid Payload")
)

type application struct {
	sa *serverActions
}

type registerOrLoginResponse struct {
	RefreshToken string `json:"refreshToken"`
}

func missingFields(ac *db.AuthConfig) bool {
	// we accept booleans as false by default
	// to avoid the headache of *bool
	switch {
	case ac.Email == "":
		return true
	case ac.Username == "":
		return true
	case ac.Password == "":
		return true
	default:
		return false
	}
}

// only accept POST and json on this endpoint
func (app *application) register(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method != http.MethodPost:
		http.Error(w, ErrInvalidRequestType.Error(), http.StatusMethodNotAllowed)
		return
	case r.Header.Get("Content-Type") != "application/json":
		http.Error(w, ErrInvalidRequestType.Error(), http.StatusBadRequest)
		return
	}

	// serveHTTP does this, we dont actually need to
	defer r.Body.Close()
	jd := json.NewDecoder(r.Body)
	jd.DisallowUnknownFields()
	var ac db.AuthConfig
	// if payload doesnt match struct members dont accept
	if err := jd.Decode(&ac); (err != nil) || missingFields(&ac) {
		log.Print("failed to decode payload in handler")
		log.Printf("error: %v", err != nil)
		http.Error(w, ErrInvalidPayload.Error(), http.StatusBadRequest)
		return
	}

	t, err := app.sa.registerUser(&ac)
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
			http.Error(w, "Internal server error occured. Please try again later.", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	tokenResponse := registerOrLoginResponse{
		RefreshToken: t,
	}
	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
		log.Printf("unresolved error in token encoding: %v", err)
		http.Error(w, "something went wrong; cannot serialise token", http.StatusInternalServerError)
		return
	}
}

func start(sa *serverActions) {
	app := application{sa: sa}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", app.register)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	err := srv.ListenAndServe()
	log.Fatal(err)
}
