package jwtAuthentication

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	database "github.com/suneel-eng/Authentication-Methods/Database"
)

type User struct {
	UserId   string
	Username string
	Password string
}

func JWTAuthProtectedHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")

	fmt.Println(auth)
}

func JWTAuthLoginHandler(w http.ResponseWriter, r *http.Request) {

	// Get user credentials
	var user User
	json.NewDecoder(r.Body).Decode(&user)

	// throw error if any one of credentials missing
	if user.Username == "" || user.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}

	// Lookup the user with the help of provided credentials
	query := `
			SELECT user_name, user_id FROM jwt_auth_users WHERE user_name = ? AND user_password = ?
		`

	execErr := database.Db.QueryRow(query, &user.Username, &user.Password).Scan(&user.Username, &user.UserId)

	// throw error if there is no user with provided credentials
	if execErr != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate access token for the user
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "http://localhost:3000",
		"sub": user.UserId,
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	})

	// Sign the access token with a private secret key
	encodedAccessToken, enAccErr := accessToken.SignedString([]byte(os.Getenv("JWT_AUTH_ACCESS_SECRET_KEY")))

	// throw the error, if there is an error to sign the token
	if enAccErr != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "http://localhost:3000",
		"sub": user.UserId,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	// Sign refresh token with another private secret key
	encodedRefreshToken, enReErr := refreshToken.SignedString([]byte(os.Getenv("JWT_AUTH_REFRESH_SECRET_KEY")))

	// throw the error, if there is an error to sign the token
	if enReErr != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store the refresh token in the database
	query = `
		UPDATE jwt_auth_users SET refresh_token=? WHERE user_id=?
	`

	_, insertErr := database.Db.Exec(query, encodedRefreshToken, user.UserId)

	// throw error, if there is an error to update the row
	if insertErr != nil {
		http.Error(w, insertErr.Error(), http.StatusInternalServerError)
		return
	}

	// Send response
	type LoggedInUser struct {
		Username     string `json:"username"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	response := LoggedInUser{
		Username:     user.Username,
		AccessToken:  encodedAccessToken,
		RefreshToken: encodedRefreshToken,
	}

	json.NewEncoder(w).Encode(response)

}

func JWTAuthSignupHandler(w http.ResponseWriter, r *http.Request) {

	var user User
	json.NewDecoder(r.Body).Decode(&user)

	if user.Username == "" || user.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}

	query := `
		INSERT INTO jwt_auth_users ( user_name, user_password ) VALUES ( ?, ? )
	`

	_, err := database.Db.Exec(query, user.Username, user.Password)

	if err != nil {
		log.Fatal("Error 500 internal server error", err)
	}

	fmt.Fprintf(w, "Signup success")

}
