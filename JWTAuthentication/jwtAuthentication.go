package jwtAuthentication

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	database "github.com/suneel-eng/Authentication-Methods/Database"
)

func JWTAuthRefreshTokenHandler(w http.ResponseWriter, r *http.Request) {

	type RequestBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	var requestBody RequestBody
	jsonParseErr := json.NewDecoder(r.Body).Decode(&requestBody)

	refreshToken := requestBody.RefreshToken

	if jsonParseErr != nil {
		http.Error(w, "refresh token required", http.StatusBadRequest)
		return
	}

	token, tokenErr := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%v", "Unauthorized")
		}

		return []byte(os.Getenv("JWT_AUTH_REFRESH_SECRET_KEY")), nil
	})

	if tokenErr != nil {
		http.Error(w, "Unauthorized token", http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			http.Error(w, "Unauthorized token", http.StatusUnauthorized)
			return
		}

		var userId string

		query := `
			SELECT user_id FROM jwt_auth_users WHERE user_id = ? AND refresh_token = ?
		`

		execErr := database.Db.QueryRow(query, claims["sub"], refreshToken).Scan(&userId)

		if execErr != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Generate access token for the user
		accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": "http://localhost:3000",
			"sub": userId,
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
		newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": "http://localhost:3000",
			"sub": userId,
			"exp": time.Now().Add(time.Hour * 24).Unix(),
		})

		// Sign refresh token with another private secret key
		encodedRefreshToken, enReErr := newRefreshToken.SignedString([]byte(os.Getenv("JWT_AUTH_REFRESH_SECRET_KEY")))

		// throw the error, if there is an error to sign the token
		if enReErr != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store the refresh token in the database
		query = `
		UPDATE jwt_auth_users SET refresh_token=? WHERE user_id=?
	`

		_, insertErr := database.Db.Exec(query, encodedRefreshToken, userId)

		// throw error, if there is an error to update the row
		if insertErr != nil {
			http.Error(w, insertErr.Error(), http.StatusInternalServerError)
			return
		}

		// Send response
		type LoggedInUser struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}

		response := LoggedInUser{
			AccessToken:  encodedAccessToken,
			RefreshToken: encodedRefreshToken,
		}

		json.NewEncoder(w).Encode(response)
		return

	} else {
		http.Error(w, "Unauthorized token", http.StatusUnauthorized)
		return
	}

}

func JWTAuthProtectedHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")

	if bearerToken := strings.Split(auth, " "); bearerToken[0] == "Bearer" {
		authToken := bearerToken[1]

		token, tokenErr := jwt.Parse(authToken, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("%v", "Unauthorized")
			}

			return []byte(os.Getenv("JWT_AUTH_ACCESS_SECRET_KEY")), nil
		})

		if tokenErr != nil {
			http.Error(w, "Unauthorized token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

			if float64(time.Now().Unix()) > claims["exp"].(float64) {
				http.Error(w, "Unauthorized token", http.StatusUnauthorized)
				return
			}

			type User struct {
				Username string `json:"username"`
				UserId   string `json:"userId"`
			}

			query := `
				SELECT user_name, user_id FROM jwt_auth_users WHERE user_id = ?
			`

			var user User
			execErr := database.Db.QueryRow(query, claims["sub"]).Scan(&user.Username, &user.UserId)

			if execErr != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			json.NewEncoder(w).Encode(user)
			return
		} else {
			http.Error(w, "Unauthorized token", http.StatusUnauthorized)
			return
		}
	}

	http.Error(w, "Unauthorized token", http.StatusUnauthorized)
}

func JWTAuthLoginHandler(w http.ResponseWriter, r *http.Request) {

	type User struct {
		UserId   string
		Username string
		Password string
	}

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
	type User struct {
		UserId   string
		Username string
		Password string
	}

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
