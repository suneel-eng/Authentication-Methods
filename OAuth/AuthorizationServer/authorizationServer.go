package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	database "github.com/suneel-eng/Authentication-Methods/Database"
)

func init() {
	configErr := godotenv.Load("../../.env")
	if configErr != nil {
		log.Fatal("Error loading .env file")
	}

	database.InitDb()
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		templatePath, templateErr := filepath.Abs("./static/dashboard.html")

		if templateErr != nil {
			fmt.Fprintf(w, "404: File not found")
			return
		}

		tmpl, err := template.ParseFiles(templatePath)

		if err != nil {
			fmt.Fprintf(w, "500: Internal server error")
			fmt.Println(err)
			return
		}

		tmpl.Execute(w, nil)
	})

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {

		if r.Method == http.MethodGet {
			templatePath, templateErr := filepath.Abs("./static/login.html")

			if templateErr != nil {
				fmt.Fprintf(w, "404: File not found")
				return
			}

			tmpl, err := template.ParseFiles(templatePath)

			if err != nil {
				fmt.Fprintf(w, "500: Internal server error")
				fmt.Println(err)
				return
			}

			tmpl.Execute(w, nil)
			return
		}

		if r.Method == http.MethodPost {
			type User struct {
				UserId   string
				Username string
				Password string
			}

			// Get user credentials
			var user User
			user.Username = r.FormValue("username")
			user.Password = r.FormValue("password")

			// throw error if any one of credentials missing
			if user.Username == "" || user.Password == "" {
				http.Error(w, "username and password required", http.StatusBadRequest)
				return
			}

			// Lookup the user with the help of provided credentials
			query := `
					SELECT user_name, user_id FROM oauth_server_photos WHERE user_name = ? AND user_password = ?
				`

			execErr := database.Db.QueryRow(query, &user.Username, &user.Password).Scan(&user.Username, &user.UserId)

			// throw error if there is no user with provided credentials
			if execErr != nil {
				http.Error(w, execErr.Error(), http.StatusInternalServerError)
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
				UPDATE oauth_server_photos SET refresh_token=? WHERE user_id=?
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
	}).Methods("GET", "POST")

	router.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			templatePath, templateErr := filepath.Abs("./static/signup.html")

			if templateErr != nil {
				fmt.Fprintf(w, "404: File not found")
				return
			}

			tmpl, err := template.ParseFiles(templatePath)

			if err != nil {
				fmt.Fprintf(w, "500: Internal server error")
				fmt.Println(err)
				return
			}

			tmpl.Execute(w, nil)
			return
		}

		if r.Method == http.MethodPost {
			type User struct {
				UserId   string
				Username string
				Password string
			}

			var user User
			user.Username = r.FormValue("username")
			user.Password = r.FormValue("password")

			if user.Username == "" || user.Password == "" {
				http.Error(w, "username and password required", http.StatusBadRequest)
				return
			}

			query := `
				INSERT INTO oauth_server_photos ( user_name, user_password ) VALUES ( ?, ? )
			`

			_, err := database.Db.Exec(query, user.Username, user.Password)

			if err != nil {
				log.Fatal("Error 500 internal server error", err)
			}

			fmt.Fprintf(w, "Signup success")
			return
		}
	}).Methods("GET", "POST")

	host := "localhost"
	port := "8080"

	log.Printf("Server started listening on %s:%s", host, port)

	http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), router)
}
