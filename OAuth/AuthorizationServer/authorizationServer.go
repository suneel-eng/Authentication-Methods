package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/jaevor/go-nanoid"
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

	router.HandleFunc("/add-application", func(w http.ResponseWriter, r *http.Request) {

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

				type Application struct {
					AppName        string
					AppOrigin      string
					AppRedirectUrl string
					AppIdentifier  string
					AppSecret      string
					AppOwnerId     string
				}

				var app Application

				app.AppOwnerId = claims["sub"].(string)
				app.AppName = r.FormValue("app_name")
				app.AppOrigin = r.FormValue("allowed_origin")
				app.AppRedirectUrl = r.FormValue("redirect_url")

				identifier, idErr := nanoid.Standard(21)

				if idErr != nil {
					http.Error(w, idErr.Error(), http.StatusInternalServerError)
				}

				app.AppIdentifier = identifier()
				app.AppSecret = identifier()

				query := `
					INSERT INTO oauth_server_photos_apps ( app_name, app_origin, app_redirect_url, app_identifier, app_secret, app_owner_id )
					VALUES ( ?, ?, ?, ?, ?, ? )
				`

				_, err := database.Db.Exec(query, app.AppName, app.AppOrigin, app.AppRedirectUrl, app.AppIdentifier, app.AppSecret, app.AppOwnerId)

				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}

				fmt.Fprintf(w, "Success")
			} else {
				http.Error(w, "Unauthorized token", http.StatusUnauthorized)
				return
			}
		}

		http.Error(w, "Unauthorized token", http.StatusUnauthorized)

	}).Methods("POST")

	// Temporary Credential Request
	router.HandleFunc("/intiate", func(w http.ResponseWriter, r *http.Request) {

	})

	// Resource Owner Authorization URI
	router.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {

	})

	// Token Request URI
	router.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

	})

	host := "localhost"
	port := "8080"

	log.Printf("Server started listening on %s:%s", host, port)

	http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), router)
}
