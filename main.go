package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	basicAuthentication "github.com/suneel-eng/Authentication-Methods/BasicAuthentication"
	database "github.com/suneel-eng/Authentication-Methods/Database"
	formAuthentication "github.com/suneel-eng/Authentication-Methods/FormAuthentication"
	jwtAuthentication "github.com/suneel-eng/Authentication-Methods/JWTAuthentication"
	middleware "github.com/suneel-eng/Authentication-Methods/Middlewares"
)

func init() {
	configErr := godotenv.Load()
	if configErr != nil {
		log.Fatal("Error loading .env file")
	}

	database.InitDb()
}

func main() {
	fmt.Printf("%v", time.Now())
	router := mux.NewRouter()

	basicAuthRouter := router.PathPrefix("/basic-auth").Subrouter()

	basicAuthRouter.HandleFunc("/", middleware.Logger(basicAuthentication.BasicAuthPublicHandler)).Methods("POST", "GET")
	basicAuthRouter.HandleFunc("/protected", middleware.Logger(basicAuthentication.BasicAuthProtectedHandler)).Methods("POST", "GET")
	basicAuthRouter.HandleFunc("/signup", middleware.Logger(basicAuthentication.BasicAuthSignupHandler)).Methods("POST")

	formAuthRouter := router.PathPrefix("/form-auth").Subrouter()

	formAuthRouter.HandleFunc("/", middleware.Logger(formAuthentication.FormAuthPublicHandler)).Methods("GET")
	formAuthRouter.HandleFunc("/protected", middleware.Logger(formAuthentication.FormAuthProtectedHandler)).Methods("GET", "POST")
	formAuthRouter.HandleFunc("/signup", middleware.Logger(formAuthentication.FormAuthSignupHandler)).Methods("POST")

	jwtAuthRouter := router.PathPrefix("/jwt-auth").Subrouter()

	jwtAuthRouter.HandleFunc("/login", middleware.Logger(jwtAuthentication.JWTAuthLoginHandler)).Methods("POST")
	jwtAuthRouter.HandleFunc("/protected", middleware.Logger(jwtAuthentication.JWTAuthProtectedHandler)).Methods("GET")
	jwtAuthRouter.HandleFunc("/signup", middleware.Logger(jwtAuthentication.JWTAuthSignupHandler)).Methods("POST")

	host := os.Getenv("HOST")
	port := os.Getenv("PORT")

	http.ListenAndServe(host+":"+port, router)

}
