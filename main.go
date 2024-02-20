package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	basicAuthentication "github.com/suneel-eng/Authentication-Methods/BasicAuthentication"
	database "github.com/suneel-eng/Authentication-Methods/Database"
	formAuthentication "github.com/suneel-eng/Authentication-Methods/FormAuthentication"
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

	router := mux.NewRouter()

	basicAuthRouter := router.PathPrefix("/basic-auth").Subrouter()

	basicAuthRouter.HandleFunc("/", middleware.Logger(basicAuthentication.BasicAuthPublicHandler)).Methods("POST", "GET")
	basicAuthRouter.HandleFunc("/protected", middleware.Logger(basicAuthentication.BasicAuthProtectedHandler)).Methods("POST", "GET")
	basicAuthRouter.HandleFunc("/signup", middleware.Logger(basicAuthentication.BasicAuthSignupHandler)).Methods("POST")

	formAuthRouter := router.PathPrefix("/form-auth").Subrouter()

	formAuthRouter.HandleFunc("/", middleware.Logger(formAuthentication.FormAuthPublicHandler)).Methods("GET")
	formAuthRouter.HandleFunc("/protected", middleware.Logger(formAuthentication.FormAuthProtectedHandler)).Methods("GET", "POST")

	host := os.Getenv("HOST")
	port := os.Getenv("PORT")

	http.ListenAndServe(host+":"+port, router)

}
