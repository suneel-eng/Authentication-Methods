package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	basicAuthentication "github.com/suneel-eng/Authentication-Methods/BasicAuthentication"
	formAuthentication "github.com/suneel-eng/Authentication-Methods/FormAuthentication"
	middleware "github.com/suneel-eng/Authentication-Methods/Middlewares"
)

func init() {
	configErr := godotenv.Load()
	if configErr != nil {
		log.Fatal("Error loading .env file")
	}

	db, dbErr := sql.Open(
		"mysql",
		fmt.Sprintf(
			"%s:%s@(%s:%s)/%s?parseTime=true",
			os.Getenv("DB_USERNAME"),
			os.Getenv("DB_PASSWORD"),
			os.Getenv("DB_HOST"),
			os.Getenv("DB_PORT"),
			os.Getenv("DB_NAME"),
		),
	)

	if dbErr != nil {
		log.Fatal("Error connection configuration", dbErr)
	}

	connectErr := db.Ping()

	if connectErr != nil {
		log.Fatal("Error connecting to database", connectErr)
	}
}

func main() {

	router := mux.NewRouter()

	basicAuthRouter := router.PathPrefix("/basic-auth").Subrouter()

	basicAuthRouter.HandleFunc("/", middleware.Logger(basicAuthentication.BasicAuthPublicHandler)).Methods("POST", "GET")
	basicAuthRouter.HandleFunc("/protected", middleware.Logger(basicAuthentication.BasicAuthProtectedHandler)).Methods("POST", "GET")

	formAuthRouter := router.PathPrefix("/form-auth").Subrouter()

	formAuthRouter.HandleFunc("/", middleware.Logger(formAuthentication.FormAuthPublicHandler)).Methods("GET")
	formAuthRouter.HandleFunc("/protected", middleware.Logger(formAuthentication.FormAuthProtectedHandler)).Methods("GET", "POST")

	host := os.Getenv("HOST")
	port := os.Getenv("PORT")

	http.ListenAndServe(host+":"+port, router)

}
