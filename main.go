package main

import (
	"net/http"

	"github.com/gorilla/mux"
	basicAuthentication "github.com/suneel-eng/Authentication-Methods/BasicAuthentication"
	middleware "github.com/suneel-eng/Authentication-Methods/Middlewares"
)

func main() {

	router := mux.NewRouter()

	basicAuthRouter := router.PathPrefix("/basic-auth").Subrouter()

	basicAuthRouter.HandleFunc("/", middleware.Logger(basicAuthentication.BasicAuthPublicHandler)).Methods("POST", "GET")
	basicAuthRouter.HandleFunc("/protected", middleware.Logger(basicAuthentication.BasicAuthProtectedHandler)).Methods("POST", "GET")

	http.ListenAndServe("localhost:3000", router)

}
