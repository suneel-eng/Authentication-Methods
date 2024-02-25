package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
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
	})

	host := "localhost"
	port := "3000"

	log.Printf("Server started listening on %s:%s", host, port)

	http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), router)
}
