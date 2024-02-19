package basicAuthentication

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
)

func BasicAuthProtectedHandler(w http.ResponseWriter, r *http.Request) {

	username, _, ok := r.BasicAuth()

	if ok {
		templatePath, templateErr := filepath.Abs("./BasicAuthentication/static/protected.html")

		if templateErr != nil {
			fmt.Fprintf(w, "404: File not found")
			fmt.Println(templateErr)
			return
		}

		tmpl, err := template.ParseFiles(templatePath)

		if err != nil {
			fmt.Fprintf(w, "500: Internal server error")
			fmt.Println(err)
			return
		}

		tmpl.Execute(w, username)

		return

	}

	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func BasicAuthPublicHandler(w http.ResponseWriter, r *http.Request) {

	templatePath, templateErr := filepath.Abs("./BasicAuthentication/static/index.html")

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
}
