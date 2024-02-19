package formAuthentication

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
)

func FormAuthProtectedHandler(w http.ResponseWriter, r *http.Request) {

	username, _ := r.FormValue("username"), r.FormValue("password")
	templatePath, templateErr := filepath.Abs("./FormAuthentication/static/protected.html")

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
}

func FormAuthPublicHandler(w http.ResponseWriter, r *http.Request) {
	templatePath, templateErr := filepath.Abs("./FormAuthentication/static/index.html")

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
