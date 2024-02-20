package basicAuthentication

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	database "github.com/suneel-eng/Authentication-Methods/Database"
)

func BasicAuthProtectedHandler(w http.ResponseWriter, r *http.Request) {

	username, password, ok := r.BasicAuth()

	if ok {

		query := `
			SELECT user_name FROM basic_auth WHERE user_name = ? AND user_password = ?
		`

		execErr := database.Db.QueryRow(query, username, password).Scan(&username)

		if execErr != nil {
			log.Fatal("Error", execErr)
			fmt.Fprintf(w, "Error: Internal server error")
			return
		}

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

func BasicAuthSignupHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	query := `
		INSERT INTO basic_auth ( user_name, user_password ) VALUES ( ?, ? )
	`

	_, err := database.Db.Exec(query, username, password)

	if err != nil {
		log.Fatal("Error 500 internal server error", err)
	}

	fmt.Fprintf(w, "Signup success")

}
