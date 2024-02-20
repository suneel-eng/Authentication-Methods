package formAuthentication

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gorilla/sessions"

	database "github.com/suneel-eng/Authentication-Methods/Database"
)

func FormAuthProtectedHandler(w http.ResponseWriter, r *http.Request) {

	var (
		// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
		key   = []byte("super-secret-key")
		store = sessions.NewCookieStore(key)
	)
	session, sessionErr := store.Get(r, "cookie-name")

	if sessionErr != nil {
		log.Fatal(sessionErr)
		fmt.Fprintf(w, "Error: 500 internal server error")
		return
	}

	username, password := r.FormValue("username"), r.FormValue("password")

	if username == "" && password == "" {
		// authentication using cookies
		sessionId, ok := session.Values["session_id"].(int64)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		query := `
			SELECT u.user_name FROM form_auth_sessions AS s INNER JOIN form_auth_users As u
			ON s.user_id = u.user_id WHERE s.session_id = ?
			AND TIMEDIFF(NOW(), s.expiry) < 0
		`

		execErr := database.Db.QueryRow(query, sessionId).Scan(&username)
		if execErr != nil {
			log.Fatal(execErr)
			fmt.Fprintf(w, "Error: 500 internal server error")
			return
		}

	} else {
		// authentication using form data
		query := `
			SELECT user_name, user_id FROM form_auth_users WHERE user_name = ? AND user_password = ?
		`
		var userId int
		execErr := database.Db.QueryRow(query, username, password).Scan(&username, &userId)

		if execErr != nil {
			log.Fatal(execErr)
			fmt.Fprintf(w, "Error: 500 internal server error")
			return
		}

		query = `
		INSERT INTO form_auth_sessions ( user_id, loginAt, expiry ) VALUES ( ?, ?, ? )
	`
		result, insertErr := database.Db.Exec(query, userId, time.Now().Format("2006-01-02 15:04:05"), time.Now().Add(time.Minute*5).Format("2006-01-02 15:04:05"))

		if insertErr != nil {
			log.Fatal("Error", insertErr)
			fmt.Fprintf(w, "Error: 500 internal server error")
			return
		}

		lastId, idErr := result.LastInsertId()
		log.Printf("%v", lastId)
		if idErr != nil {
			log.Fatal("Error", insertErr)
			fmt.Fprintf(w, "Error: 500 internal server error")
			return
		}
		session.Values["session_id"] = lastId
		session.Save(r, w)
	}

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

func FormAuthSignupHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	query := `
		INSERT INTO form_auth_users ( user_name, user_password ) VALUES ( ?, ? )
	`

	_, err := database.Db.Exec(query, username, password)

	if err != nil {
		log.Fatal("Error 500 internal server error", err)
	}

	fmt.Fprintf(w, "Signup success")

}
