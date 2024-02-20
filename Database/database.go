package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

var Db *sql.DB

func InitDb() {
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

	Db = db
}
