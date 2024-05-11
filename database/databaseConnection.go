package database

import (
	"context"
	"database/sql"
	"fmt"
	"jwt-auth/models"
	"log"

	"github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func Init() {
	db, err := sql.Open("sqlite3", "users.db")
	if err != nil {
		log.Fatal(err)
	}
	DB = db

	_, err = DB.Exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        phone VARCHAR(15) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        user_type TEXT CHECK (user_type IN ('USER', 'ADMIN')) NOT NULL,
        created_at TIMESTAMP ,
        updated_at TIMESTAMP 
    )
`)

	if err != nil {
		log.Fatal(err)
	}
}

func InsertUser(ctx context.Context, db *sql.DB, user *models.User) error {
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO users (first_name, last_name, phone, email, password_hash, user_type,created_at,updated_at)
		VALUES (?, ?, ?, ?, ?, ?,?,?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, user.First_name, user.Last_name, user.Phone, user.Email, user.Password, user.User_type,user.Created_at, user.Updated_at)
	if err != nil {
		if err==context.DeadlineExceeded {
			return fmt.Errorf("something went wrong try again later...")
		} else if isDuplicateKeyError(err) {
			return fmt.Errorf("Email or phone already exist")
		} else {
			return fmt.Errorf("Email or phone already exist")
		}
	}
	return nil
}

func isDuplicateKeyError(err error) bool {
	pqErr, ok := err.(*pq.Error)
	return ok && pqErr.Code == "23505" // PostgreSQL error code for unique violation
}

