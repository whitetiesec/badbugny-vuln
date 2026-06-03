package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func InitDB() {
	host := getenv("DB_HOST", DBHost)
	port := getenv("DB_PORT", fmt.Sprintf("%d", DBPort))
	user := getenv("DB_USER", DBUser)
	pass := getenv("DB_PASSWORD", DBPassword)
	name := getenv("DB_NAME", DBName)

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, pass, name)

	var err error
	for i := 0; i < 30; i++ {
		DB, err = sql.Open("postgres", dsn)
		if err == nil {
			if err = DB.Ping(); err == nil {
				log.Println("[db] connected")
				break
			}
		}
		log.Printf("[db] not ready (%v), retrying...", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("[db] connection failed: %v", err)
	}

	bootstrap()
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func bootstrap() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			balance INTEGER NOT NULL DEFAULT 1000,
			api_key TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS comments (
			id SERIAL PRIMARY KEY,
			post_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			author TEXT NOT NULL,
			body TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS files (
			id SERIAL PRIMARY KEY,
			owner_id INTEGER NOT NULL,
			filename TEXT NOT NULL,
			path TEXT NOT NULL,
			uploaded_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS notes (
			id SERIAL PRIMARY KEY,
			owner_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			body TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS reset_tokens (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			token TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		if _, err := DB.Exec(s); err != nil {
			log.Fatalf("[db] schema: %v", err)
		}
	}

	var n int
	_ = DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	if n == 0 {
		seed()
	}
}

func seed() {
	// VULN: passwords stored as plain MD5 (CWE-916). Seeded users:
	//   admin / admin123    (role=admin)
	//   alice / password1   (role=user)
	//   bob   / hunter2     (role=user)
	users := []struct {
		Username, Email, Pass, Role string
		Balance                     int
	}{
		{"admin", "admin@badbugny.local", "admin123", "admin", 99999},
		{"alice", "alice@badbugny.local", "password1", "user", 1000},
		{"bob", "bob@badbugny.local", "hunter2", "user", 500},
	}
	for _, u := range users {
		_, err := DB.Exec(
			`INSERT INTO users (username, email, password_hash, role, balance, api_key) VALUES ($1,$2,$3,$4,$5,$6)`,
			u.Username, u.Email, md5hex(u.Pass), u.Role, u.Balance, "ak_"+u.Username+"_"+u.Pass,
		)
		if err != nil {
			log.Printf("[seed] %v", err)
		}
	}

	_, _ = DB.Exec(
		`INSERT INTO comments (post_id, user_id, author, body) VALUES (1,1,'admin','Welcome to BadBugny! 🐰🏍️ Rev your engines and drop a comment below.')`,
	)
	_, _ = DB.Exec(
		`INSERT INTO notes (owner_id, title, body) VALUES (1,'Garage master key','Internal API key: sk_live_demo_DO_NOT_LEAK_FROM_NOTES')`,
	)
	log.Println("[db] seeded default users (admin/admin123, alice/password1, bob/hunter2)")
}
