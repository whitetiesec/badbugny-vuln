package main

import "time"

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // "user" or "admin"
	Balance      int       `json:"balance"`
	APIKey       string    `json:"api_key"`
	CreatedAt    time.Time `json:"created_at"`
}

type Comment struct {
	ID        int       `json:"id"`
	PostID    int       `json:"post_id"`
	UserID    int       `json:"user_id"`
	Author    string    `json:"author"`
	Body      string    `json:"body"` // VULN: stored verbatim, no sanitization
	CreatedAt time.Time `json:"created_at"`
}

type FileRecord struct {
	ID         int       `json:"id"`
	OwnerID    int       `json:"owner_id"`
	Filename   string    `json:"filename"`
	Path       string    `json:"path"`
	UploadedAt time.Time `json:"uploaded_at"`
}

type Note struct {
	ID      int    `json:"id"`
	OwnerID int    `json:"owner_id"`
	Title   string `json:"title"`
	Body    string `json:"body"`
}
