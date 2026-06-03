package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
)

// =====================================================================
// VULN #1 — SQL Injection in /api/login (CWE-89).
// Username concatenated directly into the SQL string. Classic example:
//   POST /api/login {"username":"admin' OR '1'='1' -- ","password":"x"}
// Detected by: SAST (data flow), DAST (active payloads), IAST.
// =====================================================================
func Login(c *gin.Context) {
	var body map[string]interface{}
	raw, _ := io.ReadAll(c.Request.Body)
	_ = json.Unmarshal(raw, &body)

	username, _ := body["username"].(string)
	password, _ := body["password"].(string)

	q := fmt.Sprintf(
		"SELECT id, username, email, password_hash, role, balance, api_key FROM users WHERE username = '%s' AND password_hash = '%s' LIMIT 1",
		username, md5hex(password),
	)
	row := DB.QueryRow(q)

	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &u.Balance, &u.APIKey); err != nil {
		// VULN: verbose error includes the raw query (CWE-209 information exposure).
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login failed", "query": q, "detail": err.Error()})
		return
	}

	tok, _ := issueJWT(&u)
	c.JSON(http.StatusOK, gin.H{"token": tok, "user": u})
}

// =====================================================================
// VULN #2 — Mass assignment on /api/register (CWE-915).
// Whatever the client sends in JSON is copied into the user record,
// including "role":"admin". Easy for AI review to spot, hard for
// signature-based DAST.
// =====================================================================
func Register(c *gin.Context) {
	var body map[string]interface{}
	raw, _ := io.ReadAll(c.Request.Body)
	if err := json.Unmarshal(raw, &body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username, _ := body["username"].(string)
	email, _ := body["email"].(string)
	password, _ := body["password"].(string)
	role, _ := body["role"].(string) // VULN: trusted from client
	if role == "" {
		role = "user"
	}
	balance, _ := body["balance"].(float64) // VULN: trusted from client

	// VULN: weak password policy — anything 1+ char accepted.
	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password required"})
		return
	}

	apiKey := "ak_" + username + "_" + password
	_, err := DB.Exec(
		`INSERT INTO users (username, email, password_hash, role, balance, api_key) VALUES ($1,$2,$3,$4,$5,$6)`,
		username, email, md5hex(password), role, int(balance)+1000, apiKey,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "role_assigned": role})
}

// =====================================================================
// VULN #3 — Predictable password reset token (CWE-330 / CWE-340).
// Uses satori/go.uuid v1.2.0 which has a known broken RNG fallback.
// Even if RNG were fine, we also expose the token in the JSON response,
// which an AI reviewer flags but a regex-based scanner usually misses.
// =====================================================================
func ForgotPassword(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
	}
	_ = c.ShouldBindJSON(&body)

	var uid int
	err := DB.QueryRow(`SELECT id FROM users WHERE username=$1`, body.Username).Scan(&uid)
	if err != nil {
		// VULN: user enumeration via differing error messages.
		c.JSON(http.StatusNotFound, gin.H{"error": "no such user: " + body.Username})
		return
	}
	tok := uuid.NewV4().String()
	_, _ = DB.Exec(`INSERT INTO reset_tokens (user_id, token) VALUES ($1,$2)`, uid, tok)
	// VULN: token leaked in response (CWE-200).
	c.JSON(http.StatusOK, gin.H{"reset_token": tok, "instructions": "POST /api/reset-password with token + new_password"})
}

func ResetPassword(c *gin.Context) {
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	_ = c.ShouldBindJSON(&body)

	// VULN: SQL injection via token (second-order channel).
	q := "SELECT user_id FROM reset_tokens WHERE token = '" + body.Token + "'"
	var uid int
	if err := DB.QueryRow(q).Scan(&uid); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "query": q})
		return
	}
	_, _ = DB.Exec(`UPDATE users SET password_hash=$1 WHERE id=$2`, md5hex(body.NewPassword), uid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Profile — used to demonstrate that JWT-based session works.
func Profile(c *gin.Context) {
	uid := c.GetInt("user_id")
	var u User
	err := DB.QueryRow(
		`SELECT id, username, email, role, balance, api_key, created_at FROM users WHERE id=$1`, uid,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Balance, &u.APIKey, &u.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, u)
}

// =====================================================================
// VULN #4 — HTTP Response Header Injection / CRLF (CWE-113).
// /api/ping?msg=hello%0d%0aSet-Cookie:%20pwned=1
// =====================================================================
func Ping(c *gin.Context) {
	msg := c.Query("msg")
	c.Writer.Header().Set("X-Echo", msg) // gin sanitizes some, but raw header set echoes user input
	c.Writer.WriteHeader(http.StatusOK)
	_, _ = c.Writer.WriteString("pong " + strings.ReplaceAll(msg, "<", "<")) // weak attempt
}
