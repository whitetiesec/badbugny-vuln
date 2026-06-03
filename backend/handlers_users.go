package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// =====================================================================
// VULN #5 — IDOR on GET /api/users/:id (CWE-639).
// No check that c.user_id == :id. Any authenticated user can read any
// other user including api_key + role.
// =====================================================================
func GetUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var u User
	err := DB.QueryRow(
		`SELECT id, username, email, role, balance, api_key, created_at FROM users WHERE id=$1`, id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Balance, &u.APIKey, &u.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, u)
}

// =====================================================================
// VULN #6 — Mass assignment + privilege escalation via PUT /api/users/:id.
// Combined with VULN #5 (IDOR): any logged-in user can promote anyone to
// admin or rewrite their balance.
// =====================================================================
func UpdateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	raw, _ := io.ReadAll(c.Request.Body)
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)

	// VULN: build dynamic SQL from arbitrary keys.
	for k, v := range body {
		// Only string-or-number values to keep things simple.
		var val string
		switch t := v.(type) {
		case string:
			val = "'" + t + "'" // VULN: SQLi
		case float64:
			val = fmt.Sprintf("%d", int(t))
		default:
			b, _ := json.Marshal(v)
			val = "'" + string(b) + "'"
		}
		q := fmt.Sprintf("UPDATE users SET %s = %s WHERE id = %d", k, val, id)
		if _, err := DB.Exec(q); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "query": q})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// =====================================================================
// VULN #7 — Business-logic: race condition on /api/transfer (CWE-362).
// Reads balance, then writes new balance. Concurrent requests double-spend.
// Also: no check that amount > 0 — negative amounts steal from the recipient.
// AI reviewers flag the missing positivity check; SAST/DAST usually miss it.
// =====================================================================
func Transfer(c *gin.Context) {
	uid := c.GetInt("user_id")
	var body struct {
		ToUserID int `json:"to_user_id"`
		Amount   int `json:"amount"`
	}
	_ = c.ShouldBindJSON(&body)

	// VULN: missing `if body.Amount <= 0` check.
	var srcBal int
	if err := DB.QueryRow(`SELECT balance FROM users WHERE id=$1`, uid).Scan(&srcBal); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if srcBal < body.Amount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "insufficient funds"})
		return
	}

	// VULN: TOCTOU — non-atomic read/modify/write, no transaction.
	_, _ = DB.Exec(`UPDATE users SET balance = balance - $1 WHERE id=$2`, body.Amount, uid)
	_, _ = DB.Exec(`UPDATE users SET balance = balance + $1 WHERE id=$2`, body.Amount, body.ToUserID)

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// =====================================================================
// VULN #8 — Missing authorization on /api/notes/:id (CWE-862).
// Any authenticated user can read any note (including admin's).
// =====================================================================
func GetNote(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var n Note
	err := DB.QueryRow(`SELECT id, owner_id, title, body FROM notes WHERE id=$1`, id).
		Scan(&n.ID, &n.OwnerID, &n.Title, &n.Body)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, n)
}

// =====================================================================
// VULN #9 — Weak admin gate. Trusts JWT "role" claim without re-checking
// in DB; combined with weak JWT signing it's trivially forged.
// =====================================================================
func AdminListUsers(c *gin.Context) {
	role, _ := c.Get("role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admins only"})
		return
	}
	rows, err := DB.Query(`SELECT id, username, email, role, balance, api_key FROM users`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		_ = rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Balance, &u.APIKey)
		out = append(out, u)
	}
	c.JSON(http.StatusOK, out)
}

// =====================================================================
// VULN #10 — Arbitrary SQL execution via /api/admin/exec-sql (CWE-89, CWE-285).
// "Admin tool" that runs raw SQL. Combined with VULN #9, easy to reach.
// =====================================================================
func AdminExecSQL(c *gin.Context) {
	role, _ := c.Get("role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admins only"})
		return
	}
	var body struct {
		SQL string `json:"sql"`
	}
	_ = c.ShouldBindJSON(&body)
	rows, err := DB.Query(body.SQL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	out := []map[string]interface{}{}
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		_ = rows.Scan(ptrs...)
		row := map[string]interface{}{}
		for i, c := range cols {
			row[c] = vals[i]
		}
		out = append(out, row)
	}
	c.JSON(http.StatusOK, out)
}
