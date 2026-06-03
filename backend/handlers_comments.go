package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// =====================================================================
// VULN #13 — Stored XSS (CWE-79).
// Comment body is stored verbatim and rendered raw on the frontend
// (Comments.jsx uses dangerouslySetInnerHTML). Try posting:
//   {"post_id":1,"body":"<img src=x onerror=alert(document.cookie)>"}
// =====================================================================
func CreateComment(c *gin.Context) {
	var body struct {
		PostID int    `json:"post_id"`
		Author string `json:"author"`
		Body   string `json:"body"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Author == "" {
		body.Author = "anonymous"
	}
	_, err := DB.Exec(
		`INSERT INTO comments (post_id, user_id, author, body) VALUES ($1,$2,$3,$4)`,
		body.PostID, c.GetInt("user_id"), body.Author, body.Body,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// =====================================================================
// VULN #14 — Second SQL Injection on /api/comments/:postId (CWE-89).
// Path parameter concatenated into ORDER BY. Tools that only test the
// most obvious POST bodies often miss URL-path SQLi.
//   GET /api/comments/1%20UNION%20SELECT%20...
// =====================================================================
func ListComments(c *gin.Context) {
	postID := c.Param("postId")
	order := c.DefaultQuery("order", "id ASC")
	q := fmt.Sprintf(
		"SELECT id, post_id, user_id, author, body FROM comments WHERE post_id = %s ORDER BY %s",
		postID, order, // both injectable
	)
	rows, err := DB.Query(q)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "query": q})
		return
	}
	defer rows.Close()

	out := []Comment{}
	for rows.Next() {
		var co Comment
		if err := rows.Scan(&co.ID, &co.PostID, &co.UserID, &co.Author, &co.Body); err != nil {
			continue
		}
		out = append(out, co)
	}
	// Help the frontend XSS demo: pass raw bodies through unescaped.
	c.JSON(http.StatusOK, out)
}

// helper used elsewhere
func toInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
