package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
)

// =====================================================================
// VULN #11 — Path Traversal on /api/download?file=... (CWE-22).
// `?file=../../etc/passwd` → server reads outside ./uploads.
// =====================================================================
func Download(c *gin.Context) {
	name := c.Query("file")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file required"})
		return
	}
	full := filepath.Join("/app/uploads", name) // VULN: no Clean() / no prefix check
	data, err := os.ReadFile(full)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error(), "tried": full})
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}

// =====================================================================
// VULN #12 — Unrestricted file upload (CWE-434) + path traversal in filename.
// No MIME check, no extension allowlist, filename used verbatim → can
// drop a file like "../../usr/local/bin/foo" or any .html/.svg with XSS.
// =====================================================================
func Upload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	dst := filepath.Join("/app/uploads", file.Filename) // VULN: filename not sanitized
	_ = os.MkdirAll("/app/uploads", 0o777)
	if err := c.SaveUploadedFile(file, dst); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	uid := c.GetInt("user_id") // 0 if not logged in — uploads are public
	_, _ = DB.Exec(
		`INSERT INTO files (owner_id, filename, path) VALUES ($1,$2,$3)`,
		uid, file.Filename, dst,
	)
	c.JSON(http.StatusOK, gin.H{"ok": true, "path": dst, "url": "/api/download?file=" + file.Filename})
}

// GetFile — returns the stored file metadata. Also IDOR-vulnerable
// (no ownership check), reusing #5 in a different route.
func GetFile(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var f FileRecord
	err := DB.QueryRow(`SELECT id, owner_id, filename, path FROM files WHERE id=$1`, id).
		Scan(&f.ID, &f.OwnerID, &f.Filename, &f.Path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	// VULN: returns server filesystem path (CWE-200).
	c.JSON(http.StatusOK, f)
}

// Convenience helper used by /api/render to "load" a template.
func loadTemplateFile(name string) (string, error) {
	// VULN: file path concatenation, no sanitization (CWE-22 again).
	p := "/app/templates/" + name
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("loadTemplate(%s): %w", p, err)
	}
	return string(b), nil
}

// Force a write of a default template at startup so /api/render has
// something to load when no upload has happened yet.
func init() {
	go func() {
		_ = os.MkdirAll("/app/templates", 0o777)
		f, err := os.OpenFile("/app/templates/welcome.tpl", os.O_RDWR|os.O_CREATE, 0o666)
		if err != nil {
			return
		}
		defer f.Close()
		fi, _ := f.Stat()
		if fi.Size() == 0 {
			_, _ = io.WriteString(f, "Welcome, {{.Name}}!")
		}
	}()
}
