package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	texttemplate "text/template"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

// =====================================================================
// VULN #15 — Reflected XSS via /api/search?q=... (CWE-79).
// Query echoed into an HTML page using text/template (NOT html/template),
// so it is not auto-escaped. Easy to weaponise:
//   /api/search?q=<script>alert(1)</script>
// SAST flags the choice of `text/template` for HTML; signature DAST
// catches the reflection.
// =====================================================================
func Search(c *gin.Context) {
	q := c.Query("q")

	// Also do a SQL search to mix concerns — and to add a third SQLi sink.
	rows, err := DB.Query(fmt.Sprintf(
		"SELECT id, username FROM users WHERE username LIKE '%%%s%%'", q,
	))
	results := []map[string]interface{}{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var name string
			_ = rows.Scan(&id, &name)
			results = append(results, map[string]interface{}{"id": id, "username": name})
		}
	}

	page := `<html><body>
<h1>Search results for: {{.Q}}</h1>
<p>You searched: {{.Q}}</p>
<ul>{{range .R}}<li>{{.username}} (#{{.id}})</li>{{end}}</ul>
</body></html>`
	// VULN: text/template (no HTML escaping).
	t, _ := texttemplate.New("s").Parse(page)
	c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.Execute(c.Writer, gin.H{"Q": q, "R": results})
}

// =====================================================================
// VULN #16 — Open Redirect on /api/redirect?url=... (CWE-601).
//   /api/redirect?url=https://attacker.example/phish
// =====================================================================
func OpenRedirect(c *gin.Context) {
	target := c.Query("url")
	if target == "" {
		target = "/"
	}
	c.Redirect(http.StatusFound, target)
}

// =====================================================================
// VULN #17 — SSRF on /api/fetch?url=... (CWE-918).
// Fetches arbitrary URLs server-side, including:
//   - http://169.254.169.254/latest/meta-data/  (cloud metadata)
//   - file:// (with some clients)
//   - http://db:5432/ (internal-only services)
// Uses axios on the frontend for the equivalent (still SSRF when the
// backend proxies). Note the use of net/http with no host allowlist.
// =====================================================================
func SSRFFetch(c *gin.Context) {
	target := c.Query("url")
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url required"})
		return
	}
	// VULN: no scheme allowlist, no internal-IP block.
	resp, err := http.Get(target)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

// =====================================================================
// VULN #18 — XXE on /api/parse-xml (CWE-611).
// Go's encoding/xml does not resolve external entities by default, so
// we add a hand-rolled DOCTYPE/&entity expansion to demonstrate XXE
// behavior. Ship a payload like:
//   <!DOCTYPE x [<!ENTITY p SYSTEM "file:///etc/passwd">]><x>&p;</x>
// =====================================================================
func ParseXML(c *gin.Context) {
	raw, _ := io.ReadAll(c.Request.Body)
	body := string(raw)

	// VULN: manual SYSTEM entity resolution that reads any file/URL.
	re := regexp.MustCompile(`<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>`)
	entities := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		name, src := m[1], m[2]
		var data []byte
		if strings.HasPrefix(src, "file://") {
			data, _ = os.ReadFile(strings.TrimPrefix(src, "file://"))
		} else if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
			resp, err := http.Get(src)
			if err == nil {
				data, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
		} else {
			data, _ = os.ReadFile(src)
		}
		entities[name] = string(data)
	}
	expanded := body
	for name, val := range entities {
		expanded = strings.ReplaceAll(expanded, "&"+name+";", val)
	}

	type any_ struct {
		XMLName xml.Name
		Inner   string `xml:",innerxml"`
	}
	var doc any_
	_ = xml.Unmarshal([]byte(expanded), &doc)

	c.JSON(http.StatusOK, gin.H{
		"resolved_entities": entities,
		"inner":             doc.Inner,
	})
}

// =====================================================================
// VULN #19 — Command Injection on /api/exec (CWE-78).
// `host` argument passed straight into `sh -c`.
//   POST /api/exec {"host":"127.0.0.1; cat /etc/passwd"}
// =====================================================================
func CommandExec(c *gin.Context) {
	var body struct {
		Host string `json:"host"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.Host == "" {
		body.Host = "localhost"
	}

	pingCmd := "ping -c 1 " + body.Host
	if runtime.GOOS == "windows" {
		pingCmd = "ping -n 1 " + body.Host
	}
	cmd := exec.Command("sh", "-c", pingCmd) // VULN: shell concatenation
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run()
	c.JSON(http.StatusOK, gin.H{"command": pingCmd, "output": out.String()})
}

// =====================================================================
// VULN #20 — Server-Side Template Injection (CWE-1336) on /api/render.
//   ?template=welcome.tpl&name={{.}}    → benign
//   …but body=`{{.Env}}` reaches OS env via os.Environ wrapper.
// Also reads template file with no sanitization (CWE-22).
// =====================================================================
func RenderTemplate(c *gin.Context) {
	name := c.DefaultQuery("template", "welcome.tpl")
	body, err := loadTemplateFile(name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// VULN: arbitrary template parsed from disk, plus exposing env.
	t, err := texttemplate.New("r").Funcs(texttemplate.FuncMap{
		"env":    os.Getenv,
		"envall": os.Environ, // leaks all env via {{envall}}
		"exec": func(cmd string) string {
			out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
			return string(out)
		},
	}).Parse(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var buf bytes.Buffer
	_ = t.Execute(&buf, gin.H{
		"Name":  c.DefaultQuery("name", "world"),
		"Query": c.Request.URL.Query(),
	})
	c.Data(http.StatusOK, "text/html", buf.Bytes())
}

// =====================================================================
// VULN #21 — Insecure deserialization via /api/import (CWE-502).
// Uses gopkg.in/yaml.v2 v2.2.2 (CVE-2019-11254) and accepts arbitrary
// YAML with !!binary / !!python tags. Even without a gadget chain, the
// vulnerable lib can be DoS'd with a billion-laughs-style payload.
// =====================================================================
func ImportYAML(c *gin.Context) {
	raw, _ := io.ReadAll(c.Request.Body)
	var out map[string]interface{}
	if err := yaml.Unmarshal(raw, &out); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// VULN: client controls keys; mass-assign into users where matching.
	if uname, ok := out["promote_to_admin"].(string); ok {
		_, _ = DB.Exec(`UPDATE users SET role='admin' WHERE username=$1`, uname)
	}
	c.JSON(http.StatusOK, out)
}

// =====================================================================
// VULN #22 — Verbose debug endpoint (CWE-200, CWE-489).
// Returns env, hardcoded secrets, DB DSN, etc.
// =====================================================================
func Debug(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"env":            os.Environ(),
		"jwt_secret":     JWTSecret,
		"aws_access_key": AWSAccessKeyID,
		"aws_secret":     AWSSecretAccessKey,
		"stripe":         StripeSecretKey,
		"github_token":   GitHubToken,
		"slack_webhook":  SlackWebhookURL,
		"db": gin.H{
			"host": DBHost, "user": DBUser, "password": DBPassword, "name": DBName,
		},
		"backdoor_token": AdminBackdoorToken,
	})
}
