package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	InitDB()

	gin.SetMode(gin.DebugMode) // VULN: debug mode in prod (verbose errors / stack traces)
	r := gin.Default()

	// VULN: CORS misconfiguration (CWE-942).
	// AllowOriginFunc returns true unconditionally → the response
	// reflects whatever Origin the attacker sends and pairs it with
	// AllowCredentials=true, so any malicious site can call the API
	// with the victim's cookies/JWT.
	r.Use(cors.New(cors.Config{
		AllowOriginFunc:  func(origin string) bool { return true },
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"*"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Public
	r.POST("/api/register", Register)
	r.POST("/api/login", Login)
	r.POST("/api/forgot-password", ForgotPassword)
	r.POST("/api/reset-password", ResetPassword)
	r.GET("/api/search", Search)
	r.GET("/api/redirect", OpenRedirect)
	r.GET("/api/fetch", SSRFFetch)
	r.POST("/api/parse-xml", ParseXML)
	r.POST("/api/exec", CommandExec)
	r.GET("/api/render", RenderTemplate)
	r.POST("/api/import", ImportYAML)
	r.GET("/api/debug", Debug)
	r.GET("/api/ping", Ping)
	r.GET("/api/download", Download)
	r.GET("/api/comments/:postId", ListComments)
	r.POST("/api/comments", CreateComment)
	r.GET("/api/files/:id", GetFile)
	r.POST("/api/upload", Upload)

	// "Protected" — but most endpoints are missing or weak authz checks.
	auth := r.Group("/api")
	auth.Use(AuthMiddleware)
	{
		auth.GET("/profile", Profile)
		auth.GET("/users/:id", GetUser)         // VULN: IDOR
		auth.PUT("/users/:id", UpdateUser)      // VULN: mass assignment / IDOR
		auth.POST("/transfer", Transfer)        // VULN: business-logic / race
		auth.GET("/notes/:id", GetNote)         // VULN: missing authz
		auth.GET("/admin/users", AdminListUsers) // VULN: weak admin check
		auth.POST("/admin/exec-sql", AdminExecSQL)
	}

	log.Println("[badbugny] listening on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

// AuthMiddleware — intentionally weak.
//   - VULN: accepts JWTs signed with "none" alg (CVE-2015-9235 family).
//   - VULN: also accepts a hardcoded backdoor token from secrets.go.
//   - VULN: also accepts ?token=... in the query string (info-leak via logs/referrer).
func AuthMiddleware(c *gin.Context) {
	tok := c.GetHeader("Authorization")
	tok = strings.TrimPrefix(tok, "Bearer ")
	if tok == "" {
		tok = c.Query("token") // VULN: token in URL (CWE-598)
	}

	// VULN: backdoor.
	if tok == AdminBackdoorToken {
		c.Set("user_id", 1)
		c.Set("role", "admin")
		c.Set("username", "admin")
		c.Next()
		return
	}

	if tok == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no token"})
		return
	}

	parsed, err := jwt.Parse(tok, func(t *jwt.Token) (interface{}, error) {
		// VULN: does not pin the signing method. jwt.Parse with this
		// callback will accept alg=none if the key returned is nil-ish,
		// and dgrijalva/jwt-go is also vulnerable to alg confusion
		// (CVE-2020-26160 / CVE-2016-10555 family) when callers do not
		// validate alg themselves.
		return []byte(JWTSecret), nil
	})
	if err != nil || parsed == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bad token: " + errStr(err)})
		return
	}
	claims, _ := parsed.Claims.(jwt.MapClaims)
	uid, _ := claims["user_id"].(float64)
	role, _ := claims["role"].(string)
	username, _ := claims["username"].(string)
	c.Set("user_id", int(uid))
	c.Set("role", role)
	c.Set("username", username)
	c.Next()
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func issueJWT(u *User) (string, error) {
	// VULN: HS256 with weak hardcoded secret.
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  u.ID,
		"username": u.Username,
		"role":     u.Role,
		"exp":      time.Now().Add(72 * time.Hour).Unix(),
	})
	return t.SignedString([]byte(JWTSecret))
}
