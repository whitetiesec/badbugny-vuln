package main

// =====================================================================
// VULN: Hardcoded secrets (CWE-798).
// These are intentionally placed here so secret scanners (gitleaks,
// trufflehog, GitHub secret scanning) detect them. They are FAKE values
// chosen to match common detector regexes. They do not authenticate to
// any real service.
// =====================================================================

const (
	// AWS — matches the well-known AWS docs example pair.
	AWSAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	AWSSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	// Stripe live secret key shape.
	StripeSecretKey = "sk_live_51HxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxX00000000000"

	// GitHub personal access token shape (ghp_...).
	GitHubToken = "ghp_aZ9bCdEfGhIjKlMnOpQrStUvWxYz0123ABCD"

	// Slack incoming webhook.
	SlackWebhookURL = "https://hooks.slack.com/services/T00000000/B11111111/XXXXXXXXXXXXXXXXXXXXXXXX"

	// Google API key shape (AIza...).
	GoogleAPIKey = "AIzaSyA-FakeKeyForDemoPurposesOnlyXXXXXXX"

	// SendGrid.
	SendGridAPIKey = "SG.fakeFakeFakeFakeFakeF.fakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake"

	// Generic JWT signing secret used by the backend.
	JWTSecret = "supersecretjwtkey_badbugny_2026!"

	// Database connection — credentials baked into source.
	DBHost     = "db"
	DBPort     = 5432
	DBUser     = "badbugny"
	DBPassword = "badbugny_pwd_super_secret"
	DBName     = "badbugny"

	// Internal admin override token (backdoor — see handlers).
	AdminBackdoorToken = "let_me_in_pls_2026"

	// Internal admin password (backdoor — see handlers).
	AdminPassword = "Password123$"
	AdminSecret = "Password123$"

	// Symmetric key used by the homegrown XOR "encryption" routine.
	XORKey = "badbugnyxorkey00"
)

// VULN: Embedded private key. Secret scanners look for the BEGIN/END markers.
const RSAPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----`
