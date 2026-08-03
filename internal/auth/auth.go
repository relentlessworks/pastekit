package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"github.com/relentlessworks/pastekit/internal/config"
	"github.com/relentlessworks/pastekit/internal/model"
	"github.com/relentlessworks/pastekit/internal/store"
)

// Auth handles OTP-based authentication.
type Auth struct {
	cfg   *config.Config
	store *store.Store
}

// New creates a new Auth instance.
func New(cfg *config.Config, s *store.Store) *Auth {
	return &Auth{cfg: cfg, store: s}
}

// RequestOTP generates a 6-digit OTP code and "sends" it via email.
// If no SMTP is configured, the code is logged to stderr.
func (a *Auth) RequestOTP(email string) error {
	// Generate 6-digit code
	code := generateOTPCode()

	req := &model.OTPRequest{
		Email:  email,
		Code:   code,
		Expiry: time.Now().Add(10 * time.Minute),
	}

	if err := a.store.SaveOTP(req); err != nil {
		return fmt.Errorf("failed to save OTP: %w", err)
	}

	// Send email or log to stderr
	if a.cfg.SMTPHost == "" {
		log.Printf("OTP for %s: %s (no SMTP configured, code logged to stderr)", email, code)
		return nil
	}

	return a.sendEmail(email, code)
}

// VerifyOTP validates the OTP code and returns a long-lived token.
func (a *Auth) VerifyOTP(email, code string) (*model.Token, error) {
	req, err := a.store.GetOTP(email)
	if err != nil {
		return nil, fmt.Errorf("no OTP request found for %s | hint: call POST /auth/request with your email first", email)
	}

	if time.Now().After(req.Expiry) {
		a.store.DeleteOTP(email)
		return nil, fmt.Errorf("OTP expired | hint: request a new OTP via POST /auth/request")
	}

	if req.Code != code {
		return nil, fmt.Errorf("invalid OTP code | hint: check the code and try again, or request a new OTP via POST /auth/request")
	}

	// OTP verified, delete it
	a.store.DeleteOTP(email)

	// Generate long-lived token
	token := generateToken(a.cfg.Secret, email)

	t := &model.Token{
		Token:     token,
		Email:     email,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour), // 1 year
	}

	if err := a.store.SaveToken(t); err != nil {
		return nil, fmt.Errorf("failed to save token: %w", err)
	}

	return t, nil
}

// ValidateToken checks if a token is valid and returns the associated token info.
func (a *Auth) ValidateToken(tokenStr string) (*model.Token, error) {
	t, err := a.store.GetToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token | hint: call POST /auth/request with email to get an OTP, then POST /auth/verify to get a bearer token")
	}
	if time.Now().After(t.ExpiresAt) {
		_ = a.store.DeleteToken(tokenStr)
		return nil, fmt.Errorf("token expired | hint: request a new token via POST /auth/request")
	}
	return t, nil
}

// sendEmail sends an OTP code via SMTP.
func (a *Auth) sendEmail(email, code string) error {
	subject := "Your pastekit OTP code"
	body := fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 10 minutes.", code)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		a.cfg.FromEmail, email, subject, body)

	addr := fmt.Sprintf("%s:%s", a.cfg.SMTPHost, a.cfg.SMTPPort)
	var auth smtp.Auth
	if a.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", a.cfg.SMTPUser, a.cfg.SMTPPass, a.cfg.SMTPHost)
	}
	return smtp.SendMail(addr, auth, a.cfg.FromEmail, []string{email}, []byte(msg))
}

// generateOTPCode creates a random 6-digit code.
func generateOTPCode() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	num := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if num < 0 {
		num = -num
	}
	return fmt.Sprintf("%06d", num%1000000)
}

// generateToken creates a long-lived bearer token.
func generateToken(secret, email string) string {
	h := sha256.New()
	h.Write([]byte(secret + email + fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(h.Sum(nil))
}

// ExtractBearer extracts the token from an Authorization header.
func ExtractBearer(header string) string {
	header = strings.TrimSpace(header)
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	return ""
}
