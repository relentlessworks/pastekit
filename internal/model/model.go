package model

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"
)

// Paste represents a text snippet stored in the system.
type Paste struct {
	Handle     string    `json:"handle"`
	Workspace  string    `json:"workspace"`
	Title      string    `json:"title,omitempty"`
	Content    string    `json:"content"`
	Language   string    `json:"language,omitempty"`
	Visibility string    `json:"visibility"` // public, unlisted, private
	TTL        string    `json:"ttl,omitempty"` // duration string like "1h", "24h", "7d"
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Workspace represents a tenant in the system.
type Workspace struct {
	Handle string    `json:"handle"`
	Name   string    `json:"name"`
	Plan   string    `json:"plan"` // free, pro
	CreatedAt time.Time `json:"created_at"`
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID        int       `json:"id"`
	Workspace string    `json:"workspace"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
	Actor     string    `json:"actor"`
	Timestamp time.Time `json:"timestamp"`
}

// Token represents an authentication token.
type Token struct {
	Token       string    `json:"token"`
	Workspace   string    `json:"workspace"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// OTPRequest represents a pending OTP verification.
type OTPRequest struct {
	Email  string    `json:"email"`
	Code   string    `json:"code"`
	Expiry time.Time `json:"expiry"`
}

// generateHandle creates a short, unique handle with the given prefix.
// Format: prefix_5char (e.g. paste_a1b2c)
func generateHandle(prefix string) string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	// Use base32 encoding (lowercase, no padding) for URL-safe handles
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").EncodeToString(b)
	// Trim to 5 chars
	if len(enc) > 5 {
		enc = enc[:5]
	}
	return fmt.Sprintf("%s_%s", prefix, enc)
}

// NewPasteHandle generates a new paste handle.
func NewPasteHandle() string {
	return generateHandle("paste")
}

// NewWorkspaceHandle generates a new workspace handle.
func NewWorkspaceHandle() string {
	return generateHandle("ws")
}

// ParseTTL parses a TTL duration string and returns the expiry time.
// Supported formats: "1h", "24h", "7d", "30d", "365d".
// Empty string means no expiry.
func ParseTTL(ttl string) (*time.Time, error) {
	if ttl == "" {
		return nil, nil
	}
	// Parse duration
	var d time.Duration
	if len(ttl) > 0 {
		last := ttl[len(ttl)-1]
		num := ttl[:len(ttl)-1]
		switch last {
		case 'h':
			var hours int
			_, err := fmt.Sscanf(num, "%d", &hours)
			if err != nil {
				return nil, fmt.Errorf("invalid TTL format: %s | hint: use formats like 1h, 24h, 7d, 30d", ttl)
			}
			d = time.Duration(hours) * time.Hour
		case 'd':
			var days int
			_, err := fmt.Sscanf(num, "%d", &days)
			if err != nil {
				return nil, fmt.Errorf("invalid TTL format: %s | hint: use formats like 1h, 24h, 7d, 30d", ttl)
			}
			d = time.Duration(days) * 24 * time.Hour
		default:
			return nil, fmt.Errorf("invalid TTL format: %s | hint: use formats like 1h, 24h, 7d, 30d", ttl)
		}
	}
	expiry := time.Now().Add(d)
	return &expiry, nil
}

// IsExpired checks if a paste has expired.
func (p *Paste) IsExpired() bool {
	if p.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*p.ExpiresAt)
}
