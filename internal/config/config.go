package config

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
)

// Config holds all configuration for the application.
type Config struct {
	Addr      string // listen address
	DBPath    string // path to JSON storage file
	Secret    string // token signing secret
	SMTPHost  string // SMTP server host
	SMTPPort  string // SMTP server port
	SMTPUser  string // SMTP username
	SMTPPass  string // SMTP password
	FromEmail string // from email address for OTP
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Addr:      ":8470",
		DBPath:    "pastekit.json",
		Secret:    "",
		SMTPHost:  "",
		SMTPPort:  "587",
		SMTPUser:  "",
		SMTPPass:  "",
		FromEmail: "noreply@pastekit.local",
	}
}

// Load reads configuration from defaults < env < flags.
func Load() *Config {
	c := Default()

	// Environment variables
	if v := os.Getenv("PASTEKIT_ADDR"); v != "" {
		c.Addr = v
	}
	if v := os.Getenv("PASTEKIT_DB"); v != "" {
		c.DBPath = v
	}
	if v := os.Getenv("PASTEKIT_SECRET"); v != "" {
		c.Secret = v
	}
	if v := os.Getenv("PASTEKIT_SMTP_HOST"); v != "" {
		c.SMTPHost = v
	}
	if v := os.Getenv("PASTEKIT_SMTP_PORT"); v != "" {
		c.SMTPPort = v
	}
	if v := os.Getenv("PASTEKIT_SMTP_USER"); v != "" {
		c.SMTPUser = v
	}
	if v := os.Getenv("PASTEKIT_SMTP_PASS"); v != "" {
		c.SMTPPass = v
	}
	if v := os.Getenv("PASTEKIT_FROM_EMAIL"); v != "" {
		c.FromEmail = v
	}

	// Flags (override env)
	flag.StringVar(&c.Addr, "addr", c.Addr, "listen address")
	flag.StringVar(&c.DBPath, "db", c.DBPath, "path to JSON storage file")
	flag.StringVar(&c.Secret, "secret", c.Secret, "token signing secret (auto-generated if empty)")
	flag.StringVar(&c.SMTPHost, "smtp-host", c.SMTPHost, "SMTP server host")
	flag.StringVar(&c.SMTPPort, "smtp-port", c.SMTPPort, "SMTP server port")
	flag.StringVar(&c.SMTPUser, "smtp-user", c.SMTPUser, "SMTP username")
	flag.StringVar(&c.SMTPPass, "smtp-pass", c.SMTPPass, "SMTP password")
	flag.StringVar(&c.FromEmail, "from-email", c.FromEmail, "from email address for OTP")
	flag.Parse()

	// Auto-generate secret if not provided
	if c.Secret == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		c.Secret = fmt.Sprintf("%x", b)
	}

	return c
}
