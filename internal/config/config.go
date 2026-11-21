// Package config loads the ASI_* environment configuration (architecture §10).
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr      string // ASI_HTTP_ADDR
	DatabaseURL   string // ASI_DATABASE_URL
	EncryptionKey string // ASI_ENCRYPTION_KEY (pgcrypto key, see internal/db)

	DojoURL          string // ASI_DOJO_URL; empty disables the Dojo bootstrap
	DojoPublicURL    string // ASI_DOJO_PUBLIC_URL: Dojo as the browser reaches it (links); default ASI_DOJO_URL
	DojoToken        string // ASI_DOJO_TOKEN; empty = obtain with DD_ADMIN_USER/DD_ADMIN_PASSWORD
	DojoAdminUser    string // DD_ADMIN_USER
	DojoAdminPass    string // DD_ADMIN_PASSWORD
	DojoOrganization string // ASI_DOJO_ORGANIZATION

	AdminUsername string // ASI_ADMIN_USERNAME, bootstrap admin on first start
	AdminPassword string // ASI_ADMIN_PASSWORD

	CookieSecure bool          // ASI_COOKIE_SECURE: set the Secure flag on the session cookie (enable behind TLS)
	SessionTTL   time.Duration // ASI_SESSION_TTL
}

func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:         env("ASI_HTTP_ADDR", ":8000"),
		DatabaseURL:      os.Getenv("ASI_DATABASE_URL"),
		EncryptionKey:    os.Getenv("ASI_ENCRYPTION_KEY"),
		DojoURL:          os.Getenv("ASI_DOJO_URL"),
		DojoToken:        os.Getenv("ASI_DOJO_TOKEN"),
		DojoAdminUser:    env("DD_ADMIN_USER", "admin"),
		DojoAdminPass:    os.Getenv("DD_ADMIN_PASSWORD"),
		DojoOrganization: env("ASI_DOJO_ORGANIZATION", "ASI"),
		AdminUsername:    env("ASI_ADMIN_USERNAME", "admin"),
		AdminPassword:    os.Getenv("ASI_ADMIN_PASSWORD"),
	}
	c.DojoPublicURL = env("ASI_DOJO_PUBLIC_URL", c.DojoURL)
	var err error
	if c.CookieSecure, err = strconv.ParseBool(env("ASI_COOKIE_SECURE", "false")); err != nil {
		return nil, fmt.Errorf("ASI_COOKIE_SECURE: %w", err)
	}
	if c.SessionTTL, err = time.ParseDuration(env("ASI_SESSION_TTL", "12h")); err != nil {
		return nil, fmt.Errorf("ASI_SESSION_TTL: %w", err)
	}
	if c.DatabaseURL == "" {
		return nil, errors.New("ASI_DATABASE_URL is required")
	}
	if len(c.EncryptionKey) < 32 {
		return nil, errors.New("ASI_ENCRYPTION_KEY is required (at least 32 characters; scripts/gen-env.sh generates one)")
	}
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
