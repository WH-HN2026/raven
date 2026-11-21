// Package config loads the RAVEN_* environment configuration (architecture §10).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr      string // RAVEN_HTTP_ADDR
	DatabaseURL   string // RAVEN_DATABASE_URL
	EncryptionKey string // RAVEN_ENCRYPTION_KEY (pgcrypto key, see internal/db)

	DojoURL          string // RAVEN_DOJO_URL; empty disables the Dojo bootstrap
	DojoPublicURL    string // RAVEN_DOJO_PUBLIC_URL: Dojo as the browser reaches it (links); default RAVEN_DOJO_URL
	DojoToken        string // RAVEN_DOJO_TOKEN; empty = obtain with DD_ADMIN_USER/DD_ADMIN_PASSWORD
	DojoAdminUser    string // DD_ADMIN_USER
	DojoAdminPass    string // DD_ADMIN_PASSWORD
	DojoOrganization string // RAVEN_DOJO_ORGANIZATION

	AdminUsername string // RAVEN_ADMIN_USERNAME, bootstrap admin on first start
	AdminPassword string // RAVEN_ADMIN_PASSWORD

	CookieSecure bool          // RAVEN_COOKIE_SECURE: set the Secure flag on the session cookie (enable behind TLS)
	SessionTTL   time.Duration // RAVEN_SESSION_TTL

	MaxWorkers int // RAVEN_MAX_WORKERS: global cap on concurrent scan batch jobs (default 2)

	ZAPURL    string // RAVEN_ZAP_URL; empty disables the ZAP aggressive stage
	ZAPAPIKey string // RAVEN_ZAP_API_KEY; required when RAVEN_ZAP_URL is set
}

func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:         env("RAVEN_HTTP_ADDR", ":8000"),
		DatabaseURL:      os.Getenv("RAVEN_DATABASE_URL"),
		EncryptionKey:    os.Getenv("RAVEN_ENCRYPTION_KEY"),
		DojoURL:          os.Getenv("RAVEN_DOJO_URL"),
		DojoToken:        os.Getenv("RAVEN_DOJO_TOKEN"),
		DojoAdminUser:    env("DD_ADMIN_USER", "admin"),
		DojoAdminPass:    os.Getenv("DD_ADMIN_PASSWORD"),
		DojoOrganization: env("RAVEN_DOJO_ORGANIZATION", "RAVEN"),
		AdminUsername:    env("RAVEN_ADMIN_USERNAME", "admin"),
		AdminPassword:    os.Getenv("RAVEN_ADMIN_PASSWORD"),
		ZAPURL:           strings.TrimRight(strings.TrimSpace(os.Getenv("RAVEN_ZAP_URL")), "/"),
		ZAPAPIKey:        os.Getenv("RAVEN_ZAP_API_KEY"),
	}
	c.DojoPublicURL = env("RAVEN_DOJO_PUBLIC_URL", c.DojoURL)
	var err error
	if c.CookieSecure, err = strconv.ParseBool(env("RAVEN_COOKIE_SECURE", "false")); err != nil {
		return nil, fmt.Errorf("RAVEN_COOKIE_SECURE: %w", err)
	}
	if c.SessionTTL, err = time.ParseDuration(env("RAVEN_SESSION_TTL", "12h")); err != nil {
		return nil, fmt.Errorf("RAVEN_SESSION_TTL: %w", err)
	}
	if c.MaxWorkers, err = strconv.Atoi(env("RAVEN_MAX_WORKERS", "2")); err != nil || c.MaxWorkers < 1 {
		return nil, fmt.Errorf("RAVEN_MAX_WORKERS: must be a positive integer")
	}
	if c.ZAPURL != "" {
		u, err := url.Parse(c.ZAPURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, errors.New("RAVEN_ZAP_URL must be an http(s) URL with a host")
		}
		if c.ZAPAPIKey == "" {
			return nil, errors.New("RAVEN_ZAP_API_KEY is required when RAVEN_ZAP_URL is set")
		}
	}
	if c.DatabaseURL == "" {
		return nil, errors.New("RAVEN_DATABASE_URL is required")
	}
	if len(c.EncryptionKey) < 32 {
		return nil, errors.New("RAVEN_ENCRYPTION_KEY is required (at least 32 characters; scripts/gen-env.sh generates one)")
	}
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
