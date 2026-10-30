package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is read once at startup from UP2DATE_* environment variables,
// usually supplied by the systemd unit's EnvironmentFile.
type Config struct {
	Listen    string
	PublicURL string // https://up2date.example.com, used for the OIDC callback

	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	GroupsClaim  string

	// A user may sign in when they match AllowedUsers or belong to one of AllowedGroups
	AllowedUsers  []string // matched against sub, email and preferred_username
	AllowedGroups []string

	StateDir string        // hosts.json and the session secret
	StaleAge time.Duration // a host that has not reported for this long needs attention

	SessionSecret string
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func list(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func LoadConfig() (*Config, error) {
	c := &Config{
		Listen:        env("UP2DATE_LISTEN", "127.0.0.1:8080"),
		PublicURL:     strings.TrimRight(env("UP2DATE_PUBLIC_URL", ""), "/"),
		Issuer:        strings.TrimRight(env("UP2DATE_OIDC_ISSUER", ""), "/"),
		ClientID:      env("UP2DATE_OIDC_CLIENT_ID", ""),
		ClientSecret:  env("UP2DATE_OIDC_CLIENT_SECRET", ""),
		Scopes:        list(env("UP2DATE_OIDC_SCOPES", "openid profile email groups")),
		GroupsClaim:   env("UP2DATE_OIDC_GROUPS_CLAIM", "groups"),
		AllowedUsers:  list(env("UP2DATE_ALLOWED_USERS", "")),
		AllowedGroups: list(env("UP2DATE_ALLOWED_GROUPS", "")),
		// systemd's StateDirectory= sets STATE_DIRECTORY
		StateDir: env("UP2DATE_STATE_DIR", env("STATE_DIRECTORY", "/var/lib/up2date")),
	}
	hours, err := strconv.ParseFloat(env("UP2DATE_STALE_HOURS", "24"), 64)
	if err != nil || hours <= 0 {
		return nil, errors.New("UP2DATE_STALE_HOURS must be a positive number of hours")
	}
	c.StaleAge = time.Duration(hours * float64(time.Hour))

	var missing []string
	for k, v := range map[string]string{
		"UP2DATE_PUBLIC_URL":     c.PublicURL,
		"UP2DATE_OIDC_ISSUER":    c.Issuer,
		"UP2DATE_OIDC_CLIENT_ID": c.ClientID,
	} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required settings: %s", strings.Join(missing, ", "))
	}
	// Fail closed: an OIDC provider alone would let every account it knows in
	if len(c.AllowedUsers) == 0 && len(c.AllowedGroups) == 0 {
		return nil, errors.New("set UP2DATE_ALLOWED_USERS and/or UP2DATE_ALLOWED_GROUPS")
	}

	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return nil, err
	}
	secret, err := loadSecret(filepath.Join(c.StateDir, "session.key"))
	if err != nil {
		return nil, err
	}
	c.SessionSecret = secret
	return c, nil
}

// loadSecret keeps sessions valid across restarts without asking for a secret
func loadSecret(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	s := randomHex(32)
	return s, os.WriteFile(path, []byte(s), 0o600)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	rand.Read(buf) // never fails since Go 1.24; it crashes the program instead

	return hex.EncodeToString(buf)
}
