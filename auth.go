package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "u2d_session"
	flowCookie    = "u2d_oidc"
	sessionTTL    = 12 * time.Hour
	flowTTL       = 10 * time.Minute
)

// Authenticator handles the OIDC login and signed session cookies
type Authenticator struct {
	cfg *Config

	mu       sync.Mutex
	provider *oidc.Provider
}

func (a *Authenticator) getProvider() (*oidc.Provider, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.provider != nil {
		return a.provider, nil
	}
	// go-oidc keeps this context for later JWKS refreshes, so it must outlive the request
	ctx := oidc.ClientContext(context.Background(), &http.Client{Timeout: 10 * time.Second})
	p, err := oidc.NewProvider(ctx, a.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", a.cfg.Issuer, err)
	}
	a.provider = p
	return p, nil
}

func (a *Authenticator) oauthConfig(p *oidc.Provider) *oauth2.Config {
	scopes := []string{oidc.ScopeOpenID}
	for _, sc := range a.cfg.Scopes {
		if sc != oidc.ScopeOpenID {
			scopes = append(scopes, sc)
		}
	}
	return &oauth2.Config{
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  a.cfg.PublicURL + "/auth/callback",
		Scopes:       scopes,
	}
}

/* Signed cookies */

func sign(secret string, payload any) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verify(secret, token string, out any) error {
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return errors.New("malformed token")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return errors.New("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

type sessionData struct {
	Sub     string `json:"sub"`
	Name    string `json:"name"`
	Expires int64  `json:"exp"`
	IDToken string `json:"idt,omitempty"` // kept for RP-initiated logout
}

type flowData struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Next     string `json:"next"`
	Expires  int64  `json:"exp"`
}

func (a *Authenticator) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   strings.HasPrefix(a.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) clearCookie(w http.ResponseWriter, name string) {
	a.setCookie(w, name, "", -time.Second)
}

// Session returns the signed-in user, if any
func (a *Authenticator) Session(r *http.Request) (sessionData, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return sessionData{}, false
	}
	var sess sessionData
	if err := verify(a.cfg.SessionSecret, c.Value, &sess); err != nil {
		return sessionData{}, false
	}
	if time.Now().Unix() > sess.Expires {
		return sessionData{}, false
	}
	return sess, true
}

// safeNext only allows local paths so the login cannot be used as an open redirect
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

func (a *Authenticator) HandleLogin(w http.ResponseWriter, r *http.Request) {
	p, err := a.getProvider()
	if err != nil {
		renderMessage(w, http.StatusBadGateway, err.Error())
		return
	}
	flow := flowData{
		State:    randomHex(16),
		Nonce:    randomHex(16),
		Verifier: oauth2.GenerateVerifier(),
		Next:     safeNext(r.URL.Query().Get("next")),
		Expires:  time.Now().Add(flowTTL).Unix(),
	}
	token, err := sign(a.cfg.SessionSecret, flow)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.setCookie(w, flowCookie, token, flowTTL)
	target := a.oauthConfig(p).AuthCodeURL(flow.State, oidc.Nonce(flow.Nonce), oauth2.S256ChallengeOption(flow.Verifier))
	http.Redirect(w, r, target, http.StatusFound)
}

type claims struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Groups            []string
}

// allowed checks the verified claims against the configured users and groups
func (a *Authenticator) allowed(c claims) bool {
	for _, u := range a.cfg.AllowedUsers {
		if u == c.Sub || (c.Email != "" && strings.EqualFold(u, c.Email)) || (c.PreferredUsername != "" && u == c.PreferredUsername) {
			return true
		}
	}
	for _, g := range a.cfg.AllowedGroups {
		if slices.Contains(c.Groups, g) {
			return true
		}
	}
	return false
}

func (a *Authenticator) HandleCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, msg string) {
		a.clearCookie(w, flowCookie)
		renderMessage(w, status, msg)
	}

	c, err := r.Cookie(flowCookie)
	if err != nil {
		fail(http.StatusBadRequest, "Your sign-in attempt expired. Please try again.")
		return
	}
	var flow flowData
	if err := verify(a.cfg.SessionSecret, c.Value, &flow); err != nil || time.Now().Unix() > flow.Expires {
		fail(http.StatusBadRequest, "Your sign-in attempt expired. Please try again.")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		fail(http.StatusUnauthorized, "The identity provider refused the sign-in: "+e)
		return
	}
	if r.URL.Query().Get("state") != flow.State {
		fail(http.StatusBadRequest, "Sign-in state mismatch. Please try again.")
		return
	}

	p, err := a.getProvider()
	if err != nil {
		fail(http.StatusBadGateway, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := a.oauthConfig(p).Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		fail(http.StatusBadGateway, "Token exchange failed: "+err.Error())
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		fail(http.StatusBadGateway, "The identity provider did not return an ID token.")
		return
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: a.cfg.ClientID}).Verify(ctx, rawID)
	if err != nil {
		fail(http.StatusUnauthorized, "ID token rejected: "+err.Error())
		return
	}
	if idt.Nonce != flow.Nonce {
		fail(http.StatusUnauthorized, "ID token nonce mismatch.")
		return
	}

	var cl claims
	var all map[string]any
	if err := idt.Claims(&cl); err != nil || idt.Claims(&all) != nil {
		fail(http.StatusBadGateway, "Could not read the ID token claims.")
		return
	}
	cl.Groups = stringList(all[a.cfg.GroupsClaim])
	// Some providers only put groups in the userinfo response
	if len(cl.Groups) == 0 {
		if ui, err := p.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
			var uall map[string]any
			if ui.Claims(&uall) == nil {
				cl.Groups = stringList(uall[a.cfg.GroupsClaim])
			}
		}
	}
	if !a.allowed(cl) {
		fail(http.StatusForbidden, "Your account is not allowed to use Up2Date.")
		return
	}

	name := cl.Name
	if name == "" {
		name = firstNonEmpty(cl.PreferredUsername, cl.Email, cl.Sub)
	}
	token, err := sign(a.cfg.SessionSecret, sessionData{
		Sub:     cl.Sub,
		Name:    name,
		Expires: time.Now().Add(sessionTTL).Unix(),
		IDToken: rawID,
	})
	if err != nil {
		fail(http.StatusInternalServerError, err.Error())
		return
	}
	a.clearCookie(w, flowCookie)
	a.setCookie(w, sessionCookie, token, sessionTTL)
	http.Redirect(w, r, flow.Next, http.StatusFound)
}

func (a *Authenticator) HandleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := a.Session(r)
	a.clearCookie(w, sessionCookie)
	// RP-initiated logout when the provider supports it
	if p, err := a.getProvider(); err == nil && sess.IDToken != "" {
		var meta struct {
			EndSession string `json:"end_session_endpoint"`
		}
		if p.Claims(&meta) == nil && meta.EndSession != "" {
			q := url.Values{"id_token_hint": {sess.IDToken}, "post_logout_redirect_uri": {a.cfg.PublicURL + "/"}}
			http.Redirect(w, r, meta.EndSession+"?"+q.Encode(), http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func renderMessage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Up2Date</title>
<link rel="stylesheet" href="/static/style.css"><main class="narrow"><h1>Up2Date</h1><p>%s</p><p><a href="/auth/login">Sign in again</a></p></main>`, html.EscapeString(msg))
}
