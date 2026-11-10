package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) (*Server, *http.Cookie) {
	t.Helper()
	cfg := &Config{
		PublicURL:     "https://u2d.example.com",
		StateDir:      t.TempDir(),
		StaleAge:      48 * time.Hour,
		SessionSecret: "test-secret",
	}
	store, err := OpenStore(filepath.Join(cfg.StateDir, "hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, store)
	tok, _ := sign(cfg.SessionSecret, sessionData{Sub: "u", Name: "Denis", Expires: time.Now().Add(time.Hour).Unix()})
	return s, &http.Cookie{Name: sessionCookie, Value: tok}
}

type req struct {
	method, url, body string
	cookie            *http.Cookie
	header            map[string]string
}

func do(t *testing.T, h http.Handler, r req) *httptest.ResponseRecorder {
	t.Helper()
	hr := httptest.NewRequest(r.method, r.url, strings.NewReader(r.body))
	if r.method == "POST" && !strings.HasPrefix(r.url, "/api/") {
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		hr.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	if r.cookie != nil {
		hr.AddCookie(r.cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, hr)
	return w
}

var tokenRe = regexp.MustCompile(`u2d_[0-9a-f]{64}`)

func TestPagesNeedSession(t *testing.T) {
	s, _ := testServer(t)
	h := s.Routes()
	if w := do(t, h, req{method: "GET", url: "/"}); w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "/auth/login") {
		t.Fatalf("dashboard without session: %d", w.Code)
	}
	if w := do(t, h, req{method: "POST", url: "/hosts", body: "name=x"}); w.Code != 401 {
		t.Fatalf("add without session: %d", w.Code)
	}
	// A forged or expired cookie is no session
	bad, _ := sign("other-secret", sessionData{Sub: "u", Expires: time.Now().Add(time.Hour).Unix()})
	if w := do(t, h, req{method: "GET", url: "/", cookie: &http.Cookie{Name: sessionCookie, Value: bad}}); w.Code != 302 {
		t.Fatalf("forged session: %d", w.Code)
	}
	old, _ := sign("test-secret", sessionData{Sub: "u", Expires: time.Now().Add(-time.Minute).Unix()})
	if w := do(t, h, req{method: "GET", url: "/", cookie: &http.Cookie{Name: sessionCookie, Value: old}}); w.Code != 302 {
		t.Fatalf("expired session: %d", w.Code)
	}
	if w := do(t, h, req{method: "GET", url: "/static/style.css"}); w.Code != 200 {
		t.Fatalf("stylesheet: %d", w.Code)
	}
}

func TestFlow(t *testing.T) {
	s, c := testServer(t)
	h := s.Routes()

	// Cross-site form posts are refused even with a session
	w := do(t, h, req{method: "POST", url: "/hosts", body: "name=evil", cookie: c, header: map[string]string{"Sec-Fetch-Site": "cross-site"}})
	if w.Code != 403 {
		t.Fatalf("cross-site add: %d", w.Code)
	}

	w = do(t, h, req{method: "POST", url: "/hosts", body: "name=pve1", cookie: c})
	token := tokenRe.FindString(w.Body.String())
	if w.Code != 200 || token == "" {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("csp: %q", csp)
	}
	if w := do(t, h, req{method: "POST", url: "/hosts", body: "name=" + url.QueryEscape("<script>"), cookie: c}); w.Code != 400 || !strings.Contains(w.Body.String(), "a host name has") {
		t.Fatalf("bad name: %d", w.Code)
	}

	report := `{"agent":"t","hostname":"web-01","machine":"lxc","os":"Debian <b>13</b>","manager":"apt","rebootRequired":false,
		"updates":[{"name":"libssl3","current":"1","available":"2","security":true},{"name":"curl","available":"8"}],
		"failedUnits":[{"unit":"backup.service","description":"Nightly backup"}],
		"futureField":true}`
	if w := do(t, h, req{method: "POST", url: "/api/report", body: report}); w.Code != 401 {
		t.Fatalf("report without token: %d", w.Code)
	}
	if w := do(t, h, req{method: "POST", url: "/api/report", body: report, header: map[string]string{"Authorization": "Bearer u2d_nope"}}); w.Code != 401 {
		t.Fatalf("report with a wrong token: %d", w.Code)
	}
	auth := map[string]string{"Authorization": "Bearer " + token}
	if w := do(t, h, req{method: "POST", url: "/api/report", body: `{"updates":"nope"}`, header: auth}); w.Code != 400 {
		t.Fatalf("malformed report: %d", w.Code)
	}
	if w := do(t, h, req{method: "POST", url: "/api/report", body: report, header: auth}); w.Code != 204 {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}

	w = do(t, h, req{method: "GET", url: "/", cookie: c})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "1 security update") || !strings.Contains(body, "1 failed service") || !strings.Contains(body, "Needs attention") {
		t.Fatalf("dashboard: %d %s", w.Code, body)
	}
	if strings.Contains(body, "<b>13</b>") || !strings.Contains(body, "Debian &lt;b&gt;13&lt;/b&gt;") {
		t.Fatal("report values must be escaped")
	}
	if !strings.Contains(body, "web-01") || !strings.Contains(body, "<td>LXC</td>") {
		t.Fatalf("dashboard should show the hostname and type: %s", body)
	}
	if !strings.Contains(do(t, h, req{method: "GET", url: "/?machine=lxc", cookie: c}).Body.String(), "/hosts/pve1") ||
		strings.Contains(do(t, h, req{method: "GET", url: "/?machine=vm", cookie: c}).Body.String(), "/hosts/pve1") {
		t.Fatal("type filter")
	}

	w = do(t, h, req{method: "GET", url: "/hosts/pve1", cookie: c})
	page := w.Body.String()
	if w.Code != 200 || strings.Index(page, "libssl3") > strings.Index(page, "curl") {
		t.Fatalf("host page should list security updates first: %d", w.Code)
	}
	if !strings.Contains(page, "backup.service") {
		t.Fatalf("host page should show failed services: %s", page)
	}

	// Acknowledging the failed service from the page quiets it
	if w := do(t, h, req{method: "POST", url: "/hosts/pve1/units", body: "unit=%2Fbackup.service&action=ack", cookie: c}); w.Code != 303 {
		t.Fatalf("ack: %d %s", w.Code, w.Body)
	}
	w = do(t, h, req{method: "GET", url: "/", cookie: c})
	if strings.Contains(w.Body.String(), "failed service") {
		t.Fatal("acknowledged service still counted")
	}
	if !strings.Contains(do(t, h, req{method: "GET", url: "/hosts/pve1", cookie: c}).Body.String(), "acknowledged until it recovers") {
		t.Fatal("acknowledgement not shown")
	}

	// Global patterns from the settings page
	if w := do(t, h, req{method: "POST", url: "/settings", body: "ignoreUnits=" + url.QueryEscape("[bad"), cookie: c}); w.Code != 400 || !strings.Contains(w.Body.String(), "not a valid pattern") {
		t.Fatalf("bad pattern: %d", w.Code)
	}
	if w := do(t, h, req{method: "POST", url: "/settings", body: "ignoreUnits-vm=" + url.QueryEscape("backup.*"), cookie: c}); w.Code != 303 {
		t.Fatalf("settings: %d", w.Code)
	}
	if strings.Contains(do(t, h, req{method: "GET", url: "/settings", cookie: c}).Body.String(), "pve1: backup.service") {
		t.Fatal("a VM pattern ignored a unit in an LXC container")
	}
	if w := do(t, h, req{method: "POST", url: "/settings", body: "ignoreUnits-lxc=" + url.QueryEscape("backup.*\r\nfoo.service"), cookie: c}); w.Code != 303 {
		t.Fatalf("settings: %d", w.Code)
	}
	w = do(t, h, req{method: "GET", url: "/settings", cookie: c})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "pve1: backup.service") {
		t.Fatalf("settings page should show what a pattern ignores: %s", w.Body)
	}

	// Rotating the token locks the old one out
	w = do(t, h, req{method: "POST", url: "/hosts/pve1/token", cookie: c})
	newToken := tokenRe.FindString(w.Body.String())
	if newToken == "" || newToken == token {
		t.Fatal("no new token")
	}
	if w := do(t, h, req{method: "POST", url: "/api/report", body: report, header: auth}); w.Code != 401 {
		t.Fatalf("old token after rotation: %d", w.Code)
	}

	// Removing needs the name typed in
	do(t, h, req{method: "POST", url: "/hosts/pve1/delete", body: "confirm=nope", cookie: c})
	if _, ok := s.store.Get("pve1"); !ok {
		t.Fatal("deleted without confirmation")
	}
	do(t, h, req{method: "POST", url: "/hosts/pve1/delete", body: "confirm=pve1", cookie: c})
	if _, ok := s.store.Get("pve1"); ok {
		t.Fatal("not deleted")
	}
}

func TestEmptyDashboardRenders(t *testing.T) {
	s, c := testServer(t)
	s.store.Add("fresh")
	w := do(t, s.Routes(), req{method: "GET", url: "/", cookie: c})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "No report yet") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = do(t, s.Routes(), req{method: "GET", url: "/hosts/fresh", cookie: c})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "has not reported yet") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestAuthHelpers(t *testing.T) {
	for in, want := range map[string]string{"/hosts/x": "/hosts/x", "//evil.com": "/", "https://evil.com": "/", "/\\evil.com": "/", "": "/"} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
	a := &Authenticator{cfg: &Config{AllowedUsers: []string{"denis@example.com"}, AllowedGroups: []string{"admins"}}}
	if !a.allowed(claims{Email: "Denis@example.com"}) || !a.allowed(claims{Groups: []string{"admins"}}) {
		t.Fatal("allowed user or group refused")
	}
	if a.allowed(claims{Sub: "x", Email: "x@example.com", Groups: []string{"users"}}) {
		t.Fatal("stranger allowed")
	}
}

func TestAgentToServer(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Routes())
	defer srv.Close()
	token, _ := s.store.Add("box")
	target, err := reportURL(srv.URL) // http://127.0.0.1:…
	if err != nil {
		t.Fatal(err)
	}
	rep := &Report{Hostname: "box", Manager: "apt", Updates: []Update{{Name: "a", Available: "2", Security: true}}}
	if err := send(t.Context(), target, token, rep); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.store.Get("box"); h.Report == nil || h.Report.SecurityCount() != 1 {
		t.Fatalf("stored: %+v", h)
	}
	if err := send(t.Context(), target, "u2d_wrong", rep); !errors.Is(err, errRejected) {
		t.Fatalf("wrong token: %v", err)
	}
}
