package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrollmentAuthorizationAndRetry(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(&Config{EnrollmentSecret: "secret"}, store)
	token := "u2d_" + strings.Repeat("a", 64)
	request := func(auth, name, tok string) int {
		b, _ := json.Marshal(map[string]string{"name": name, "token": tok})
		req := httptest.NewRequest(http.MethodPost, "/api/enroll", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+auth)
		w := httptest.NewRecorder()
		server.Routes().ServeHTTP(w, req)
		return w.Code
	}
	if got := request("wrong", "host", token); got != 401 {
		t.Fatalf("bad auth: %d", got)
	}
	if got := request("secret", "host", token); got != 204 {
		t.Fatalf("enroll: %d", got)
	}
	if got := request("secret", "host", token); got != 204 {
		t.Fatalf("retry: %d", got)
	}
	if got := request("secret", "host", "u2d_"+strings.Repeat("b", 64)); got != 409 {
		t.Fatalf("replacement: %d", got)
	}
	if got := request("secret", "other", token); got != 409 {
		t.Fatalf("reused token: %d", got)
	}
	if name, ok := store.Authenticate(token); !ok || name != "host" {
		t.Fatal("token not registered")
	}
}
