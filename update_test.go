package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewestRelease(t *testing.T) {
	tags := []string{"v1.9.0", "v2.0.1", "v1.10.2", "v1.10.3-rc1", "nightly", "v0.9.0"}
	cur, _ := parseVersion("v1.2.0")
	if got := newestRelease(tags, cur, false); got != "v2.0.1" {
		t.Fatalf("any: %s", got)
	}
	if got := newestRelease(tags, cur, true); got != "v1.10.2" {
		t.Fatalf("same major: %s", got)
	}
	cur, _ = parseVersion("v2.0.1")
	if got := newestRelease(tags, cur, false); got != "" {
		t.Fatalf("current is newest: %s", got)
	}
}

func TestUpdate(t *testing.T) {
	asset := "up2date_linux_" + runtime.GOARCH
	// A stand-in for the release binary: it only has to answer "version"
	binary := []byte("#!/bin/sh\necho v1.3.0\n")
	sum := sha256.Sum256(binary)
	sums := hex.EncodeToString(sum[:]) + "  " + asset + "\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases":
			fmt.Fprint(w, `[{"tag_name":"v2.0.0"},{"tag_name":"v1.3.0"},{"tag_name":"v1.4.0","draft":true}]`)
		case "/download/v1.3.0/SHA256SUMS":
			fmt.Fprint(w, sums)
		case "/download/v1.3.0/" + asset:
			w.Write(binary)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	releasesAPI, releaseDownload = srv.URL+"/releases", srv.URL+"/download"

	exe := filepath.Join(t.TempDir(), "up2date")
	os.WriteFile(exe, []byte("old"), 0o755)
	ctx := context.Background()

	if _, err := update(ctx, exe, "dev", true); err == nil {
		t.Fatal("a dev build has nothing to compare with")
	}
	// A tampered checksum list leaves the binary alone
	good := sums
	sums = strings.Repeat("0", 64) + "  " + asset + "\n"
	if _, err := update(ctx, exe, "v1.2.0", true); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatal("binary replaced despite a bad checksum")
	}
	sums = good

	tag, err := update(ctx, exe, "v1.2.0", true)
	if err != nil || tag != "v1.3.0" {
		t.Fatalf("update: %q %v", tag, err)
	}
	if b, _ := os.ReadFile(exe); string(b) != string(binary) {
		t.Fatal("binary not replaced")
	}
	if tag, err := update(ctx, exe, "v1.3.0", true); err != nil || tag != "" {
		t.Fatalf("already current: %q %v", tag, err)
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".up2date-update-*")); len(matches) != 0 {
		t.Fatalf("temporary files left: %v", matches)
	}
}
