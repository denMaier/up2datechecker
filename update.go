package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const repo = "denMaier/up2datechecker"

// Where releases are listed and downloaded from; tests point these elsewhere
var (
	releasesAPI     = "https://api.github.com/repos/" + repo + "/releases?per_page=50"
	releaseDownload = "https://github.com/" + repo + "/releases/download"
)

const maxBinaryBytes = 100 << 20

// runUpdate replaces this binary with a newer release, checked against the release's SHA256SUMS,
// and restarts the dashboard if it runs. When there is nothing newer, or any check fails, it
// leaves everything as it was. It only runs when someone calls it: nothing schedules it.
func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	sameMajor := fs.Bool("same-major", false, "only install releases of the current major version")
	fs.Parse(args)
	if runtime.GOOS != "linux" {
		return errors.New("updates are only published for Linux")
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	tag, err := update(ctx, exe, version, *sameMajor)
	if err != nil {
		return err
	}
	if tag == "" {
		fmt.Printf("up2date %s is the newest release allowed\n", version)
		return nil
	}
	fmt.Printf("updated up2date from %s to %s\n", version, tag)
	// The dashboard keeps running the old binary until it restarts; try-restart leaves a
	// stopped or missing service alone. The agent starts fresh on its next run anyway.
	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.CommandContext(ctx, "systemctl", "try-restart", "up2date.service").CombinedOutput(); err != nil {
			return fmt.Errorf("restarting the dashboard: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// update installs the newest allowed release over exe and returns its tag, or "" when current
// is already the newest
func update(ctx context.Context, exe, current string, sameMajor bool) (string, error) {
	cur, ok := parseVersion(current)
	if !ok {
		return "", fmt.Errorf("this build (%s) is not a release, so it can't tell which release is newer", current)
	}
	tags, err := releaseTags(ctx)
	if err != nil {
		return "", fmt.Errorf("listing releases: %w", err)
	}
	tag := newestRelease(tags, cur, sameMajor)
	if tag == "" {
		return "", nil
	}
	asset := "up2date_linux_" + runtime.GOARCH
	sums, err := fetch(ctx, releaseDownload+"/"+tag+"/SHA256SUMS", 64<<10)
	if err != nil {
		return "", err
	}
	want, ok := checksumFor(sums, asset)
	if !ok {
		return "", fmt.Errorf("%s: no checksum for %s", tag, asset)
	}

	// Written next to exe, so the final rename is atomic and a failure leaves exe untouched
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".up2date-update-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	got, err := download(ctx, releaseDownload+"/"+tag+"/"+asset, tmp)
	if err == nil {
		err = tmp.Chmod(0o755)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if got != want {
		return "", fmt.Errorf("%s: checksum mismatch for %s", tag, asset)
	}
	// The new binary has to run here before it replaces the one that does
	out, err := exec.CommandContext(ctx, tmp.Name(), "version").Output()
	if err != nil || strings.TrimSpace(string(out)) != tag {
		return "", fmt.Errorf("%s: the downloaded binary does not run or reports %q", tag, strings.TrimSpace(string(out)))
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		return "", err
	}
	return tag, nil
}

var versionRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// parseVersion reads a release tag such as v1.2.3; anything else, like a pre-release, is not one
func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return v, false
	}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

func newestRelease(tags []string, cur [3]int, sameMajor bool) string {
	best, bestTag := cur, ""
	for _, t := range tags {
		v, ok := parseVersion(t)
		if !ok || (sameMajor && v[0] != cur[0]) {
			continue
		}
		if v[0] > best[0] || v[0] == best[0] && (v[1] > best[1] || v[1] == best[1] && v[2] > best[2]) {
			best, bestTag = v, t
		}
	}
	return bestTag
}

func releaseTags(ctx context.Context) ([]string, error) {
	b, err := fetch(ctx, releasesAPI, 4<<20)
	if err != nil {
		return nil, err
	}
	var releases []struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(b, &releases); err != nil {
		return nil, err
	}
	var tags []string
	for _, r := range releases {
		if !r.Draft && !r.Prerelease {
			tags = append(tags, r.Tag)
		}
	}
	return tags, nil
}

// checksumFor finds a file's hash in sha256sum output
func checksumFor(sums []byte, name string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		hash, file, ok := strings.Cut(sc.Text(), "  ")
		if ok && strings.TrimPrefix(file, "*") == name && len(hash) == 64 {
			return strings.ToLower(hash), true
		}
	}
	return "", false
}

func get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "up2date/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return resp, nil
}

func fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	resp, err := get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// download writes a file to w and returns its sha256
func download(ctx context.Context, url string, w io.Writer) (string, error) {
	resp, err := get(ctx, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, maxBinaryBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxBinaryBytes {
		return "", errors.New("the download is too large")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
