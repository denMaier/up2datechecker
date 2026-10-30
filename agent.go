package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// runAgent collects this machine's pending updates and sends them to the server. It runs as
// root from a systemd timer, because refreshing the package lists needs root; it only ever
// runs the package manager's read-only queries and opens no port.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "print the report instead of sending it")
	noRefresh := fs.Bool("no-refresh", false, "do not refresh the package lists first")
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	rep := collect(ctx, !*noRefresh)

	if *dryRun {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	target, err := reportURL(os.Getenv("UP2DATE_URL"))
	if err != nil {
		return err
	}
	token, err := agentToken()
	if err != nil {
		return err
	}
	if rep.Error != "" {
		fmt.Fprintln(os.Stderr, "collecting:", rep.Error)
	}
	// A few tries cover a server that is restarting; the next timer run covers the rest
	for attempt := 1; ; attempt++ {
		err = send(ctx, target, token, rep)
		if err == nil || attempt == 3 || errors.Is(err, errRejected) {
			break
		}
		fmt.Fprintf(os.Stderr, "sending failed, retrying: %v\n", err)
		time.Sleep(time.Duration(attempt) * 30 * time.Second)
	}
	if err != nil {
		return err
	}
	fmt.Printf("reported %d updates (%d security), reboot required: %v\n", len(rep.Updates), rep.SecurityCount(), rep.RebootRequired)
	return nil
}

// reportURL insists on https, so the token never crosses the network in the clear
func reportURL(base string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(base), "/"))
	if err != nil || u.Host == "" {
		return "", errors.New("set UP2DATE_URL to the server's address, e.g. https://up2date.example.com")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return "", errors.New("UP2DATE_URL must use https (plain http is only allowed to localhost)")
		}
	}
	return u.String() + "/api/report", nil
}

func agentToken() (string, error) {
	token := strings.TrimSpace(os.Getenv("UP2DATE_TOKEN"))
	if f := os.Getenv("UP2DATE_TOKEN_FILE"); token == "" && f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		return "", errors.New("set UP2DATE_TOKEN (or UP2DATE_TOKEN_FILE) to the host's token")
	}
	return token, nil
}

var errRejected = errors.New("the server rejected the report")

func send(ctx context.Context, target, token string, rep *Report) error {
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	switch {
	case resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("%w: %s %s", errRejected, resp.Status, strings.TrimSpace(string(msg)))
	}
	return fmt.Errorf("%s %s", resp.Status, strings.TrimSpace(string(msg)))
}

/* Collecting */

type manager struct {
	name    string
	bin     string
	refresh []string
	collect func(ctx context.Context, refreshed bool) ([]Update, error)
}

var managers = []manager{
	{name: "apt", bin: "apt-get", refresh: []string{"apt-get", "update", "-qq"}, collect: aptUpdates},
	{name: "dnf", bin: "dnf", refresh: []string{"dnf", "-q", "makecache"}, collect: dnfUpdates},
	{name: "apk", bin: "apk", refresh: []string{"apk", "update", "-q"}, collect: apkUpdates},
	{name: "pacman", bin: "pacman", collect: pacmanUpdates},
}

func collect(ctx context.Context, refresh bool) *Report {
	rep := &Report{Agent: version, Updates: []Update{}}
	rep.Hostname, _ = os.Hostname()
	rep.OS = osName(ctx)
	rep.Kernel = readTrim("/proc/sys/kernel/osrelease")
	rep.BootTime = bootTime()

	var errs []string
	if m := findManager(); m == nil {
		errs = append(errs, "no supported package manager found (apt, dnf, apk, pacman)")
	} else {
		rep.Manager = m.name
		refreshed := false
		if refresh && m.refresh != nil {
			if _, err := run(ctx, m.refresh[0], m.refresh[1:]...); err != nil {
				errs = append(errs, "refreshing the package lists: "+err.Error())
			} else {
				refreshed = true
			}
		}
		updates, err := m.collect(ctx, refreshed)
		if err != nil {
			errs = append(errs, err.Error())
		}
		if updates != nil {
			rep.Updates = updates
		}
		rep.RebootRequired = rebootRequired(ctx, m.name)
	}

	// Failed services of the system and of every account that lingers, which is where
	// rootless Quadlets run: a container that crashed shows up as its failed unit
	units, err := failedUnits(ctx, append([]*account{nil}, lingeringAccounts()...))
	if err != nil {
		errs = append(errs, err.Error())
	}
	rep.FailedUnits = units
	rep.Error = strings.Join(errs, "; ")
	return rep
}

func findManager() *manager {
	for i := range managers {
		if _, err := exec.LookPath(managers[i].bin); err == nil {
			return &managers[i]
		}
	}
	return nil
}

// run executes a command in the C locale and returns its stdout. A failure carries the end
// of stderr, which is where package managers explain themselves.
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, _, err := runCode(ctx, name, args...)
	return out, err
}

func runCode(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	return runAs(ctx, nil, name, args...)
}

// runAs runs a command as an account (nil: as the agent itself)
func runAs(ctx context.Context, acct *account, name string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive")
	if acct != nil {
		acct.apply(cmd)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = "…" + msg[len(msg)-500:]
		}
		return out, exit.ExitCode(), fmt.Errorf("%s: %v: %s", name, err, msg)
	}
	return out, 0, err
}

/* apt: Debian, Ubuntu, Proxmox VE */

// Inst libssl3 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])
var aptInstRe = regexp.MustCompile(`^Inst (\S+)(?: \[([^\]]*)\])? \((\S+)\s*([^\[)]*)`)

func aptUpdates(ctx context.Context, _ bool) ([]Update, error) {
	// A simulation needs no lock and changes nothing. dist-upgrade also shows the updates
	// that bring in new packages, such as new kernels, which plain upgrade holds back.
	out, err := run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
	if err != nil {
		return nil, err
	}
	return parseApt(out), nil
}

func parseApt(out []byte) []Update {
	updates := []Update{}
	for line := range strings.Lines(string(out)) {
		m := aptInstRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		updates = append(updates, Update{
			Name:      m[1],
			Current:   m[2],
			Available: m[3],
			Security:  strings.Contains(strings.ToLower(m[4]), "security"),
		})
	}
	return updates
}

/* dnf: Fedora, RHEL, Alma, Rocky */

func dnfUpdates(ctx context.Context, refreshed bool) ([]Update, error) {
	args := []string{"-q", "check-update"}
	if !refreshed {
		args = append(args, "--cacheonly")
	}
	all, err := dnfCheck(ctx, args...)
	if err != nil {
		return nil, err
	}
	// Advisory data says which ones fix security issues. Without it (no updateinfo in the
	// repositories), the updates are still listed, just not marked.
	sec, err := dnfCheck(ctx, append(args, "--security")...)
	if err == nil {
		names := map[string]bool{}
		for _, u := range sec {
			names[u.Name] = true
		}
		for i := range all {
			all[i].Security = names[all[i].Name]
		}
	}
	installedRPMs(ctx, all)
	return all, nil
}

// installedRPMs fills in the installed versions, which check-update does not show. Of several
// installed versions (kernels), the last one listed wins.
func installedRPMs(ctx context.Context, updates []Update) {
	if len(updates) == 0 {
		return
	}
	args := []string{"-q", "--qf", `%{NAME} %|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n`}
	for _, u := range updates {
		args = append(args, u.Name)
	}
	out, _, _ := runCode(ctx, "rpm", args...) // exits non-zero when one isn't installed
	current := map[string]string{}
	for line := range strings.Lines(string(out)) {
		if f := strings.Fields(line); len(f) == 2 {
			current[f[0]] = f[1]
		}
	}
	for i := range updates {
		updates[i].Current = current[updates[i].Name]
	}
}

// dnfCheck runs check-update, which exits with 100 when there are updates
func dnfCheck(ctx context.Context, args ...string) ([]Update, error) {
	out, code, err := runCode(ctx, "dnf", args...)
	if err != nil && code != 100 {
		return nil, err
	}
	return parseDnf(out), nil
}

// parseDnf reads "name.arch  version  repo" lines. Long names may wrap onto a second line.
func parseDnf(out []byte) []Update {
	updates := []Update{}
	var carry []string
	for line := range strings.Lines(string(out)) {
		f := append(carry, strings.Fields(line)...)
		carry = nil
		if len(f) == 0 {
			continue
		}
		if strings.HasPrefix(line, "Obsoleting") || strings.HasPrefix(line, "Security:") {
			break
		}
		if len(f) < 3 {
			if len(f) == 1 && strings.Contains(f[0], ".") {
				carry = f
			}
			continue
		}
		if len(f) != 3 || !strings.Contains(f[0], ".") {
			continue
		}
		name := f[0][:strings.LastIndex(f[0], ".")]
		updates = append(updates, Update{Name: name, Available: f[1]})
	}
	return updates
}

/* apk: Alpine */

func apkUpdates(ctx context.Context, _ bool) ([]Update, error) {
	out, err := run(ctx, "apk", "version", "-l", "<")
	if err != nil {
		return nil, err
	}
	return parseApk(out), nil
}

// parseApk reads "busybox-1.36.1-r15 < 1.36.1-r16". Alpine versions always end in -rN, so the
// name is everything before the last two dashes.
func parseApk(out []byte) []Update {
	updates := []Update{}
	for line := range strings.Lines(string(out)) {
		f := strings.Fields(line)
		if len(f) != 3 || f[1] != "<" {
			continue
		}
		parts := strings.Split(f[0], "-")
		if len(parts) < 3 {
			continue
		}
		updates = append(updates, Update{
			Name:      strings.Join(parts[:len(parts)-2], "-"),
			Current:   strings.Join(parts[len(parts)-2:], "-"),
			Available: f[2],
		})
	}
	return updates
}

/* pacman: Arch */

// checkupdates (from pacman-contrib) syncs a private copy of the databases, so it always
// sees fresh lists without touching the system's. It exits with 2 when there is nothing.
func pacmanUpdates(ctx context.Context, _ bool) ([]Update, error) {
	if _, err := exec.LookPath("checkupdates"); err != nil {
		return nil, errors.New("checkupdates not found: install pacman-contrib and fakeroot")
	}
	out, code, err := runCode(ctx, "checkupdates")
	if err != nil && code != 2 {
		return nil, err
	}
	return parsePacman(out), nil
}

// parsePacman reads "linux 6.6.1.arch1-1 -> 6.6.2.arch1-1"
func parsePacman(out []byte) []Update {
	updates := []Update{}
	for line := range strings.Lines(string(out)) {
		f := strings.Fields(line)
		if len(f) == 4 && f[2] == "->" {
			updates = append(updates, Update{Name: f[0], Current: f[1], Available: f[3]})
		}
	}
	return updates
}

/* System facts */

func readTrim(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

func osName(ctx context.Context) string {
	name := "Linux"
	if f, err := os.Open("/etc/os-release"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
				name = strings.Trim(v, `"'`)
			}
		}
	}
	// pve-manager/8.2.4/faa83925c9641325 (running kernel: …)
	if _, err := exec.LookPath("pveversion"); err == nil {
		if out, err := run(ctx, "pveversion"); err == nil {
			if _, v, ok := strings.Cut(string(out), "pve-manager/"); ok {
				v, _, _ = strings.Cut(v, "/")
				name += ", Proxmox VE " + v
			}
		}
	}
	return name
}

func bootTime() time.Time {
	b, _ := os.ReadFile("/proc/stat")
	for line := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			if sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(sec, 0).UTC()
			}
		}
	}
	return time.Time{}
}

func rebootRequired(ctx context.Context, mgr string) bool {
	// Written by Debian and Ubuntu packages that need a reboot
	for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	// A container runs its host's kernel: whatever kernel packages it has don't matter
	if inContainer() {
		return false
	}
	if mgr == "dnf" {
		// Exits with 1 and says so when core libraries or the kernel were updated
		out, _, _ := runCode(ctx, "dnf", "-q", "needs-restarting", "-r")
		if strings.Contains(string(out), "Reboot is required") {
			return true
		}
	}
	return newerKernel(readTrim("/proc/sys/kernel/osrelease"), "/usr/lib/modules", "/boot")
}

func inContainer() bool {
	if _, err := os.Stat("/run/systemd/container"); err == nil {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	return strings.Contains(readTrim("/proc/1/environ"), "container=")
}

// newerKernel tells whether an installed kernel is newer than the running one, or the running
// one's modules are gone (Arch and Alpine replace them in place). A kernel counts as installed
// when its image is in /boot or in its modules directory.
func newerKernel(running, modulesDir, bootDir string) bool {
	if running == "" {
		return false
	}
	entries, err := os.ReadDir(modulesDir)
	if err != nil {
		return false
	}
	var installed []string
	for _, e := range entries {
		v := e.Name()
		if !e.IsDir() {
			continue
		}
		if exists(filepath.Join(modulesDir, v, "vmlinuz")) || exists(filepath.Join(bootDir, "vmlinuz-"+v)) {
			installed = append(installed, v)
		}
	}
	if len(installed) == 0 {
		return false
	}
	if !exists(filepath.Join(modulesDir, running)) {
		return true
	}
	for _, v := range installed {
		if compareVersions(v, running) > 0 {
			return true
		}
	}
	return false
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// compareVersions orders version strings by their runs of digits and of other characters,
// so 6.8.12-4-pve sorts after 6.8.9-1-pve
func compareVersions(a, b string) int {
	for a != "" && b != "" {
		ca, ra := versionChunk(a)
		cb, rb := versionChunk(b)
		na, errA := strconv.ParseUint(ca, 10, 64)
		nb, errB := strconv.ParseUint(cb, 10, 64)
		switch {
		case errA == nil && errB == nil:
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
		case ca != cb:
			return strings.Compare(ca, cb)
		}
		a, b = ra, rb
	}
	return strings.Compare(a, b)
}

func versionChunk(s string) (string, string) {
	digit := s[0] >= '0' && s[0] <= '9'
	i := 1
	for i < len(s) && (s[i] >= '0' && s[i] <= '9') == digit {
		i++
	}
	return s[:i], s[i:]
}
