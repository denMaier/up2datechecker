package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Host is a server that may report, with the last report it sent
type Host struct {
	Name      string    `json:"name"`
	TokenHash string    `json:"tokenHash"` // sha256 of the agent's token; the token itself is never stored
	Created   time.Time `json:"created"`
	Received  time.Time `json:"received,omitzero"` // when the last report arrived, by the server's clock
	Report    *Report   `json:"report,omitempty"`

	// Failed units that don't count, as unitKey: ignored for good, or acknowledged until the
	// unit is no longer failed
	IgnoredUnits []string `json:"ignoredUnits,omitempty"`
	AckedUnits   []string `json:"ackedUnits,omitempty"`
}

// Policy decides what needs attention
type Policy struct {
	StaleAge    time.Duration
	IgnoreUnits map[string][]string // glob patterns of unit names, by machine kind; "" for every host
}

// unitKey identifies a unit on a host: "/name.service" for system units, "account/name.service"
// for user units. Neither part can contain a slash.
func unitKey(u FailedUnit) string {
	return u.User + "/" + u.Unit
}

// Quiet says why a failed unit does not count ("pattern", "ignored", "acknowledged"), or ""
// when it does. For "pattern", the second value is the matching pattern.
func (h *Host) Quiet(u FailedUnit, p Policy) (string, string) {
	pats := p.IgnoreUnits[""]
	if h.Report != nil && h.Report.Machine != "" {
		pats = slices.Concat(pats, p.IgnoreUnits[h.Report.Machine])
	}
	for _, pat := range pats {
		if ok, _ := path.Match(pat, u.Unit); ok {
			return "pattern", pat
		}
	}
	switch k := unitKey(u); {
	case slices.Contains(h.IgnoredUnits, k):
		return "ignored", ""
	case slices.Contains(h.AckedUnits, k):
		return "acknowledged", ""
	}
	return "", ""
}

// FailedCount is the number of failed units that count
func (h *Host) FailedCount(p Policy) int {
	n := 0
	if h.Report != nil {
		for _, u := range h.Report.FailedUnits {
			if q, _ := h.Quiet(u, p); q == "" {
				n++
			}
		}
	}
	return n
}

// Reasons lists why a host needs attention; empty when it does not
func (h *Host) Reasons(p Policy, now time.Time) []string {
	r := h.Report
	if r == nil {
		return nil
	}
	var out []string
	if n := r.SecurityCount(); n > 0 {
		out = append(out, plural(n, "security update"))
	}
	if r.AutoSecurity == AutoSecurityDisabled {
		out = append(out, "APT unattended upgrades are not enabled")
	}
	if r.RebootRequired {
		out = append(out, "reboot required")
	}
	if n := h.FailedCount(p); n > 0 {
		out = append(out, plural(n, "failed service"))
	}
	if age := now.Sub(h.Received); age > p.StaleAge {
		out = append(out, "no report for "+humanDuration(age))
	}
	if r.Error != "" {
		out = append(out, "the agent reported an error")
	}
	return out
}

func (h *Host) Status(p Policy, now time.Time) Status {
	switch {
	case h.Report == nil:
		return StatusNever
	case len(h.Reasons(p, now)) > 0:
		return StatusAttention
	case len(h.Report.Updates) > 0:
		return StatusUpdates
	}
	return StatusOK
}

// unitNameRe accepts unit and account names: no slashes, spaces or control characters
var unitNameRe = regexp.MustCompile(`^[^/\s\x00-\x1f]{1,256}$`)

var hostNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Store keeps all hosts and settings in memory and in one JSON file, rewritten atomically on
// every change
type Store struct {
	path string

	mu          sync.RWMutex
	hosts       map[string]*Host
	byHash      map[string]string   // token hash → host name
	ignoreUnits map[string][]string // see Policy
}

type stateFile struct {
	Hosts       []*Host  `json:"hosts"`
	IgnoreUnits []string `json:"ignoreUnits,omitempty"` // on every host
	// On hosts of one machine kind
	IgnoreUnitsOn map[string][]string `json:"ignoreUnitsOn,omitempty"`
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, hosts: map[string]*Host{}, byHash: map[string]string{}, ignoreUnits: map[string][]string{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var st stateFile
	if b = bytes.TrimSpace(b); len(b) > 0 && b[0] == '[' {
		err = json.Unmarshal(b, &st.Hosts) // the first format: just the hosts
	} else {
		err = json.Unmarshal(b, &st)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.ignoreUnits = map[string][]string{"": st.IgnoreUnits}
	for _, kind := range machineKinds {
		s.ignoreUnits[kind] = st.IgnoreUnitsOn[kind]
	}
	for _, h := range st.Hosts {
		s.hosts[h.Name] = h
		s.byHash[h.TokenHash] = h.Name
	}
	return s, nil
}

// save writes the state file; callers hold the write lock
func (s *Store) save() error {
	hosts := make([]*Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		hosts = append(hosts, h)
	}
	slices.SortFunc(hosts, func(a, b *Host) int { return cmp.Compare(a.Name, b.Name) })
	st := stateFile{Hosts: hosts, IgnoreUnits: s.ignoreUnits[""], IgnoreUnitsOn: map[string][]string{}}
	for _, kind := range machineKinds {
		if pats := s.ignoreUnits[kind]; len(pats) > 0 {
			st.IgnoreUnitsOn[kind] = pats
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".hosts-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newToken() string {
	return "u2d_" + randomHex(32)
}

// Enroll is idempotent for retries using the same token, and never replaces an existing token.
func (s *Store) Enroll(name, token string) error {
	if !hostNameRe.MatchString(name) || !regexp.MustCompile(`^u2d_[a-f0-9]{64}$`).MatchString(token) {
		return errors.New("invalid host name or token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := hashToken(token)
	if h, ok := s.hosts[name]; ok {
		if h.TokenHash == hash {
			return nil
		}
		return errors.New("host already exists")
	}
	if _, ok := s.byHash[hash]; ok {
		return errors.New("token already in use")
	}
	s.hosts[name] = &Host{Name: name, TokenHash: hash, Created: time.Now().UTC()}
	s.byHash[hash] = name
	if err := s.save(); err != nil {
		delete(s.hosts, name)
		delete(s.byHash, hash)
		return err
	}
	return nil
}

// List returns copies of all hosts
func (s *Store) List() []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		out = append(out, *h)
	}
	return out
}

func (s *Store) Get(name string) (Host, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hosts[name]
	if !ok {
		return Host{}, false
	}
	return *h, true
}

// Add creates a host and returns its token, which is shown once and not kept
func (s *Store) Add(name string) (string, error) {
	if !hostNameRe.MatchString(name) {
		return "", errors.New("a host name has 1 to 63 letters, digits, dots, dashes or underscores")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[name]; ok {
		return "", fmt.Errorf("%s already exists", name)
	}
	token := newToken()
	h := &Host{Name: name, TokenHash: hashToken(token), Created: time.Now().UTC()}
	s.hosts[name] = h
	s.byHash[h.TokenHash] = name
	if err := s.save(); err != nil {
		delete(s.hosts, name)
		delete(s.byHash, h.TokenHash)
		return "", err
	}
	return token, nil
}

// Rotate replaces a host's token; the old one stops working at once
func (s *Store) Rotate(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[name]
	if !ok {
		return "", errors.New("no such host")
	}
	old := h.TokenHash
	token := newToken()
	h.TokenHash = hashToken(token)
	delete(s.byHash, old)
	s.byHash[h.TokenHash] = name
	if err := s.save(); err != nil {
		h.TokenHash = old
		delete(s.byHash, hashToken(token))
		s.byHash[old] = name
		return "", err
	}
	return token, nil
}

func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[name]
	if !ok {
		return errors.New("no such host")
	}
	delete(s.hosts, name)
	delete(s.byHash, h.TokenHash)
	if err := s.save(); err != nil {
		s.hosts[name] = h
		s.byHash[h.TokenHash] = name
		return err
	}
	return nil
}

// Authenticate returns the host a token belongs to. Tokens carry 256 bits of randomness, so
// looking up their hash leaks nothing useful through timing.
func (s *Store) Authenticate(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	name, ok := s.byHash[hashToken(token)]
	return name, ok
}

// SaveReport replaces a host's last report
func (s *Store) SaveReport(name string, r *Report, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[name]
	if !ok {
		return errors.New("no such host")
	}
	prevReport, prevReceived, prevAcked := h.Report, h.Received, h.AckedUnits
	h.Report, h.Received = r, now.UTC()
	// An acknowledgement lasts as long as the failure: once the unit is fine, the next
	// failure counts again
	h.AckedUnits = slices.DeleteFunc(slices.Clone(h.AckedUnits), func(k string) bool {
		return !slices.ContainsFunc(r.FailedUnits, func(u FailedUnit) bool { return unitKey(u) == k })
	})
	if err := s.save(); err != nil {
		h.Report, h.Received, h.AckedUnits = prevReport, prevReceived, prevAcked
		return err
	}
	return nil
}

// SetUnit ignores or acknowledges a failed unit on a host, or undoes that. action is one of
// ignore, unignore, ack, unack.
func (s *Store) SetUnit(name, key, action string) error {
	user, unit, ok := strings.Cut(key, "/")
	if !ok || !unitNameRe.MatchString(unit) || (user != "" && !unitNameRe.MatchString(user)) {
		return errors.New("invalid unit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[name]
	if !ok {
		return errors.New("no such host")
	}
	without := func(l []string) []string {
		return slices.DeleteFunc(slices.Clone(l), func(k string) bool { return k == key })
	}
	with := func(l []string) []string { return append(without(l), key) }
	prevIgnored, prevAcked := h.IgnoredUnits, h.AckedUnits
	switch action {
	case "ignore":
		h.IgnoredUnits, h.AckedUnits = with(h.IgnoredUnits), without(h.AckedUnits)
	case "unignore":
		h.IgnoredUnits = without(h.IgnoredUnits)
	case "ack":
		h.AckedUnits = with(h.AckedUnits)
	case "unack":
		h.AckedUnits = without(h.AckedUnits)
	default:
		return errors.New("unknown action")
	}
	if err := s.save(); err != nil {
		h.IgnoredUnits, h.AckedUnits = prevIgnored, prevAcked
		return err
	}
	return nil
}

// IgnorePatterns returns the unit name patterns by machine kind; "" for every host
func (s *Store) IgnorePatterns() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string][]string{}
	for kind, pats := range s.ignoreUnits {
		out[kind] = slices.Clone(pats)
	}
	return out
}

// SetIgnorePatterns replaces the unit name patterns, by machine kind ("" for every host). A kind
// that is left out keeps no patterns.
func (s *Store) SetIgnorePatterns(patterns map[string][]string) error {
	clean := map[string][]string{}
	for kind, pats := range patterns {
		if kind != "" && !slices.Contains(machineKinds, kind) {
			return fmt.Errorf("unknown machine kind %q", kind)
		}
		for _, p := range pats {
			if p = strings.TrimSpace(p); p == "" || slices.Contains(clean[kind], p) {
				continue
			}
			if _, err := path.Match(p, ""); err != nil || strings.Contains(p, "/") || len(p) > maxFieldLen {
				return fmt.Errorf("%q is not a valid pattern", p)
			}
			clean[kind] = append(clean[kind], p)
		}
		if len(clean[kind]) > maxItems {
			return errors.New("too many patterns")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.ignoreUnits
	s.ignoreUnits = clean
	if err := s.save(); err != nil {
		s.ignoreUnits = prev
		return err
	}
	return nil
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour")
	}
	return plural(int(d/(24*time.Hour)), "day")
}
