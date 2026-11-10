package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "-x", "a/b", "with space", "../x"} {
		if _, err := s.Add(bad); err == nil {
			t.Errorf("accepted host name %q", bad)
		}
	}
	tok, err := s.Add("pve1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("pve1"); err == nil {
		t.Fatal("duplicate host")
	}
	if name, ok := s.Authenticate(tok); !ok || name != "pve1" {
		t.Fatal("token not accepted")
	}
	if _, ok := s.Authenticate(""); ok {
		t.Fatal("empty token accepted")
	}
	if err := s.SaveReport("pve1", &Report{Updates: []Update{{Name: "x", Available: "2"}}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Everything survives a restart, except the plain token
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := s2.Get("pve1")
	if !ok || h.Report == nil || len(h.Report.Updates) != 1 || h.TokenHash == tok {
		t.Fatalf("reloaded: %+v", h)
	}
	if _, ok := s2.Authenticate(tok); !ok {
		t.Fatal("token not accepted after reload")
	}

	tok2, err := s2.Rotate("pve1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Authenticate(tok); ok {
		t.Fatal("old token still works after rotation")
	}
	if _, ok := s2.Authenticate(tok2); !ok {
		t.Fatal("new token rejected")
	}
	if err := s2.Delete("pve1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Authenticate(tok2); ok {
		t.Fatal("token of a deleted host still works")
	}
}

func TestStatus(t *testing.T) {
	now := time.Now()
	stale := Policy{StaleAge: 48 * time.Hour}
	h := Host{Name: "a"}
	if h.Status(stale, now) != StatusNever {
		t.Fatal("never reported")
	}
	h.Received = now.Add(-time.Hour)
	h.Report = &Report{}
	if h.Status(stale, now) != StatusOK {
		t.Fatal("ok")
	}
	h.Report.Updates = []Update{{Name: "a"}}
	if h.Status(stale, now) != StatusUpdates {
		t.Fatal("updates")
	}
	h.Report.Updates[0].Security = true
	if h.Status(stale, now) != StatusAttention {
		t.Fatal("security")
	}
	h.Report = &Report{RebootRequired: true}
	if h.Status(stale, now) != StatusAttention {
		t.Fatal("reboot")
	}
	h.Report = &Report{}
	h.Received = now.Add(-3 * 24 * time.Hour)
	if r := h.Reasons(stale, now); len(r) != 1 || r[0] != "no report for 3 days" {
		t.Fatalf("stale: %v", r)
	}
}

func TestSanitize(t *testing.T) {
	r := &Report{OS: string(make([]byte, 1000)) + "\xff", Updates: make([]Update, maxUpdates+1)}
	if r.sanitize() == nil {
		t.Fatal("too many updates accepted")
	}
	r.Updates = nil
	r.OS = "äöü" + string(make([]byte, 1000))
	r.sanitize()
	if len(r.OS) > maxFieldLen+len("…") {
		t.Fatalf("not clipped: %d", len(r.OS))
	}
}

func TestQuietUnits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.json")
	s, _ := OpenStore(path)
	s.Add("box")
	now := time.Now()
	backup := FailedUnit{Unit: "backup.service"}
	worker := FailedUnit{Unit: "worker.service", User: "quadlets"}
	modules := FailedUnit{Unit: "systemd-modules-load.service"}
	s.SaveReport("box", &Report{Machine: "lxc", FailedUnits: []FailedUnit{backup, worker, modules}}, now)
	count := func() int {
		h, _ := s.Get("box")
		return h.FailedCount(Policy{IgnoreUnits: s.IgnorePatterns()})
	}
	if count() != 3 {
		t.Fatal("all count at first")
	}

	// A pattern for VMs leaves this LXC container alone; one for LXC applies
	if err := s.SetIgnorePatterns(map[string][]string{"vm": {"systemd-modules-*"}}); err != nil {
		t.Fatal(err)
	}
	if count() != 3 {
		t.Fatal("a VM pattern applied to an LXC container")
	}
	if err := s.SetIgnorePatterns(map[string][]string{"lxc": {"systemd-modules-*", "", "systemd-modules-*"}}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string][]string{{"": {"[unclosed"}}, {"": {"a/b"}}, {"docker": {"x"}}} {
		if s.SetIgnorePatterns(bad) == nil {
			t.Fatalf("bad patterns accepted: %v", bad)
		}
	}
	if p := s.IgnorePatterns(); len(p["lxc"]) != 1 || len(p["vm"]) != 0 || count() != 2 {
		t.Fatalf("pattern: %v %d", p, count())
	}

	if err := s.SetUnit("box", "quadlets/worker.service", "ignore"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUnit("box", "/backup.service", "ack"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"backup.service", "/", "/a/b", "/a b", "x/"} {
		if s.SetUnit("box", bad, "ack") == nil {
			t.Errorf("accepted unit key %q", bad)
		}
	}
	if count() != 0 {
		t.Fatalf("ignored and acknowledged still count: %d", count())
	}

	// Still failing: the acknowledgement holds
	s.SaveReport("box", &Report{FailedUnits: []FailedUnit{backup, worker}}, now)
	if count() != 0 {
		t.Fatal("acknowledgement dropped while still failing")
	}
	// Recovered, then failing again: it counts again; the ignore stays
	s.SaveReport("box", &Report{FailedUnits: []FailedUnit{worker}}, now)
	s.SaveReport("box", &Report{FailedUnits: []FailedUnit{backup, worker}}, now)
	if count() != 1 {
		t.Fatalf("a new failure after recovery must count: %d", count())
	}

	// Everything survives a restart
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := s2.Get("box")
	if len(s2.IgnorePatterns()["lxc"]) != 1 || len(h.IgnoredUnits) != 1 {
		t.Fatalf("reloaded: %v %v", s2.IgnorePatterns(), h.IgnoredUnits)
	}
}

func TestLegacyStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.json")
	os.WriteFile(path, []byte(`[{"name":"old","tokenHash":"x"}]`), 0o600)
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("old"); !ok {
		t.Fatal("hosts of the first file format not loaded")
	}
}
