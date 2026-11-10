package main

import (
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Report is what an agent sends: the state of one server's packages and services
type Report struct {
	Agent          string             `json:"agent"` // agent version
	Hostname       string             `json:"hostname"`
	OS             string             `json:"os"`
	Kernel         string             `json:"kernel"`
	Machine        string             `json:"machine,omitempty"` // see machineKinds; empty when unknown
	Manager        string             `json:"manager"`           // apt, dnf, apk or pacman
	Updates        []Update           `json:"updates"`
	RebootRequired bool               `json:"rebootRequired"`
	AutoSecurity   AutoSecurityStatus `json:"autoSecurity,omitempty"`
	BootTime       time.Time          `json:"bootTime,omitzero"`
	FailedUnits    []FailedUnit       `json:"failedUnits,omitempty"`
	Error          string             `json:"error,omitempty"` // why collecting failed, partly or entirely
}

// machineKinds are what a host runs as, as far as ignore patterns and the dashboard tell them
// apart. An agent may also report "container" for a container other than LXC (Docker, nspawn).
var machineKinds = []string{"vm", "lxc", "metal"}

func machineLabel(kind string) string {
	switch kind {
	case "vm":
		return "VM"
	case "lxc":
		return "LXC"
	case "metal":
		return "Bare metal"
	case "container":
		return "Container"
	}
	return ""
}

// FailedUnit is a systemd unit in the failed state
type FailedUnit struct {
	Unit        string `json:"unit"`
	User        string `json:"user,omitempty"` // the account of a user unit; empty for system units
	Description string `json:"description,omitempty"`
}

type Update struct {
	Name      string `json:"name"`
	Current   string `json:"current,omitempty"`
	Available string `json:"available"`
	Security  bool   `json:"security,omitempty"`
}

const (
	maxUpdates  = 5000
	maxItems    = 1000 // failed units
	maxFieldLen = 256
	maxErrorLen = 4096
)

// sanitize bounds what an agent may store. The values are only ever shown through
// html/template, which escapes them; this keeps the state file and the pages a sane size.
func (r *Report) sanitize() error {
	if len(r.Updates) > maxUpdates || len(r.FailedUnits) > maxItems {
		return errors.New("too many entries in one report")
	}
	for _, s := range []*string{&r.Agent, &r.Hostname, &r.OS, &r.Kernel, &r.Manager} {
		*s = clip(*s, maxFieldLen)
	}
	r.Error = clip(r.Error, maxErrorLen)
	if r.Machine != "" && r.Machine != "container" && !slices.Contains(machineKinds, r.Machine) {
		r.Machine = ""
	}
	switch r.AutoSecurity {
	case "", AutoSecurityEnabled, AutoSecurityDisabled, AutoSecurityUnknown:
	default:
		r.AutoSecurity = AutoSecurityUnknown
	}
	for i := range r.Updates {
		u := &r.Updates[i]
		u.Name, u.Current, u.Available = clip(u.Name, maxFieldLen), clip(u.Current, maxFieldLen), clip(u.Available, maxFieldLen)
	}
	for i := range r.FailedUnits {
		u := &r.FailedUnits[i]
		u.Unit, u.User, u.Description = clip(u.Unit, maxFieldLen), clip(u.User, maxFieldLen), clip(u.Description, maxFieldLen)
	}
	return nil
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func (r *Report) SecurityCount() int {
	n := 0
	for _, u := range r.Updates {
		if u.Security {
			n++
		}
	}
	return n
}

// Status sums up a host, from most to least urgent
type Status int

const (
	StatusAttention Status = iota // security updates, reboot, failed services, stale or failing agent
	StatusNever                   // added but never reported
	StatusUpdates                 // ordinary updates are waiting
	StatusOK
)

func (s Status) String() string {
	return [...]string{"attention", "never", "updates", "ok"}[s]
}

func (s Status) Label() string {
	return [...]string{"Needs attention", "No report yet", "Updates available", "Up to date"}[s]
}
