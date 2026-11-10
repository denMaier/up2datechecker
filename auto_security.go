package main

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Automatic security updates cannot be inferred reliably for arbitrary custom jobs.
// An empty status also covers reports from agents that predate this check.
type AutoSecurityStatus string

const (
	AutoSecurityEnabled  AutoSecurityStatus = "enabled"
	AutoSecurityDisabled AutoSecurityStatus = "disabled"
	AutoSecurityUnknown  AutoSecurityStatus = "unknown"
)

var aptPeriodicRE = regexp.MustCompile(`(?m)^APT::Periodic::Unattended-Upgrade\s+"([^"]*)";\s*$`)

func aptAutomaticSecurity(config string, hasBinary bool, timerState string) AutoSecurityStatus {
	if !hasBinary {
		return AutoSecurityDisabled
	}
	match := aptPeriodicRE.FindStringSubmatch(config)
	if len(match) == 0 {
		return AutoSecurityDisabled
	}
	n, err := strconv.Atoi(match[1])
	if err != nil {
		return AutoSecurityUnknown
	}
	if n <= 0 || timerState == "inactive" {
		return AutoSecurityDisabled
	}
	if timerState != "active" {
		return AutoSecurityUnknown
	}
	// APT may use arbitrary origin patterns or a custom scheduler. Only assert that
	// security updates are configured when an effective allowed-origin entry names
	// a security archive; a more general or custom rule remains unknown.
	for _, line := range strings.Split(config, "\n") {
		lower := strings.ToLower(line)
		if (strings.HasPrefix(lower, "unattended-upgrade::origins-pattern::") || strings.HasPrefix(lower, "unattended-upgrade::allowed-origins::")) && strings.Contains(lower, "security") {
			return AutoSecurityEnabled
		}
	}
	return AutoSecurityUnknown
}

func autoSecurity(ctx context.Context, manager string) AutoSecurityStatus {
	if manager != "apt" {
		return AutoSecurityUnknown
	}
	if _, err := exec.LookPath("unattended-upgrade"); err != nil {
		return AutoSecurityDisabled
	}
	config, err := run(ctx, "apt-config", "dump")
	if err != nil {
		return AutoSecurityUnknown
	}
	timer := "unknown"
	if _, err := exec.LookPath("systemctl"); err == nil {
		out, code, err := runCode(ctx, "systemctl", "is-active", "apt-daily-upgrade.timer")
		switch {
		case err == nil && strings.TrimSpace(string(out)) == "active":
			timer = "active"
		case code == 3 || code == 4:
			timer = "inactive"
		}
	}
	return aptAutomaticSecurity(string(config), true, timer)
}
