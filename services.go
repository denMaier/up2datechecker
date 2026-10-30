package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// account is a user whose systemd user manager the agent asks about failed units
type account struct {
	name     string
	uid, gid uint32
	groups   []uint32
	home     string
}

func (a *account) label() string {
	if a == nil {
		return ""
	}
	return a.name
}

func (a *account) runtimeDir() string {
	return fmt.Sprintf("/run/user/%d", a.uid)
}

// apply makes cmd run as the account, with the environment its systemd expects
func (a *account) apply(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: a.uid, Gid: a.gid, Groups: a.groups}}
	cmd.Dir = a.home
	cmd.Env = []string{
		"LC_ALL=C", "LANG=C",
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
		"HOME=" + a.home,
		"USER=" + a.name,
		"LOGNAME=" + a.name,
		"XDG_RUNTIME_DIR=" + a.runtimeDir(),
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + a.runtimeDir() + "/bus",
	}
}

// lingeringAccounts are the accounts whose user manager runs without a login
func lingeringAccounts() []*account {
	entries, _ := os.ReadDir("/var/lib/systemd/linger")
	var out []*account
	for _, e := range entries {
		u, err := user.Lookup(e.Name())
		if err != nil {
			continue
		}
		uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
		gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
		if err1 != nil || err2 != nil || uid == 0 {
			continue
		}
		a := &account{name: u.Username, uid: uint32(uid), gid: uint32(gid), home: u.HomeDir}
		gids, _ := u.GroupIds()
		for _, g := range gids {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				a.groups = append(a.groups, uint32(n))
			}
		}
		// Only accounts whose user manager is running right now
		if exists(filepath.Join(a.runtimeDir(), "systemd")) {
			out = append(out, a)
		}
	}
	return out
}

/* Failed systemd units */

func failedUnits(ctx context.Context, accounts []*account) ([]FailedUnit, error) {
	if !exists("/run/systemd/system") {
		return nil, nil // not booted with systemd
	}
	out := []FailedUnit{}
	var errs []string
	for _, a := range accounts {
		args := []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager", "--full"}
		if a != nil {
			args = append([]string{"--user"}, args...)
		}
		stdout, _, err := runAs(ctx, a, "systemctl", args...)
		if err != nil {
			errs = append(errs, whose(a)+err.Error())
			continue
		}
		for _, u := range parseFailedUnits(stdout) {
			u.User = a.label()
			out = append(out, u)
		}
	}
	return out, joinErrs("failed units", errs)
}

var podmanHealthUnit = regexp.MustCompile(`^[0-9a-f]{64}-[0-9a-f]+\.(service|timer)$`)

// parseFailedUnits reads "foo.service loaded failed failed Some description"
func parseFailedUnits(out []byte) []FailedUnit {
	var units []FailedUnit
	for line := range strings.Lines(string(out)) {
		f := strings.Fields(strings.TrimLeft(strings.TrimSpace(line), "●* "))
		if len(f) < 4 {
			continue
		}
		// A failing health check of a container leaves a failed transient unit per run, named
		// after the container's ID; the container's own unit is what matters
		if podmanHealthUnit.MatchString(f[0]) {
			continue
		}
		units = append(units, FailedUnit{Unit: f[0], Description: strings.Join(f[4:], " ")})
	}
	return units
}

func whose(a *account) string {
	if a == nil {
		return ""
	}
	return a.name + ": "
}

func joinErrs(what string, errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %s", what, strings.Join(errs, "; "))
}
