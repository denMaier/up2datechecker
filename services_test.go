package main

import (
	"testing"
	"time"
)

func TestParseFailedUnits(t *testing.T) {
	out := "● nfs-mount.service loaded failed failed Mount the NAS share\nbackup.timer loaded failed failed\n" +
		"9ce283cb4d6347116913fe83a3a3408bbb7ba204fbeb94f7733e6238ca367dfc-931003f3f5f8da7.service loaded failed failed [systemd-run] /usr/bin/podman healthcheck run 9ce2\n\n"
	got := parseFailedUnits([]byte(out))
	if len(got) != 2 || got[0] != (FailedUnit{Unit: "nfs-mount.service", Description: "Mount the NAS share"}) || got[1].Unit != "backup.timer" {
		t.Fatalf("%+v", got)
	}
}

func TestFailedServicesNeedAttention(t *testing.T) {
	now := time.Now()
	h := Host{Received: now, Report: &Report{FailedUnits: []FailedUnit{{Unit: "worker.service", User: "quadlets"}}}}
	if h.Status(Policy{StaleAge: time.Hour}, now) != StatusAttention || h.Reasons(Policy{StaleAge: time.Hour}, now)[0] != "1 failed service" {
		t.Fatalf("%v", h.Reasons(Policy{StaleAge: time.Hour}, now))
	}
}
