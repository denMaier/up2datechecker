package main

import (
	"strings"
	"testing"
	"time"
)

func TestAPTAutomaticSecurity(t *testing.T) {
	tests := []struct {
		name, config, timer string
		binary              bool
		want                AutoSecurityStatus
	}{
		{"missing package", "", "active", false, AutoSecurityDisabled},
		{"periodic missing", "", "active", true, AutoSecurityDisabled},
		{"disabled periodic", `APT::Periodic::Unattended-Upgrade "0";`, "active", true, AutoSecurityDisabled},
		{"timer inactive", `APT::Periodic::Unattended-Upgrade "1";`, "inactive", true, AutoSecurityDisabled},
		{"unreadable timer", `APT::Periodic::Unattended-Upgrade "1";`, "unknown", true, AutoSecurityUnknown},
		{"custom origins", "APT::Periodic::Unattended-Upgrade \"1\";\nUnattended-Upgrade::Origins-Pattern:: \"origin=Debian\";\n", "active", true, AutoSecurityUnknown},
		{"security origin", "APT::Periodic::Unattended-Upgrade \"1\";\nUnattended-Upgrade::Origins-Pattern:: \"origin=Debian,codename=${distro_codename}-security\";\n", "active", true, AutoSecurityEnabled},
		{"ubuntu allowed origin", "APT::Periodic::Unattended-Upgrade \"1\";\nUnattended-Upgrade::Allowed-Origins:: \"${distro_id}:${distro_codename}-security\";\n", "active", true, AutoSecurityEnabled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aptAutomaticSecurity(tt.config, tt.binary, tt.timer); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestAutomaticSecurityAlertAndLegacyReports(t *testing.T) {
	now := time.Now()
	h := Host{Received: now, Report: &Report{AutoSecurity: AutoSecurityDisabled}}
	if h.Status(Policy{StaleAge: time.Hour}, now) != StatusAttention || !strings.Contains(strings.Join(h.Reasons(Policy{StaleAge: time.Hour}, now), " "), "unattended") {
		t.Fatal("disabled automatic upgrades should need attention")
	}
	for _, status := range []AutoSecurityStatus{"", AutoSecurityUnknown, AutoSecurityEnabled} {
		h.Report.AutoSecurity = status
		if h.Status(Policy{StaleAge: time.Hour}, now) != StatusOK {
			t.Fatalf("status %q caused an alert", status)
		}
	}
}

func TestAutomaticSecurityAppearsOnDashboardAndHost(t *testing.T) {
	s, c := testServer(t)
	token, err := s.store.Add("box")
	if err != nil {
		t.Fatal(err)
	}
	h := s.Routes()
	w := do(t, h, req{method: "POST", url: "/api/report", body: `{"manager":"apt","autoSecurity":"disabled","updates":[]}`, header: map[string]string{"Authorization": "Bearer " + token}})
	if w.Code != 204 {
		t.Fatalf("report: %d", w.Code)
	}
	for _, path := range []string{"/", "/hosts/box"} {
		w = do(t, h, req{method: "GET", url: path, cookie: c})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "unattended upgrades") {
			t.Fatalf("%s missing alert: %d %s", path, w.Code, w.Body.String())
		}
	}
}
