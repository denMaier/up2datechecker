package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseApt(t *testing.T) {
	out := `NOTE: This is only a simulation!
Inst libssl3 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])
Inst curl [7.88.1-10+deb12u4] (7.88.1-10+deb12u5 Debian:12.5/stable, Debian:12.5/stable [arm64]) []
Inst linux-image-6.1.0-18-amd64 (6.1.76-1 Debian:12.5/stable [amd64])
Inst openssl [3.0.13-0ubuntu3] (3.0.13-0ubuntu3.1 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Conf libssl3 (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])
`
	got := parseApt([]byte(out))
	want := []Update{
		{Name: "libssl3", Current: "3.0.11-1~deb12u1", Available: "3.0.11-1~deb12u2", Security: true},
		{Name: "curl", Current: "7.88.1-10+deb12u4", Available: "7.88.1-10+deb12u5"},
		{Name: "linux-image-6.1.0-18-amd64", Available: "6.1.76-1"},
		{Name: "openssl", Current: "3.0.13-0ubuntu3", Available: "3.0.13-0ubuntu3.1", Security: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseDnf(t *testing.T) {
	out := `
kernel-core.x86_64                    6.8.9-300.fc40          updates
python3-a-really-long-package-name-that-wraps.noarch
                                      1.2.3-1.fc40            updates
openssl-libs.x86_64                   1:3.2.1-6.fc40          updates
Obsoleting Packages
grub2-tools.x86_64                    1:2.06-120.fc40         updates
`
	got := parseDnf([]byte(out))
	want := []Update{
		{Name: "kernel-core", Available: "6.8.9-300.fc40"},
		{Name: "python3-a-really-long-package-name-that-wraps", Available: "1.2.3-1.fc40"},
		{Name: "openssl-libs", Available: "1:3.2.1-6.fc40"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseApkAndPacman(t *testing.T) {
	apk := parseApk([]byte("Installed:                                Available:\nbusybox-1.36.1-r15 < 1.36.1-r16\nssl_client-1.36.1-r15 < 1.36.1-r16\npy3-foo-bar-2.0-r0 < 2.1-r0\n"))
	if len(apk) != 3 || apk[2] != (Update{Name: "py3-foo-bar", Current: "2.0-r0", Available: "2.1-r0"}) {
		t.Fatalf("apk: %+v", apk)
	}
	pac := parsePacman([]byte("linux 6.6.1.arch1-1 -> 6.6.2.arch1-1\nzstd 1.5.5-1 -> 1.5.6-1\n"))
	if len(pac) != 2 || pac[0] != (Update{Name: "linux", Current: "6.6.1.arch1-1", Available: "6.6.2.arch1-1"}) {
		t.Fatalf("pacman: %+v", pac)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"6.8.12-4-pve", "6.8.9-1-pve", 1},
		{"6.1.0-18-amd64", "6.1.0-21-amd64", -1},
		{"6.1.0-18-amd64", "6.1.0-18-amd64", 0},
		{"6.10.0", "6.9.12", 1},
	} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestNewerKernel(t *testing.T) {
	mods, boot := t.TempDir(), t.TempDir()
	kernel := func(v string) {
		os.MkdirAll(filepath.Join(mods, v), 0o755)
		os.WriteFile(filepath.Join(boot, "vmlinuz-"+v), nil, 0o644)
	}
	kernel("6.1.0-18-amd64")
	if newerKernel("6.1.0-18-amd64", mods, boot) {
		t.Fatal("only the running kernel is installed")
	}
	// Leftover module directories without a kernel image don't count
	os.MkdirAll(filepath.Join(mods, "6.1.0-99-amd64"), 0o755)
	if newerKernel("6.1.0-18-amd64", mods, boot) {
		t.Fatal("a modules directory without a kernel is not an installed kernel")
	}
	kernel("6.1.0-21-amd64")
	if !newerKernel("6.1.0-18-amd64", mods, boot) {
		t.Fatal("a newer kernel is installed")
	}
	if !newerKernel("6.1.0-10-amd64", mods, boot) {
		t.Fatal("the running kernel's modules are gone")
	}
	if newerKernel("6.1.0-21-amd64", t.TempDir(), boot) {
		t.Fatal("no modules at all, as in a container: no opinion")
	}
}

func TestReportURL(t *testing.T) {
	for in, ok := range map[string]bool{
		"https://up2date.example.com/":  true,
		"http://up2date.example.com":    false,
		"http://127.0.0.1:8080":         true,
		"http://localhost:8080":         true,
		"ftp://example.com":             false,
		"":                              false,
		"https://up2date.example.com/x": true,
	} {
		u, err := reportURL(in)
		if (err == nil) != ok {
			t.Errorf("%q: %v", in, err)
		}
		if ok && u[len(u)-len("/api/report"):] != "/api/report" {
			t.Errorf("%q gave %q", in, u)
		}
	}
}
