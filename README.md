<img src="assets/icon.svg" width="64" height="64" alt="">

# Up2Date

A small dashboard that shows which of your servers need attention: pending updates, security updates, a pending reboot, failed services, or a server that stopped reporting. That's all it does.

- **One page.** Every host with its status, most urgent first: *needs attention* (security updates, reboot required, failed services, no report for a day, agent error), *updates available*, *up to date*. Each host has a page listing its pending packages, security updates first.
- **Push, not pull.** A small agent on each server reports to the dashboard every 6 hours and right after you install or upgrade packages. The dashboard holds no SSH keys or other credentials for your servers and never connects to them.
- **Failed systemd services**, of the system and of every account with lingering enabled, which is where rootless Quadlets run. A crashed Quadlet container shows up as its failed unit. With `HealthOnFailure=kill` in a Quadlet, a failing health check does too.
  - Units that fail as a matter of course can be quieted three ways. All of them stay listed, greyed out:
    - **Acknowledge** a failure on the host's page. It stops counting until a report shows the unit recovered, so if it fails again later, it counts again.
    - **Always ignore** it on that host.
    - Ignore it on **every host** with name patterns such as `systemd-modules-load.service`, set on the Settings page. Changes apply at once.
- **Package managers:** apt (Debian, Ubuntu, Proxmox VE), dnf (Fedora, RHEL, Alma, Rocky), apk (Alpine) and pacman (Arch, with `pacman-contrib` and `fakeroot`). apt and dnf mark security updates.
- **Sign-in with OpenID Connect only** (Pocket ID, Authentik, Keycloak, …), limited to the listed users and/or groups. Up2Date refuses to start without such a list.
- **Small.** One static Go binary is both the dashboard and the agent. It has two dependencies (go-oidc, oauth2). The pages are rendered on the server and use no JavaScript. State is a single JSON file. The dashboard uses about 10 MB of memory.

## How it works

```
 server A ─┐  HTTPS POST /api/report
 server B ─┼─────────────────────────▶  up2date serve  ◀── you, signed in with OIDC
 server C ─┘  Bearer <host token>        /var/lib/up2date/hosts.json
```

You add a host in the dashboard. It shows you that host's token **once** and stores only a SHA-256 hash of it. The agent sends its report with that token, and the token alone decides which host the report is for, so a server can only update its own entry. If a token leaks, give the host a new one; the old token stops working at once.

The agent runs as root, because refreshing the package lists needs root. Otherwise it only runs the package manager's read-only queries (`apt-get -s dist-upgrade`, `dnf check-update`, `apk version`, `checkupdates`) and `systemctl list-units --failed`. For a lingering account it runs that as the account, against the account's own systemd. It opens no port and only sends to an `https://` URL; plain `http://` is accepted only for localhost. The reboot check uses `/run/reboot-required`, `dnf needs-restarting`, and whether a newer kernel is installed than the one running. The kernel part is skipped inside containers.

## Install

### Dashboard

You need:

- Linux with systemd;
- a reverse proxy with TLS;
- an OIDC client whose redirect URI is `https://<your host>/auth/callback`.

Run as root:

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/denMaier/up2datechecker/main/deploy/install.sh)" -- server
```

The installer asks for the public URL, the OIDC issuer, client ID and secret, and the users and/or groups who may sign in. It then does the following:

- Downloads the release binary to `/usr/local/bin/up2date` and checks it against the release's `SHA256SUMS`.
- Writes your settings to `/etc/up2date/server.env`, readable by root only.
- Installs and starts [`up2date.service`](deploy/up2date.service). The service runs as a dynamic, unprivileged user under a strict systemd sandbox: `systemd-analyze security` rates it 1.1.

Running the installer again updates the binary and keeps the settings. The settings are listed in [`deploy/server.env.example`](deploy/server.env.example).

### Agent, on each server

Add the host in the dashboard. It shows the token and this command, which you run as root on that server:

```sh
curl -fsSL https://raw.githubusercontent.com/denMaier/up2datechecker/main/deploy/install.sh | bash -s -- agent https://up2date.example.com
```

The command asks for the token. To run it unattended, set `UP2DATE_TOKEN` instead. It installs:

- the same binary;
- `/etc/up2date/agent.env` with the URL and token, readable by root only;
- [`up2date-agent.service`](deploy/up2date-agent.service), a sandboxed oneshot that can only write the package managers' list and cache directories (homes and `/run/user` are read-only for it);
- [`up2date-agent.timer`](deploy/up2date-agent.timer), which runs it every 6 hours;
- a hook for apt or pacman that reports after every package change.

On Alpine (OpenRC), it uses a daily job in `/etc/periodic/daily` instead of the timer. The installer needs `bash` and `curl` there.

To check what the agent would send without sending it:

```sh
up2date agent -dry-run
```

## Development

`make dev` starts a test environment in Docker at <http://127.0.0.1:8484>. Sign in as `admin@example.com` / `password`. It has Dex for the login and agents on Debian, Ubuntu, Rocky and Alpine, some with old images so they have pending updates. It also has a Debian host that boots systemd, with failing services and rootful and rootless Quadlets, where the agent runs from its real units. `make dev-down` stops it, and `make dev-reset` also forgets the hosts. The setup is in [`dev/`](dev).

```sh
make test     # gofmt, go vet, go test
make build    # ./up2date
make release  # static linux/amd64 and linux/arm64 binaries and SHA256SUMS in dist/
```

Pushing a `v*` tag builds a release on GitHub.

## License

AGPL-3.0, see [LICENSE](LICENSE).
