#!/usr/bin/env bash
# Up2Date installer, run as root:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/denMaier/up2datechecker/main/deploy/install.sh)" -- server
#   curl -fsSL https://raw.githubusercontent.com/denMaier/up2datechecker/main/deploy/install.sh | bash -s -- agent https://up2date.example.com
#
#   server              install or update the dashboard on this machine
#   agent [URL]         install or update the agent that reports this machine's updates
#
# Running it again updates the binary and keeps the settings. Questions can be answered in
# advance, for unattended runs:
#   server: UP2DATE_PUBLIC_URL UP2DATE_OIDC_ISSUER UP2DATE_OIDC_CLIENT_ID UP2DATE_OIDC_CLIENT_SECRET
#           UP2DATE_ALLOWED_USERS UP2DATE_ALLOWED_GROUPS UP2DATE_LISTEN
#   agent:  UP2DATE_URL UP2DATE_TOKEN
#   UP2DATE_VERSION=v0.1.0 (default: the latest release)
set -Eeuo pipefail

REPO=denMaier/up2datechecker
BIN=/usr/local/bin/up2date
ETC=/etc/up2date

msg() { printf ' \033[1;92m✔\033[m %s\n' "$1"; }
die() {
  printf ' \033[01;31m✖ %s\033[m\n' "$1" >&2
  exit 1
}
trap 'die "Failed at line $LINENO: $BASH_COMMAND"' ERR

# ask VAR "question" [default]: keeps VAR when it is already set
ask() {
  local var=$1 prompt=$2 def=${3:-} val
  [[ -n ${!var:-} ]] && return 0
  read -r -p " $prompt${def:+ [$def]}: " val </dev/tty || die "Cancelled"
  printf -v "$var" '%s' "${val:-$def}"
}

ask_secret() {
  local var=$1 prompt=$2 val
  [[ -n ${!var:-} ]] && return 0
  read -r -s -p " $prompt: " val </dev/tty || die "Cancelled"
  echo
  printf -v "$var" '%s' "$val"
}

# envget KEY FILE: a value from an existing env file, without quotes
envget() {
  [[ -f $2 ]] || return 0
  sed -n "s/^$1=//p" "$2" | tail -n1 | sed -e 's/^"\(.*\)"$/\1/'
}

# envline KEY VALUE: quoted for systemd and sh alike; values with quotes or backslashes are refused
envline() {
  [[ $2 != *[\"\\\$\`]* ]] || die "$1 must not contain quotes, backslashes, \$ or backticks"
  printf '%s="%s"\n' "$1" "$2"
}

resolve_version() {
  if [[ -n ${UP2DATE_VERSION:-} && $UP2DATE_VERSION != latest ]]; then
    echo "$UP2DATE_VERSION"
    return
  fi
  local url
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
  [[ $url == */tag/* ]] || die "Could not find the latest release"
  echo "${url##*/}"
}

install_binary() {
  local tag=$1 arch tmp
  case $(uname -m) in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "Unsupported architecture $(uname -m)" ;;
  esac
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/up2date_linux_$arch" "https://github.com/$REPO/releases/download/$tag/up2date_linux_$arch"
  curl -fsSL -o "$tmp/SHA256SUMS" "https://github.com/$REPO/releases/download/$tag/SHA256SUMS"
  (cd "$tmp" && grep " up2date_linux_$arch\$" SHA256SUMS | sha256sum -c --quiet -) || die "Checksum mismatch"
  install -m 0755 "$tmp/up2date_linux_$arch" "$BIN"
  rm -rf "$tmp"
  msg "Installed up2date $("$BIN" version) to $BIN"
}

# unit NAME TAG: a systemd unit from the release's own source
unit() {
  curl -fsSL -o "/etc/systemd/system/$1" "https://raw.githubusercontent.com/$REPO/$2/deploy/$1"
}

server() {
  [[ -d /run/systemd/system ]] || die "The server needs systemd"
  local f=$ETC/server.env
  for k in UP2DATE_PUBLIC_URL UP2DATE_OIDC_ISSUER UP2DATE_OIDC_CLIENT_ID UP2DATE_OIDC_CLIENT_SECRET UP2DATE_ALLOWED_USERS UP2DATE_ALLOWED_GROUPS UP2DATE_LISTEN UP2DATE_STALE_HOURS; do
    [[ -n ${!k:-} ]] || printf -v "$k" '%s' "$(envget "$k" "$f")"
  done
  ask UP2DATE_PUBLIC_URL "Public URL (https://…)"
  echo " Register this redirect URI with your OIDC provider: ${UP2DATE_PUBLIC_URL%/}/auth/callback"
  ask UP2DATE_OIDC_ISSUER "OIDC issuer URL"
  ask UP2DATE_OIDC_CLIENT_ID "OIDC client ID" up2date
  ask_secret UP2DATE_OIDC_CLIENT_SECRET "OIDC client secret (empty for a public client)"
  if [[ -z $UP2DATE_ALLOWED_USERS && -z $UP2DATE_ALLOWED_GROUPS ]]; then
    ask UP2DATE_ALLOWED_GROUPS "Groups allowed to sign in (comma separated, may be empty)"
    ask UP2DATE_ALLOWED_USERS "Users allowed to sign in (emails or usernames, may be empty)"
    [[ -n $UP2DATE_ALLOWED_USERS || -n $UP2DATE_ALLOWED_GROUPS ]] || die "Allow at least one group or user"
  fi
  ask UP2DATE_LISTEN "Listen address" 127.0.0.1:8080

  local tag
  tag=$(resolve_version)
  install_binary "$tag"
  install -d -m 0700 "$ETC"
  (
    umask 077
    for k in UP2DATE_LISTEN UP2DATE_PUBLIC_URL UP2DATE_OIDC_ISSUER UP2DATE_OIDC_CLIENT_ID UP2DATE_OIDC_CLIENT_SECRET UP2DATE_ALLOWED_USERS UP2DATE_ALLOWED_GROUPS UP2DATE_STALE_HOURS; do
      [[ -n ${!k:-} ]] && envline "$k" "${!k}"
    done >"$f.new"
    mv "$f.new" "$f"
  )
  unit up2date.service "$tag"
  systemctl daemon-reload
  systemctl enable up2date.service >/dev/null 2>&1
  systemctl restart up2date.service
  sleep 1
  systemctl is-active --quiet up2date.service || die "up2date did not start: journalctl -u up2date"
  msg "Up2Date runs on $UP2DATE_LISTEN; put a TLS reverse proxy for $UP2DATE_PUBLIC_URL in front"
}

agent() {
  local f=$ETC/agent.env
  [[ -n ${UP2DATE_URL:-} ]] || UP2DATE_URL=${1:-$(envget UP2DATE_URL "$f")}
  [[ -n ${UP2DATE_TOKEN:-} ]] || UP2DATE_TOKEN=$(envget UP2DATE_TOKEN "$f")
  ask UP2DATE_URL "Up2Date URL (https://…)"
  ask_secret UP2DATE_TOKEN "This host's token (u2d_…)"
  [[ $UP2DATE_TOKEN == u2d_* ]] || die "That is not an Up2Date token"

  local tag
  tag=$(resolve_version)
  install_binary "$tag"
  install -d -m 0700 "$ETC"
  (
    umask 077
    {
      envline UP2DATE_URL "$UP2DATE_URL"
      envline UP2DATE_TOKEN "$UP2DATE_TOKEN"
    } >"$f.new"
    mv "$f.new" "$f"
  )

  if [[ -d /run/systemd/system ]]; then
    unit up2date-agent.service "$tag"
    unit up2date-agent.timer "$tag"
    systemctl daemon-reload
    systemctl enable --now up2date-agent.timer >/dev/null 2>&1
    hooks "systemctl start --no-block up2date-agent.service"
    msg "The agent reports every 6 hours and after package upgrades"
    systemctl start up2date-agent.service || die "The first report failed: journalctl -u up2date-agent"
    journalctl -u up2date-agent.service -n 1 -o cat --no-pager
  elif [[ -d /etc/periodic/daily ]]; then
    # Alpine with OpenRC: busybox cron runs /etc/periodic/daily
    cat >/etc/periodic/daily/up2date-agent <<EOF
#!/bin/sh
set -a; . $f; set +a
exec $BIN agent >/dev/null
EOF
    chmod 0755 /etc/periodic/daily/up2date-agent
    msg "The agent reports daily from cron (/etc/periodic/daily/up2date-agent)"
    set -a
    # shellcheck source=/dev/null
    . "$f"
    set +a
    "$BIN" agent
  else
    die "No systemd and no periodic cron directory: run '$BIN agent' with $f loaded from your scheduler"
  fi
}

# hooks CMD: report right after apt or pacman installed something, so the dashboard is current
hooks() {
  if [[ -d /etc/apt/apt.conf.d ]]; then
    echo "DPkg::Post-Invoke { \"$1 >/dev/null 2>&1 || true\"; };" >/etc/apt/apt.conf.d/99up2date
  fi
  if [[ -d /etc/pacman.d ]]; then
    mkdir -p /etc/pacman.d/hooks
    cat >/etc/pacman.d/hooks/up2date.hook <<EOF
[Trigger]
Operation = Install
Operation = Upgrade
Operation = Remove
Type = Package
Target = *

[Action]
Description = Reporting to Up2Date
When = PostTransaction
Exec = /bin/sh -c '$1 || true'
EOF
  fi
}

[[ $(id -u) == 0 ]] || die "Run this as root"
cd /
case ${1:-} in
server) server ;;
agent) agent "${2:-}" ;;
*) die "Usage: install.sh server | agent [URL]" ;;
esac
