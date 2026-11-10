#!/usr/bin/env python3
"""Enroll running local Proxmox guests; reruns safely after transient failures."""
import fcntl
import json
import logging
import logging.handlers
import os
import pathlib
import secrets
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

URL = os.environ.get('UP2DATE_URL', '').rstrip('/')
SECRET = os.environ.get('UP2DATE_ENROLLMENT_SECRET', '')
INCLUDE = set(os.environ.get('UP2DATE_INCLUDE', '').replace(',', ' ').split())
EXCLUDE = set(os.environ.get('UP2DATE_EXCLUDE', '').replace(',', ' ').split())
STATE = pathlib.Path('/var/lib/up2date-discovery')
INSTALLER = 'https://raw.githubusercontent.com/denMaier/up2datechecker/main/deploy/install.sh'
LOG = logging.getLogger('up2date-discover')


def configure_logging():
    LOG.setLevel(logging.INFO)
    LOG.handlers.clear()
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    for handler in (logging.StreamHandler(sys.stderr), logging.handlers.RotatingFileHandler(
            '/var/log/up2date-discover.log', maxBytes=1024 * 1024, backupCount=3)):
        handler.setFormatter(fmt)
        LOG.addHandler(handler)


def run(args, data=None, timeout=45):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        detail = result.stderr.strip()[-1000:] or result.stdout.strip()[-1000:]
        raise RuntimeError(f'{args[0]} failed (exit {result.returncode}): {detail}')
    return result


def guest(kind, vmid, script, timeout=45):
    if kind == 'lxc':
        result = subprocess.run(['pct', 'exec', str(vmid), '--', '/bin/sh', '-s'], input=script, text=True, capture_output=True, timeout=timeout)
        return result.returncode, result.stdout + result.stderr
    result = run(['qm', 'guest', 'exec', str(vmid), '--pass-stdin', '1', '--timeout', str(timeout), '--', '/bin/sh', '-s'], script, timeout + 10)
    output = json.loads(result.stdout)
    if not output.get('exited'):
        raise RuntimeError('guest command did not finish')
    return output.get('exitcode', 1), output.get('out-data', '') + output.get('err-data', '')


def selected(kind, item):
    keys = {str(item['vmid']), str(item.get('name', '')), kind + '/' + str(item['vmid'])}
    return not (keys & EXCLUDE) and (not INCLUDE or bool(keys & INCLUDE))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def enroll(name, token):
    if urllib.parse.urlparse(URL).scheme != 'https':
        raise ValueError('UP2DATE_URL must use HTTPS')
    payload = json.dumps({'name': name, 'token': token}).encode()
    req = urllib.request.Request(URL + '/api/enroll', data=payload, headers={'Authorization': 'Bearer ' + SECRET, 'Content-Type': 'application/json'})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
        if response.status != 204:
            raise RuntimeError('unexpected enrollment response')


def process(kind, item):
    vmid = item['vmid']
    if item.get('status') != 'running' or not selected(kind, item):
        return
    code, _ = guest(kind, vmid, 'test -s /etc/up2date/agent.env && test -x /usr/local/bin/up2date && (systemctl is-enabled --quiet up2date-agent.timer 2>/dev/null || test -x /etc/periodic/daily/up2date-agent)\n')
    if code == 0:
        LOG.info('%s/%s: already installed', kind, vmid)
        return
    # Do not create a server record when the guest cannot yet reach the dashboard.
    check = ('command -v bash >/dev/null || { echo "bash is missing"; exit 1; }; '
             'command -v curl >/dev/null || { echo "curl is missing"; exit 1; }; '
             'curl -fsS --max-time 15 -o /dev/null ' + shlex.quote(URL + '/') + '\n')
    code, out = guest(kind, vmid, check, 30)
    if code:
        raise RuntimeError('dashboard unreachable or bash/curl unavailable: ' + out.strip()[-500:])
    # Save the token before creating the server record, so retries cannot orphan it.
    tokenfile = STATE / f'{kind}-{vmid}.token'
    try:
        fd = os.open(tokenfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        token = tokenfile.read_text().strip()
    else:
        token = 'u2d_' + secrets.token_hex(32)
        with os.fdopen(fd, 'w') as f:
            f.write(token + '\n')
            f.flush()
            os.fsync(f.fileno())
    name = f'pve-{kind}-{vmid}'
    enroll(name, token)
    # Token is passed through stdin, not command arguments or journal output.
    script = ("set -eu\nexport UP2DATE_URL=" + shlex.quote(URL) + "\nexport UP2DATE_TOKEN=" + shlex.quote(token) + "\n"
              + "tmp=$(mktemp); trap 'rm -f \"$tmp\"' EXIT; curl -fsSL " + shlex.quote(INSTALLER) + " -o \"$tmp\"; bash \"$tmp\" agent \"$UP2DATE_URL\"\n")
    code, out = guest(kind, vmid, script, 600)
    if code:
        raise RuntimeError('guest installer failed (exit %s): %s' % (code, out[-1000:].replace(token, '[redacted]')))
    LOG.info('%s/%s: installed', kind, vmid)


def main():
    if not URL:
        raise ValueError('UP2DATE_URL is required')
    if not SECRET:
        raise ValueError('UP2DATE_ENROLLMENT_SECRET is required')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(STATE / 'lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        node = run(['hostname']).stdout.strip()
        failures = 0
        LOG.info('discovery started on %s', node)
        for kind, endpoint in [('lxc', 'lxc'), ('qemu', 'qemu')]:
            items = json.loads(run(['pvesh', 'get', f'/nodes/{node}/{endpoint}', '--output-format', 'json']).stdout)
            for item in items:
                try:
                    process(kind, item)
                except Exception as e:
                    failures += 1
                    LOG.warning('%s/%s: %s; will retry', kind, item.get('vmid'), e)
        LOG.info('discovery finished: %d guest(s) need retry', failures)
        return 0


if __name__ == '__main__':
    configure_logging()
    try:
        sys.exit(main())
    except Exception:
        LOG.exception('discovery failed')
        sys.exit(1)
