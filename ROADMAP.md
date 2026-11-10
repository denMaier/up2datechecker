# Roadmap

Up2Date remains a monitoring service for now. Installing updates remotely is a
possible future feature, not a current commitment.

## Potential: opt-in APT upgrades

The goal would be to help keep servers current while limiting the dashboard's
authority over each host. A host could poll for an upgrade request when it
reports, and only act if remote upgrades have been enabled locally on that host.
The dashboard could choose when to request an upgrade; it could not enable the
feature on a host.

Before implementing this, define and review these boundaries:

- Allow only a fixed `apt-get upgrade` operation, with locally defined arguments.
  The server must not supply commands, arguments, package names, repository
  configuration, or replacement agent binaries. Specify whether new dependencies
  may be installed and how held-back packages are reported.
- Keep remote upgrades off by default and require explicit per-host local opt-in.
  Keep the reporting agent's restricted sandbox and explore a separate,
  narrowly scoped privileged upgrade service; verify the boundary in practice.
- Require an explicit dashboard confirmation and provide an audit trail and
  clear success, failure, and reboot-needed results. Do not reboot automatically.
- Use expiring request IDs, replay protection, concurrency and rate limits, and
  define behavior for retries, timeouts, package-manager locks, prompts, and
  package hooks. Prevent an old or repeated request from silently running again.
- Use the existing verified HTTPS connection. Define how TLS termination and
  the proxy-to-dashboard connection protect reports and upgrade requests.
- Review and test the design before implementation or deployment. A compromised
  dashboard could still trigger upgrades on opted-in hosts, including many hosts
  at once. Upgrades can restart services and run trusted packages' maintainer
  scripts as root; the host's repositories, signing keys, and APT hooks remain
  part of the trust boundary.

Other package managers and automatic scheduling are outside this initial idea.
