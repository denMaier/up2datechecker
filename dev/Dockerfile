# One image per distribution, each with the up2date binary built from this checkout
ARG BASE=debian:13-slim

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-X main.version=dev" -o /up2date .

# A Debian host booting systemd, with rootful and rootless Quadlets and the agent's real units
FROM debian:13 AS podman-host
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv dbus dbus-user-session podman uidmap passt ca-certificates >/dev/null \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /up2date /usr/local/bin/up2date
COPY deploy/up2date-agent.service deploy/up2date-agent.timer /etc/systemd/system/
COPY dev/podman-host/ /
RUN chmod 600 /etc/up2date/agent.env && systemctl enable up2date-agent.timer dev-setup.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

# The plain agents: the distribution's image plus the binary
FROM ${BASE}
COPY --from=build /up2date /usr/local/bin/up2date
