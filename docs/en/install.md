# Installation

The node is installed before any payment, by a stranger, often inside a
closed network. Hence its main property: **not one external dependency**.
No database, no cache, no queue, no mandatory network addressee.

## With a container

```bash
docker run -d --name antibot \
  -p 80:8080 -p 443:8443 \
  -v /etc/antibot:/etc/antibot:ro \
  -v antibot-state:/var/lib/antibot \
  ghcr.io/geron0025/antibot:latest
```

**Mount the whole `/var/lib/antibot` directory, not individual files
inside it.** The rules are replaced atomically, through `rename`, and a
bind-mount of a single file in Linux is tied to the inode: the new file
is a different inode, and until a restart the node keeps applying the old
rules without showing anything. That cost one post-mortem; more in
[operations.md](operations.md).

## With a binary

```bash
go build -trimpath -ldflags "-s -w -X main.Version=$(git describe --tags --always)" \
  -o antibot ./cmd/antibot
```

Go 1.25 or newer. The build has three external dependencies:
`golang.org/x/net` (HTTP/2 and punycode), `gopkg.in/yaml.v3`
(configuration) and `golang.org/x/text` (transitively). None at runtime.

```bash
sudo install -m 0755 antibot /usr/local/bin/antibot
sudo mkdir -p /etc/antibot /var/lib/antibot
sudo antibot serve -config /etc/antibot/config.yaml
```

As a systemd service:

```ini
[Unit]
Description=antibot
After=network.target

[Service]
ExecStart=/usr/local/bin/antibot serve -config /etc/antibot/config.yaml
Restart=always
User=antibot
# Ports below 1024 without root:
AmbientCapabilities=CAP_NET_BIND_SERVICE
StateDirectory=antibot

[Install]
WantedBy=multi-user.target
```

## What to put in the configuration

The minimum is where to proxy to:

```yaml
upstreams:
  - host: "*"
    to: "http://127.0.0.1:3000"
```

Everything else has a default, and the node must work with an empty file.
The full reference is [configuration.md](configuration.md).

## Certificates

The node terminates TLS itself and picks a certificate by the name from
SNI.

```yaml
tls:
  certificates_dir: "/etc/letsencrypt/live"
```

Two layouts are understood: a subdirectory per domain with
`fullchain.pem` and `privkey.pem` (the way certbot does it), or
`cert.pem` and `key.pem`. The directory is rescanned on a timer, so a
renewal by certbot and the addition of a new domain take effect
**without a restart**.

On a timer rather than by watching files, deliberately: certificates are
almost always updated by substitution — a `rename` on top or a symlink
switch — and watching follows the inode and does not notice such a
substitution at all.

If there are no certificates, a self-signed one is issued and saved into
`self_signed_dir`. It exists so that the node comes up with no
configuration at all: without it the very first HTTPS request would break
off at the handshake, and whoever installed the container would decide it
is broken. A browser complains about it — and a warning about that goes
into the log.

The node does not do ACME and will not for now: issuing certificates is a
separate responsibility with its own state, and certbot next to it solves
the same problem and is already installed for most people.

## The first run

```bash
antibot serve -config /etc/antibot/config.yaml
```

In the log at startup:

```
level=INFO msg="the node has started" http=:8080 https=:8443
  events=/var/lib/antibot/events rules=0 facts=0 version=0.1.0
```

`rules=0` and `facts=0` are the normal state of a node that has just been
installed. **It blocks nobody**: there are no rules, so there are no
prohibitions. The node proxies and writes events; you can look at them
right away.

## Next

1. Create a login for the admin UI and look at your traffic:
   `antibot admin passwd NAME`, then [admin.md](admin.md).
2. A day later write your first rule — in `shadow` mode, always — and
   replay it over the accumulated log: [rules.md](rules.md).
3. Once you see whom it touches, move it to `active`: change `mode` in
   `rules.json` and validate the file with `antibot rules check`. The
   node rereads it by itself, without a restart.

In that order. An antibot whose work is invisible never gets put into
blocking mode — and rightly so.
