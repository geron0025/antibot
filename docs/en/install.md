# Installation

The node is installed before any payment, by a stranger, often inside a
closed network. Hence its main property: **not one external dependency**.
No database, no cache, no queue, no mandatory network addressee.

There are two programs:

- **`antibot`** — the core: terminates TLS, applies the rules, writes the
  events. It works on its own, with rules from files;
- **`antibot-admin`** — the [admin UI](admin.md), optional. A separate
  process under a separate user; it talks to the core through a socket
  and shared files.

The core can be installed alone. The admin UI — when there is a need to
look at the traffic and to change the rules other than from the command
line.

## With a container

```bash
docker run -d --name antibot --restart unless-stopped \
  -p 80:8080 -p 443:8443 \
  -v /etc/antibot:/etc/antibot:ro \
  -v antibot-state:/var/lib/antibot \
  ghcr.io/geron0025/antibot:latest
```

`--restart unless-stopped` is not decoration: a fallen core is brought
back by docker, and there is nobody else to do it. The admin UI cannot
restart the core and must not be able to.

The admin UI is a separate image, with the core's volume and one of its
own:

```bash
docker run -d --name antibot-admin --restart unless-stopped \
  -p 127.0.0.1:8090:8090 \
  -v /etc/antibot:/etc/antibot:ro \
  -v antibot-state:/var/lib/antibot \
  -v antibot-admin-state:/var/lib/antibot-admin \
  ghcr.io/geron0025/antibot-admin:latest

docker exec -it antibot-admin antibot-admin accounts passwd owner
```

In a container the admin UI has to listen not on loopback —
`listen: "0.0.0.0:8090"` in `admin.yaml` — and so with a certificate:
otherwise it will not start. The users in the images are already set up
as they should be — `antibot` (10001) and `antibot-admin` (10002) in one
group — and the volume's directories get the right permissions on the
first mount.

**Mount the whole `/var/lib/antibot` directory, not individual files
inside it.** The rules are replaced atomically, through `rename`, and a
bind-mount of a single file in Linux is tied to the inode: the new file
is a different inode, and until a restart the node keeps applying the old
rules without showing anything. That cost one post-mortem; more in
[operations.md](operations.md).

## With a binary

```bash
make build    # antibot and antibot-admin
```

Go 1.26 or newer. The build has three external dependencies:
`golang.org/x/net` (HTTP/2 and punycode), `gopkg.in/yaml.v3`
(configuration) and `golang.org/x/text` (transitively). None at runtime.

Users and directories. The core and the admin UI are two users of one
group; both sides can write only in `shared`, the rest of the core's
directory is read-only to the admin UI, and the admin UI's own directory
is out of the core's reach. Why so — [admin.md](admin.md#a-program-of-its-own).

```bash
sudo groupadd --system antibot
sudo useradd --system -g antibot -d /var/lib/antibot -s /usr/sbin/nologin antibot
sudo useradd --system -g antibot -d /var/lib/antibot-admin -s /usr/sbin/nologin antibot-admin

sudo install -m 0755 antibot antibot-admin /usr/local/bin/
sudo install -d -m 0755 /etc/antibot
sudo install -d -o antibot -g antibot -m 0750 /var/lib/antibot
sudo install -d -o antibot -g antibot -m 0770 /var/lib/antibot/shared
sudo install -d -o antibot-admin -g antibot -m 0700 /var/lib/antibot-admin
```

As systemd services. The core:

```ini
[Unit]
Description=antibot
After=network.target

[Service]
ExecStart=/usr/local/bin/antibot serve -config /etc/antibot/config.yaml
Restart=always
User=antibot
Group=antibot
# Ports below 1024 without root:
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`Restart=always` brings a fallen core back, and the restart button in
the admin UI rests on the same thing: the core exits when asked, and
systemd starts it again.

The admin UI, `/etc/systemd/system/antibot-admin.service`:

```ini
[Unit]
Description=antibot admin UI
After=network.target antibot.service

[Service]
ExecStart=/usr/local/bin/antibot-admin serve -config /etc/antibot/admin.yaml
Restart=always
User=antibot-admin
Group=antibot

[Install]
WantedBy=multi-user.target
```

`After=` but not `Requires=`: the admin UI does not depend on the core,
and with the core down it shows that the core is down rather than
falling together with it.

```bash
sudo -u antibot-admin antibot-admin accounts passwd owner
sudo systemctl enable --now antibot antibot-admin
```

### An installation from before the split

Before the admin UI became a separate program, everything lived in one
process and in one directory. Such an installation is updated like this:

1. Move the `admin_ui` section from `config.yaml` to `admin.yaml`
   ([configuration.md](configuration.md#adminyaml--the-admin-uis-settings)) —
   with it the core will not start and will say so.
2. Move `rules.json`, `domains.json`, `alerts.json` and the directory of
   uploaded certificates to `/var/lib/antibot/shared` and fix the paths
   in `config.yaml` — or leave the paths as they were if the admin UI is
   not being installed.
3. Move the accounts and the API tokens to `/var/lib/antibot-admin`, with
   `antibot-admin` as the owner; or create an account anew.
4. The commands `antibot admin …` and `antibot api-token …` are now
   `antibot-admin accounts …` and `antibot-admin api-token …`.

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
   `antibot-admin accounts passwd NAME`, then [admin.md](admin.md).
2. A day later write your first rule — in `shadow` mode, always — and
   replay it over the accumulated log: [rules.md](rules.md).
3. Once you see whom it touches, move it to `active` — with the button on
   the rules page of the admin UI or with `antibot rules mode ID active`.
   The node applies it at once, without a restart.

In that order. An antibot whose work is invisible never gets put into
blocking mode — and rightly so.
