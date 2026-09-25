# Configuration

A YAML file; the path is given by the `-config` flag and defaults to
`/etc/antibot/config.yaml`. A commented example lives in
[deploy/config.example.yaml](../../deploy/config.example.yaml) and is
checked by a test: should the example drift from the code, the test
fails.

Two things settled on day one:

- **Everything has a default.** The node must work with an empty file.
- **A typo in a field name is an error at startup**, not a silently
  ignored intention. Whoever wrote `trusted_proxy` instead of
  `trusted_proxies` finds out right away rather than while investigating
  an incident with a forged address.

The validation runs **before the ports are taken**. An invalid setting
stops the startup rather than bringing an already-working node down a
second after it started. A taken port is a refusal to start too, with the
key's name and the address: a node that came up without one of its doors
looks alive, and the missing door is found only when it is needed.

These are the settings of the **core**. The admin UI, a separate program
`antibot-admin`, has its own — [admin.yaml](#adminyaml--the-admin-uis-settings),
and it does not read `config.yaml`: the cloud token is in it.

## listen

```yaml
listen:
  http: ":8080"
  https: ":8443"
  admin: "127.0.0.1:8091"
  control: "/var/lib/antibot/core.sock"
```

| Key | Default | What |
|---|---|---|
| `http` | `:80` | traffic of the customer domains |
| `https` | `:443` | the same with TLS |
| `admin` | `127.0.0.1:8091` | service port: `/healthz` and `/stats` |
| `control` | `/var/lib/antibot/core.sock` | the control socket for the admin UI; empty means no socket |

The service port is separate from 80 and 443 because those serve the
traffic of the customer domains, and `/healthz` on them would turn into a
page that does not exist on every protected site. It is not published
outwards.

At least one of `http` and `https` must be set, otherwise the startup
stops: a node with no listeners does nothing.

The name `listen.admin` is left over from an early version and means the
**service** port, not the admin UI — that one is a separate program with
settings of its own.

`listen.control` is a unix socket through which the admin UI asks the
core about what lives only in its memory: the alerts, the link to the
cloud, the certificates, the version and the start time; through it, too,
the admin UI asks the core to reread a changed file or to restart. Mode
`0660`: the core's user and the group the admin UI belongs to. A core
with rules already written and no admin UI does not need the socket — an
empty value turns it off. A socket left over from a core that fell is
replaced at startup; a socket someone answers on is a refusal to start:
that is a second core.

## tls

```yaml
tls:
  certificates_dir: "/etc/letsencrypt/live"
  uploaded_dir: "/var/lib/antibot/shared/certificates"
  self_signed_dir: "/var/lib/antibot/certs"
  reload_interval: 30s
```

| Key | Default | What |
|---|---|---|
| `certificates_dir` | empty | the certificate directory led by hand or by certbot |
| `uploaded_dir` | `/var/lib/antibot/shared/certificates` | where certificates uploaded through the admin UI land; empty turns uploads off |
| `self_signed_dir` | `/var/lib/antibot/certs` | where the fallback is kept |
| `reload_interval` | `30s` | how often to rescan the directories |

Two directories rather than one, on purpose: `certificates_dir` often
belongs to certbot or is mounted read-only, and the node does not write
into a directory somebody else leads. Both are scanned, with one layout.
When both hold a certificate for the same name, the one that lives longer
serves.

The self-signed certificate is **saved** to disk. That matters more than
it looks: a certificate created anew on every start changes the site's
fingerprint on every restart.

More about the directory layout in [install.md](install.md).

## upstreams

```yaml
upstreams:
  - host: "shop.example.ru"
    to: "http://127.0.0.1:3000"
  - host: "*.example.ru"
    to: "http://127.0.0.1:3001"
  - host: "*"
    to: "http://backend:80"
```

Three forms of a name, in decreasing order of precision:

| Form | What it covers |
|---|---|
| `shop.example.ru` | an exact name |
| `*.example.ru` | any subdomain of any depth, but **not** `example.ru` itself |
| `*` | the default route |

**The order of the lines changes nothing.** The exact match is chosen
first, then the longest matching pattern, and only after that the
default. The "whoever is higher wins" rule in route configuration has
been catching people out for decades, and it is not here.

A caveat about TLS: a wildcard in a **certificate** covers exactly one
label, so for `a.b.example.ru` the route by `*.example.ru` will be found
while the certificate `*.example.ru` will not fit.

Names are brought to a single form: no port, lowercased, in punycode.
`Пример.РФ`, `пример.рф.` and `xn--e1afmkfd.xn--p1ai` are one name — in a
rule, in a route and in an event alike.

Domains can also be added without touching this file — from the admin UI
or with `antibot domains`; they live separately, see
[`domains`](#domains). On a name both lists know, `upstreams` wins.

## trusted_proxies

```yaml
trusted_proxies:
  - "10.0.0.0/8"
```

Who is allowed to set `X-Forwarded-For`. **Empty by default**, and that
is the only possible default: the header is set with one line of curl,
and trusting it by default means anyone who wants to can call themselves
anybody — and so bypass any rule based on an address and put somebody
else's network under a block.

The chain is read right to left: on the right is whoever is closest, and
each next one was added by the previous. We walk while the addresses are
trusted; the first untrusted one is the client. Everything to its left
was written by the client itself. Garbage in the chain means "trust it no
further": working out who wrote it is no longer possible.

## own_networks

```yaml
own_networks:
  - "203.0.113.7/32"
```

Your own addresses: monitoring, VPN, your workstation. Checked **before
the rules** and always let through; marked `rule: "own network"` in the
event.

A separate layer, not a high-priority rule. An own network written as an
exception into ten rules will one day be forgotten in the eleventh — and
your own monitoring falls under a block exactly when you need it.

## node_id_file

```yaml
node_id_file: "/var/lib/antibot/node.id"
```

The installation's identifier. The node creates it itself on the first
run — sixteen random bytes — and keeps it on disk: an identifier
regenerated on every start would turn one installation into a new one
every restart.

It is **not derived** from a domain, an address or the hardware. The
cloud needs only to tell installations apart, not to recognize them.

## events

```yaml
events:
  dir: "/var/lib/antibot/events"
  max_size: 268435456
  keep_days: 14
  queue: 4096
```

| Key | Default | What |
|---|---|---|
| `dir` | `/var/lib/antibot/events` | where to write |
| `max_size` | 256 MiB | the file limit after which the next one starts |
| `keep_days` | 14 | how many days to keep; **0 means "never delete"** |
| `queue` | 4096 | how many events fit in the buffer before the write |

`keep_days: 0` is a deliberately dangerous value: the disk will run out
silently.

On an overflow of the queue the event is lost, but the request **does not
wait for the disk**. The log exists for after-the-fact analysis, and the
site exists for its visitors. The drop counter is visible on the service
port, in `/stats`: a silently dropping log is worse than none, because
people draw conclusions from it.

The event format is in [operations.md](operations.md).

## admin_ui

The section is no more: the admin UI is a separate program with settings
of its own, [admin.yaml](#adminyaml--the-admin-uis-settings). If the
section is left in `config.yaml` from an earlier version, the core will
not start and will say where to move it — ignored silently, it would
leave the owner guessing why there is no admin UI.

## The shared directory

What the admin UI writes — the rules, the domains, the alerts command,
the uploaded site certificates — lies by default in
`/var/lib/antibot/shared`. The admin UI runs under another user, and an
atomic file replacement needs write permission on the file's directory.
Granting that permission on the whole of `/var/lib/antibot` would let the
admin UI replace the cloud token and the node's identifier. So the group
may write only in `shared`, and the rest of the directory is read-only to
it — for the sake of the events and the socket.

An installation from before the split kept these files right in
`/var/lib/antibot`. It works that way too: the paths are set in its
`config.yaml`. They need moving to `shared` when `antibot-admin` is
installed — [install.md](install.md).

## rules

```yaml
rules:
  file: "/var/lib/antibot/shared/rules.json"
  reload_interval: 5s
```

The file is reread on the fly: a change is noticed by its time and size.
The check is cheap — one look at the file's metadata. An edit from the
admin UI the core takes at once: the admin UI asks it through the socket
to reread the file.

A broken rule discards the **whole** set, and the previous one stays in
force. A half-applied set looks like it works and is therefore more
dangerous than a refusal.

## domains

```yaml
domains:
  file: "/var/lib/antibot/shared/domains.json"
  reload_interval: 5s
```

The domains added while the node runs: from the admin UI or with the
command

```bash
antibot domains add shop.example.ru http://127.0.0.1:8080
antibot domains list
antibot domains remove shop.example.ru
```

The node does not write the YAML, so the domains are a file of their own
modelled on `rules.json`: the same validation, the same atomic
replacement, the same rereading on the fly. Both lists work together,
and on a name both know **`upstreams` wins** — what the machine's owner
wrote by hand is not overridden from the admin UI. The default route `*`
is set only in `upstreams`.

A broken file at startup is an error; broken on the fly, it leaves the
previous list in force, and no added site drops off because of a typo.

## facts

```yaml
facts:
  enabled: true
  dir: "/var/lib/antibot/facts"
  # url: "https://updates.example.com/facts"
  interval: 24h
```

The network and fingerprint bases. `enabled: false` turns their use off
entirely — the very line promised in the protocol.

Without a `url` the node does not fetch the bases; applying a set from
disk always works: `antibot facts apply`. More in [facts.md](facts.md).

Fetching runs once a day plus jitter. One token serves both directions
and there is no anonymous distribution of the bases — but the token need
not come from this file: the node takes one itself when the owner ticks
"receive security updates" in the admin UI ([cloud.md](cloud.md)). A
`url` set here outranks the one the cloud sends.

## cloud

```yaml
cloud:
  token: ""
  # url: "https://updates.example.com/ingest"
  interval: 15m
  state_dir: "/var/lib/antibot/aggregate"
  link_file: "/var/lib/antibot/cloud.json"
  # register_url: "https://updates.netbota.ru"
```

Sending anonymized aggregates. **An empty token means no sending at
all.** Not "switched off by a setting" but no addressee: without a token
the node does not know where to send and does not try.

What exactly leaves and what never does is in
[protocol/aggregate.md](protocol/aggregate.md).

`interval` is how often closed windows are packed into a batch and
sent; the window itself is always five minutes. The first batch leaves
after a random share of the interval following the start: otherwise
installations from one image would knock on the cloud at the same
second.

`state_dir` holds the open window and the batches the cloud has not
accepted yet: no more than 200 of them, about two days. It is created
only when a token is set. What lies there and what goes next is shown by
`antibot aggregate status` and `antibot aggregate show`.

`link_file` holds what the owner answered in the admin UI about the
cloud, and the token if he took one. It is **the node's state, not its
settings**: the one file the admin UI writes here, mode `600`. A `token`
set above outranks everything in it. An empty `link_file` means a token
cannot be taken from the admin UI at all — it can then only be written
into this file by hand.

`register_url` is where the node asks for a token. Empty means the
address beside `url`, and with no `url` either, the one the binary was
built with. In detail —
[cloud.md](cloud.md) and [protocol/registration.md](protocol/registration.md).

## alerts

```yaml
alerts:
  enabled: true
  command: ""
  file: "/var/lib/antibot/shared/alerts.json"
  language: ""
  timeout: 30s
  window: 5m
  site_error_share: 0.5
  site_min_requests: 20
  spike_factor: 5
  spike_min_requests: 500
  spike_min_blocked: 200
  rule_min_matches: 50
  cert_days: 14
  disk_min_mb: 1024
  facts_max_age: 168h
  outbox_max: 12
```

| Key | Default | What |
|---|---|---|
| `enabled` | `true` | whether to count the triggers at all |
| `command` | empty | the delivery command, through `sh -c`; set here, it wins over the one set in the admin UI |
| `file` | `/var/lib/antibot/shared/alerts.json` | where the admin UI keeps its command; empty — the command only from the configuration |
| `language` | empty | the language of the messages to the command: `en` or `ru`; set here, it wins over the one chosen in the admin UI; empty leaves it to the admin UI, and to English without one. See [Alerts](alerts.md#language) |
| `timeout` | `30s` | how long to wait for the command, from `1s` to `5m` |
| `window` | `5m` | the stretch every traffic trigger looks at; whole minutes, from `1m` to `1h` |
| `site_error_share` | `0.5` | the share of the site's 5xx at which it "does not answer" |
| `site_min_requests` | `20` | fewer requests to the site over the window — no verdict |
| `spike_factor` | `5` | how many times the usual makes a spike; at least `1.5` |
| `spike_min_requests` | `500` | fewer requests over the window — no spike, however small the usual |
| `spike_min_blocked` | `200` | the same for the cut-off ones |
| `rule_min_matches` | `50` | the same for one rule; for a new rule it alone decides |
| `cert_days` | `14` | how many days before the end of a term to speak of a certificate; `0` — never |
| `disk_min_mb` | `1024` | how much free space under the log counts as the end; `0` — do not look |
| `facts_max_age` | `168h` | how long the fact set may go without an update when the node fetches them |
| `outbox_max` | `12` | how many unsent aggregate batches are already a breakage; `0` — do not look |

The default thresholds are meant to spare a small site alarms from a
dozen bots and a big one from drowning in them. "The usual" is the
average of the hour before the window; there are no spikes in the first
half hour after a start. How a message comes, what the command gets and
ready templates — [alerts.md](alerts.md).

## What is checked at startup

- at least one listener is set;
- `trusted_proxies` and `own_networks` are networks like `10.0.0.0/8`,
  not addresses;
- every `upstreams` entry has both `host` and `to`;
- an `admin_ui` section is an error, with a hint where to move it;
- `cloud.token` without `cloud.url` is an error: nowhere to send;
- `cloud.token` without `cloud.state_dir` is an error: nowhere to keep what is not sent yet;
- `facts.url` without `facts.dir` is an error: nowhere to put it;
- `facts.url` without `cloud.token` **and** without `cloud.link_file` is
  an error: there is nowhere to take a token from and nowhere to put one;
- the `alerts` thresholds are within their bounds: the window is whole
  minutes from `1m` to `1h`, a share is above zero and at most one,
  `spike_factor` is at least `1.5`;
- durations look like `30s`, `15m`, `24h` and are not negative.

A duration type of our own is needed because YAML would read `30` as
thirty nanoseconds. That is worse than a parse error: a check interval of
thirty nanoseconds does not break the startup, it just burns the CPU in
production.

## admin.yaml — the admin UI's settings

The file of `antibot-admin`, by default `/etc/antibot/admin.yaml`; the
path is given by the `-config` flag. A commented example lives in
[deploy/admin.example.yaml](../../deploy/admin.example.yaml), also under
a test. A typo in a field name is an error, as in `config.yaml`.

```yaml
listen: "127.0.0.1:8090"
# certificate: "/etc/letsencrypt/live/admin.example.ru/fullchain.pem"
# key: "/etc/letsencrypt/live/admin.example.ru/privkey.pem"
# redirect_from: ":8089"
uploaded_dir: "/var/lib/antibot-admin/admin-ui"
users_file: "/var/lib/antibot-admin/admin.json"
tokens_file: "/var/lib/antibot-admin/api-tokens.json"
session_ttl: 12h
language: en

core:
  socket: "/var/lib/antibot/core.sock"
  events_dir: "/var/lib/antibot/events"
  rules_file: "/var/lib/antibot/shared/rules.json"
  domains_file: "/var/lib/antibot/shared/domains.json"
  certificates_dir: "/var/lib/antibot/shared/certificates"
  alerts_file: "/var/lib/antibot/shared/alerts.json"
```

| Key | Default | What |
|---|---|---|
| `listen` | `127.0.0.1:8090` | the address |
| `certificate`, `key` | empty | set **together** |
| `redirect_from` | empty | an address where HTTP answers with 308 |
| `uploaded_dir` | `/var/lib/antibot-admin/admin-ui` | where a pair added on the Settings page lands when `certificate` and `key` are empty; it serves from the next start. Empty turns adding off |
| `users_file` | `/var/lib/antibot-admin/admin.json` | the accounts |
| `tokens_file` | `/var/lib/antibot-admin/api-tokens.json` | the [API](api.md)'s tokens, as hashes; empty turns the API off |
| `session_ttl` | `12h` | the session lifetime |
| `language` | `en` | the language of the pages when neither the viewer chose one nor the browser names one: `en` or `ru`; anything else is a refusal to start. See [Language](admin.md#language) |
| `core.socket` | `/var/lib/antibot/core.sock` | the core's `listen.control` |
| `core.events_dir` | `/var/lib/antibot/events` | the core's `events.dir`; read only |
| `core.rules_file` | `/var/lib/antibot/shared/rules.json` | the core's `rules.file` |
| `core.domains_file` | `/var/lib/antibot/shared/domains.json` | the core's `domains.file` |
| `core.certificates_dir` | `/var/lib/antibot/shared/certificates` | the core's `tls.uploaded_dir`; empty means no uploads |
| `core.alerts_file` | `/var/lib/antibot/shared/alerts.json` | the core's `alerts.file`; empty means the alerts command cannot be changed from the admin UI |

The paths under `core` are the same as in the core's `config.yaml`: the
admin UI does not read it, so they are named here a second time.

**A non-loopback address without a certificate is a refusal at startup.**
Not a warning: the password would travel the network in clear text, and
that is not an inconvenience but access already granted. If you want the
admin UI exposed, set a certificate first, or add a pair on the Settings
page. It is reread on the fly, at most once every 30 seconds: one renewed
by certbot is taken up without a restart.

`redirect_from` works only together with a certificate. Code 308 and not
301: 301 allows the browser to change the method to GET, and a submitted
login form would silently turn into an empty request.

The accounts are a separate file rather than these settings: the
settings are often mounted read-only, while a password is changed without
a restart. Without a single account the admin UI does not start; the
core does not depend on that.

The API tokens live next to them for the same reason. The API lives on
the admin UI's address, under `/api/v1/`, and does not come up without
it; issuing, scopes and answers — [api.md](api.md).

Checked at startup: `listen` is set, `certificate` and `key` are set
together, `core.socket` and `core.events_dir` are not empty, there is at
least one account, a non-loopback address only with a certificate.
