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
second after it started.

## listen

```yaml
listen:
  http: ":8080"
  https: ":8443"
  admin: "127.0.0.1:8091"
```

| Key | Default | What |
|---|---|---|
| `http` | `:80` | traffic of the customer domains |
| `https` | `:443` | the same with TLS |
| `admin` | `127.0.0.1:8091` | service port: `/healthz` and `/stats` |

The service port is separate from 80 and 443 because those serve the
traffic of the customer domains, and `/healthz` on them would turn into a
page that does not exist on every protected site. It is not published
outwards.

At least one of `http` and `https` must be set, otherwise the startup
stops: a node with no listeners does nothing.

The name `listen.admin` is left over from an early version and means the
**service** port, not the admin UI — that one is configured under
`admin_ui`.

## tls

```yaml
tls:
  certificates_dir: "/etc/letsencrypt/live"
  self_signed_dir: "/var/lib/antibot/certs"
  reload_interval: 30s
```

| Key | Default | What |
|---|---|---|
| `certificates_dir` | empty | the certificate directory; empty means self-signed only |
| `self_signed_dir` | `/var/lib/antibot/certs` | where the fallback is kept |
| `reload_interval` | `30s` | how often to rescan the directory |

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

```yaml
admin_ui:
  enabled: true
  listen: "127.0.0.1:8090"
  users_file: "/var/lib/antibot/admin.json"
  session_ttl: 12h
  # certificate: "/etc/letsencrypt/live/admin.example.ru/fullchain.pem"
  # key: "/etc/letsencrypt/live/admin.example.ru/privkey.pem"
  # redirect_from: ":8089"
```

| Key | Default | What |
|---|---|---|
| `enabled` | `true` | whether to bring the admin UI up |
| `listen` | `127.0.0.1:8090` | the address |
| `certificate`, `key` | empty | set **together** |
| `redirect_from` | empty | an address where HTTP answers with 308 |
| `users_file` | `/var/lib/antibot/admin.json` | the accounts |
| `session_ttl` | `12h` | the session lifetime |

**A non-loopback address without a certificate is a refusal at startup.**
Not a warning: the password would travel the network in clear text, and
that is not an inconvenience but access already granted. If you want the
admin UI exposed, set a certificate first.

`redirect_from` works only together with a certificate. Code 308 and not
301: 301 allows the browser to change the method to GET, and a submitted
login form would silently turn into an empty request.

The accounts are a separate file rather than these settings: the
configuration is often mounted read-only, while a password is changed
without restarting the node. Without a single account the admin UI does
not come up, but **the node works**: it must serve traffic with no human
anywhere near it.

## rules

```yaml
rules:
  file: "/var/lib/antibot/rules.json"
  reload_interval: 5s
```

The file is reread on the fly: a change is noticed by its time and size.
The check is cheap — one look at the file's metadata.

A broken rule discards the **whole** set, and the previous one stays in
force. A half-applied set looks like it works and is therefore more
dangerous than a refusal.

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

Fetching runs once a day plus jitter. The token comes from
`cloud.token`: it is one token for both directions, and there is no
anonymous distribution of the bases. So `facts.url` without
`cloud.token` is an error at startup.

## cloud

```yaml
cloud:
  token: ""
  # url: "https://updates.example.com/ingest"
  interval: 15m
  state_dir: "/var/lib/antibot/aggregate"
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

## What is checked at startup

- at least one listener is set;
- `trusted_proxies` and `own_networks` are networks like `10.0.0.0/8`,
  not addresses;
- every `upstreams` entry has both `host` and `to`;
- `admin_ui.enabled` without `listen` is an error;
- `certificate` and `key` are set together;
- `cloud.token` without `cloud.url` is an error: nowhere to send;
- `cloud.token` without `cloud.state_dir` is an error: nowhere to keep what is not sent yet;
- `facts.url` without `facts.dir` is an error: nowhere to put it;
- durations look like `30s`, `15m`, `24h` and are not negative.

A duration type of our own is needed because YAML would read `30` as
thirty nanoseconds. That is worse than a parse error: a check interval of
thirty nanoseconds does not break the startup, it just burns the CPU in
production.
