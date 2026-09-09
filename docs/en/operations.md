# Running it

## Events

One line per request, NDJSON. The format was chosen because everything
reads it: `grep`, `jq`, any script and `antibot` itself when it replays a
rule over history.

```json
{"t":"2026-09-09T12:00:00Z","ip":"203.0.113.7","host":"shop.example.ru",
 "method":"GET","path":"/catalog","proto":"HTTP/2.0","ua":"curl/8.7.1",
 "ja4":"t13i4906h2_0d8feac7bc37_7395dae3b2f3","sni":"shop.example.ru",
 "alpn":"h2,http/1.1","tls":"1.3","h2":"1:65536;2:0|15663105|0|m,s,a,p",
 "hdrs":"accept,user-agent","hdrs_hash":"e5a56608905c6682",
 "net_class":"hosting","net_owner":"Example Hosting Ltd","net_age":7,
 "ua_ok":false,"decision":"block","rule":"block-hosting",
 "shadow":["watch-curl"],"status":403,"dur":47834}
```

| Field | What |
|---|---|
| `t`, `ip`, `host`, `method`, `path`, `proto` | the request |
| `ua`, `ref` | the headers |
| `ja3`, `ja3_hash`, `ja4`, `sni`, `alpn`, `tls`, `grease` | TLS |
| `h2` | the HTTP/2 fingerprint |
| `hdrs`, `hdrs_hash` | the header composition |
| `family`, `ua_ok`, `net_*` | from the fact set |
| `decision` | `pass`, `allow`, `block`, `ratelimit` |
| `rule` | which rule decided |
| `shadow` | which watchers fired |
| `status`, `bytes`, `dur` | the response; `dur` in nanoseconds |

Empty fields are not written. An event with `decision: "pass"` and no
`rule` is a request nothing was found for.

### Rotation

One file per day, `events-2026-09-09.ndjson`; one that grew to `max_size`
is closed and the writes continue into the next, numbered. A cleanup once
an hour removes files older than `keep_days`.

A change of day closes the file on purpose: that way the retention
cleanup works with whole files instead of cutting them from the inside.

### Useful

```bash
# who was not let through today
jq -r 'select(.decision=="block") | .ip' events-$(date +%F).ndjson | sort | uniq -c | sort -rn

# one fingerprint across how many addresses — this is the "bots or people" question
jq -r 'select(.ja4!=null) | "\(.ja4) \(.ip)"' events-*.ndjson | sort -u | cut -d' ' -f1 | uniq -c | sort -rn

# what fired in the shadows
jq -r '.shadow[]?' events-*.ndjson | sort | uniq -c
```

## The service port

```bash
curl http://127.0.0.1:8091/healthz    # alive
curl http://127.0.0.1:8091/stats      # {"events_dropped":0,"version":"0.1.0"}
```

`events_dropped` has to be visible: a log that loses events silently is
worse than none, because people draw conclusions from it. If it grows,
raise `events.queue` or work out why the disk is not keeping up.

The port is not published outwards.

## What to put into monitoring

- `/healthz` — liveness;
- `events_dropped` from `/stats` — whether it is growing;
- the share of `decision: "block"` — a sharp rise means either a raid or
  a rule that caught people;
- the date in `antibot facts status` — whether the base has frozen.

There are no Prometheus metrics: not until a live installation asks.

## Working out what broke

### The site stopped opening

```bash
antibot rules list                       # what is in force
antibot replay -for 1h -examples 5       # whom it is cutting off right now
```

A rule touching more than a percent of the requests almost certainly
touches people too. Switch it off — with the button in the admin UI or
`antibot rules disable ID`; the change is picked up without a restart.

If it broke after a base update — `antibot facts rollback`. No network is
needed for that.

### The rules do not apply after an edit

A **file** is mounted rather than a directory. The replacement goes
through `rename`, and a bind-mount of a single file in Linux is tied to
the inode: the new file is a different inode, and until a restart the
container applies the old rules without showing anything.

Mount the whole `/var/lib/antibot`. On Docker Desktop it is picked up,
that is, the trap does not reproduce on a developer's machine.

### Every request gets a 403

Most likely a rule like `{"field": "ua_matches_ja4", "op": "eq",
"value": false}` on a node **with no fact bases**. Check
`antibot facts status`. From this version on the field's default is
`true` and such a rule matches nobody, but a rule copied from an older
draft may have counted on the opposite.

### The browser complains about the certificate

The self-signed one is in use: `certificates_dir` is not set or holds no
suitable pair. This is written as a warning at startup.

### The node does not come up

The settings are validated **before** the ports are taken, so the reason
is always in the very first line of the log. Most often:

| Message | What to do |
|---|---|
| `admin UI on … without a certificate` | set `certificate`/`key` or listen on loopback |
| `admin_ui.enabled without admin_ui.listen` | set the address |
| `cloud.token is set and cloud.url is not` | either remove the token or set the address |
| `no listener is configured` | set `listen.http` or `listen.https` |
| `is not a network like 10.0.0.0/8` | an address instead of a network in `trusted_proxies`/`own_networks` |

### The fingerprints are not being taken

Over plain HTTP there are none and cannot be: `ja4` and `h2` come from
the TLS handshake and the HTTP/2 frames. Over HTTP/1.1 with TLS there
will be a `ja4` but no `h2`.

The header composition over HTTP/1.1 is taken **without the order**: it
can be recovered only from the raw bytes, which `net/http` does not keep.
For HTTP/2 the order is known exactly, and the fingerprint is stronger
there.

## Updating the node

The state is files in `/var/lib/antibot`; they survive a replacement of
the binary and of the image. Rules, accounts, fact sets and events stay
where they are.

```bash
docker pull ghcr.io/geron0025/antibot:latest
docker restart antibot
```

A restart logs everybody out of the admin UI (the sessions live in
memory) and resets the rate limiter's counters. That is deliberate.

## Backups

```bash
tar czf antibot-$(date +%F).tar.gz \
  /etc/antibot/config.yaml \
  /var/lib/antibot/rules.json \
  /var/lib/antibot/admin.json
```

Events are usually not needed in a backup — there are many and they go
stale. Neither are the fact sets: they arrive again.

**`admin.json` holds password hashes and `certs/` holds private keys.**
The backup belongs wherever you keep your other secrets, not on a general
file share.
