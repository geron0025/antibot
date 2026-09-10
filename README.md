# antibot

A reverse proxy in Go that takes the network fingerprint of a client and
tells a browser from an automated client by it. One binary, no external
dependencies: no database, no cache, no queue.

> Документация на русском — [docs/ru/README.md](docs/ru/README.md).

## Why

The `User-Agent` header is forged with one line. The way a client
establishes a TLS connection and opens an HTTP/2 stream is not: that is
determined by its library, and forging it means rewriting that library.

So every request yields:

| Signal | Where from |
|---|---|
| `JA3`, `JA4` | the ClientHello, parsed before it reaches `crypto/tls` |
| HTTP/2 fingerprint (Akamai format) | the SETTINGS, WINDOW_UPDATE and PRIORITY frames and the order of the pseudo-headers |
| Header composition and its hash | which headers arrived and in what order |
| A User-Agent that disagrees with JA4 | the client called itself Chrome, the handshake is not Chrome's |
| The presence of GREASE | browsers send it, hand-written clients usually do not |

The standard library cannot give you this: `tls.ClientHelloInfo` carries
neither the list of extensions nor their order — and that is half of JA3
and the key part of JA4 — and Go silently drops GREASE values, even
though their presence is a signal in itself.

## Quick start

```bash
docker run -d --name antibot \
  -p 80:8080 -p 443:8443 \
  -v /etc/antibot:/etc/antibot:ro \
  -v antibot-state:/var/lib/antibot \
  ghcr.io/geron0025/antibot:latest
```

A minimal `/etc/antibot/config.yaml`:

```yaml
upstreams:
  - host: "*"
    to: "http://127.0.0.1:3000"
```

Everything else comes from the defaults. The node comes up, starts
proxying and writing events — and **blocks nobody**: there are no rules,
so there are no prohibitions. Next: [installation](docs/en/install.md)
and [configuration](docs/en/configuration.md).

## Documentation

| Document | About |
|---|---|
| [install.md](docs/en/install.md) | installation: container, binary, certificates |
| [configuration.md](docs/en/configuration.md) | every configuration key and why it is what it is |
| [rules.md](docs/en/rules.md) | rules: the model, the fields, the order, replaying over history |
| [facts.md](docs/en/facts.md) | the network and fingerprint bases: applying, rolling back, the border |
| [admin.md](docs/en/admin.md) | the admin UI: pages, login, its single writing action |
| [operations.md](docs/en/operations.md) | running it: events, rotation, working out what broke |
| [protocol/](docs/en/protocol/) | what goes up to the cloud and what comes back |

## What already works

- **ClientHello parsing** of our own, `JA3` and `JA4` — checked against
  captured references from Chrome, Firefox, Safari, curl, python and Go,
  plus a differential fuzzer against `crypto/tls`;
- **HTTP/2 fingerprint**: SETTINGS, WINDOW_UPDATE, PRIORITY and the order
  of the pseudo-headers. The same request from Go gives `a,m,p,s`, from
  curl `m,s,a,p`, from Chrome `m,a,s,p`;
- **a fingerprint over the header composition**;
- **proxying** with routes by host name, the client's real address and
  certificate selection by SNI, including a self-signed fallback;
- **events in NDJSON** with rotation and a retention period;
- **a layer of your own networks**, checked before the rules;
- **rules**: a condition over facts, scopes, `shadow` and `active` modes,
  the `block`, `allow` and `ratelimit` actions; the file is reread on the
  fly;
- **replaying over history** — with the same matcher the hot path uses;
- **a rate limiter** — a sliding window in the process's memory;
- **an admin UI**: events, statistics and rules;
- **fact bases**: parsing, signature, applying from disk, fetching over
  the network, rollback;
- **sending aggregates** to the cloud — only with a subscription token;
  `antibot aggregate show` prints exactly what would leave.

Not there: ACME, Prometheus metrics.

Verified: the container comes up in a network **with no outside access**,
with an empty base directory, and serves HTTPS and HTTP. Not one database
is running while it does — otherwise nobody would install it.

## How it is built

```
client ──TLS/HTTP2──► antibot ──HTTP/1.1──► your site
                         │
                         ├──► events/*.ndjson   events, rotated by age
                         ├──◄─ rules.json       rules, reread on the fly
                         └──◄─ facts/*.json     network and fingerprint bases
```

All state is files on disk. Rules and facts are held compiled in memory
and reread without a restart; the hot path of a request goes into no
storage and cannot get stuck in one.

## Borders set on day one

- **Nothing is sent without a token.** Not "telemetry switched off by a
  setting" but the absence of an addressee: until a token is in the
  configuration, the sending code does not run at all.
- **The arriving bases block nothing.** They change only what a client is
  called; what to do with it is decided by your rule.
- **Rules are changed only by you.** There is no way to enable a rule
  from the outside, and there will not be one.
- **There is one matcher.** Replaying over history exercises the same
  code the hot path runs, not a translation of it into a database query.

## License

[Apache 2.0](LICENSE). Copyright 2026 Geron — see [NOTICE](NOTICE).

A fork without the fingerprint and network bases is just another user of
the update service that built its own image, so there is nothing to
defend against forks with a license. The patent clause of Apache
meanwhile settles the question for those installing this inside a
company.
