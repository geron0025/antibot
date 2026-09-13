# The API

The numbers the admin UI shows, for a program: monitoring, a panel of
your own, a CI job that rolls rules out together with the site. The API
lives on the admin UI's address, under `/api/v1/`, and follows its rules:
loopback by default, outward only with a certificate. There is no second
listener with rules of its own.

A program comes with a token, not a session. The admin UI's forms do not
take a token, and the API does not take the session cookie: neither door
opens the other, and a request without a cookie leaves CSRF nothing to
forge.

## Tokens

```bash
antibot api-token issue monitoring                # read only, 90 days
antibot api-token issue ci -scope write -days 30
antibot api-token list
antibot api-token revoke monitoring
```

The command prints the value alone to stdout — `TOKEN=$(antibot
api-token issue monitoring)` takes exactly it, and the words go to
stderr. The admin UI's "API tokens" page can do the same; there an issue
asks for the password once more, because a token outlives a session by
months ([admin.md](admin.md)).

- **Scope**: `read` — the summary, the events, the rules; `write` —
  changing the rules as well. A monitoring token should only read: it
  must not be able to switch the protection off.
- **Term** — from 1 to 365 days, 90 by default. There is no token without
  an end: "for now" on such a token lasts years.
- **Kept as a hash** — SHA-256 in `admin_ui.tokens_file`, mode `0600`. The
  value is shown once, at issue; a stolen copy of the file lets nobody
  in. SHA-256 rather than PBKDF2 as for passwords: a token is 256 random
  bits, and slowing down the guessing of something that cannot be guessed
  only slows down every request.
- **The file is reread on the fly**: a token issued with the command
  works without restarting the node, a revoked one stops from the next
  request.
- **The last use** is written down to ten minutes: otherwise monitoring
  would rewrite the file several times a second.
- **The name** — letters, digits, dot, dash and underscore, up to 64;
  among live tokens it does not repeat: by the name the node's log says
  who changed what. Revoked and expired tokens stay in the list — "which
  token did the CI use until the 12th" must have an answer.
- The value starts with `abn_` — a node API token is told from a cloud
  subscription token at a glance: in a config, in a log, in a paste that
  leaked.

**A token is the owner's.** It is issued only on the node and never goes
to the cloud: the node has no code that would send one, and the cloud
neither accepts nor keeps such tokens. A token with the right to write in
the cloud's hands would mean the cloud could switch a rule on at somebody
else's site — exactly what it can never do.

## A request

```bash
curl -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:8090/api/v1/summary?period=24h'
```

With a certificate on the admin UI — `https://` and its outward address.
Answers are JSON in UTF-8; an error is `{"error": "…"}` with the reason in
words.

| Code | What |
|---|---|
| `200` | the answer |
| `400` | a parameter was not read. A default is not substituted quietly: a program must learn that it asked for something other than it got |
| `401` | no token, or it is unknown, revoked or expired; with a `WWW-Authenticate` header |
| `403` | the token may only read |
| `404` | there is no such address in the API |
| `429` | too many refused tokens from this address — twenty per five minutes |
| `500` | the event log was not read; the reason is in the answer and in the node's log |
| `503` | the node did not read the tokens file |

Only refusals are counted: a working token never runs into the limit,
however often monitoring asks.

## The summary — `GET /api/v1/summary`

What the admin UI's overview shows — the same code builds it, so the
numbers do not drift apart.

| Parameter | Default | What |
|---|---|---|
| `period` | `24h` | over what span, up to `2160h` — 90 days |
| `top` | `10` | rows in each breakdown, up to 1000 |

```json
{
  "from": "2026-09-12T12:00:00Z",
  "to": "2026-09-13T12:00:00Z",
  "summary": {
    "events": 18422,
    "ip_count": 3120,
    "decisions": {"pass": 17890, "block": 532},
    "answers": [16010, 402, 1320, 158, 532, 0],
    "latency": {"count": 17890, "p50": 41000000, "p95": 380000000, "p99": 910000000},
    "rules": [{"value": "block-hosting", "count": 532, "ips": 61}],
    "unknown": {"no_net_class": 9120, "no_family": 4410, "self_declared_crawlers": []},
    "…": "…"
  }
}
```

- `decisions` — how many requests got each decision;
- `answers` — six numbers by answer class, in order: the site's 2xx, 3xx,
  4xx and 5xx, `blocked` — not let through by the node, `none` — no
  status;
- `latency` — the site's answer time in **nanoseconds**, only over the
  requests that reached the site;
- the breakdowns `rules`, `shadows`, `hosts`, `ips`, `ja4`, `ua`, `paths`,
  `statuses`, `server_error_paths`, `client_error_paths` — rows
  `{value, count, ips}`: the value, the requests and from how many
  addresses;
- `unknown` — what the node does not know: requests without a network
  class, nameless fingerprints, self-declared crawlers — each with how
  many came from a crawler network (`verified`);
- `series` — the time series, every point with the same six classes;
- `truncated: true` — at least one breakdown hit the key limit, and its
  numbers are incomplete.

## Events — `GET /api/v1/events`

Newest first. The filters are those of the events page and combine with
"and".

| Parameter | What |
|---|---|
| `host`, `ip`, `ja4`, `decision` | an exact match |
| `rule` | the rule that decided the request, or one that fired in shadow |
| `status` | a code (`404`) or a class (`5xx`, `blocked`) — as on the overview |
| `q` | a substring of the `User-Agent` or the path |
| `limit` | how many events, from 1 to 1000, 100 by default |
| `before` | only older than this moment — that is how the pages go |

```json
{
  "events": [
    {"t": "2026-09-13T11:58:02.123456789Z", "ip": "198.51.100.9", "host": "shop.example.ru",
     "method": "GET", "path": "/api", "proto": "HTTP/2.0", "ua": "curl/8.4",
     "ua_ok": true, "decision": "block", "rule": "block-curl", "status": 403}
  ],
  "next_before": "2026-09-13T11:58:02.123456789Z"
}
```

An event is exactly a line of the log, as in the NDJSON
([operations.md](operations.md)); `dur` is in nanoseconds.

**Pages.** A full page carries `next_before` — the moment of its oldest
event; the next one is asked for with `before=` that value. The last page
has no `next_before`. Two events written in the very same nanosecond on
either side of a page boundary may miss each other — the price of a
cursor that keeps no state on the node.

## Rules — `GET /api/v1/rules`

In the order of application, the disabled after the enabled. Each with
how many times it fired over `period` (`24h` by default) and from how
many addresses; in shadow too. This is the admin UI's rules page, and the
two share their code.

```json
{
  "from": "2026-09-12T12:00:00Z",
  "to": "2026-09-13T12:00:00Z",
  "events": 18422,
  "rules": [
    {"rule": {"id": "block-hosting", "scope": ["*"], "mode": "active", "priority": 100,
              "condition": {"field": "network.class", "op": "eq", "value": "hosting"},
              "action": {"type": "block"}},
     "matched": 532, "ips": 61, "enabled": true}
  ]
}
```

`rule` is the rule exactly as it lies in `rules.json` ([rules.md](rules.md)).
If the event log was not read, the answer is a `500` rather than rules
with zeros: a program would read the zeros as "never fired".

## The schemas

The machine-readable schemas of the answers lie next to the protocol's:
[api-summary](../schema/api-summary.schema.json),
[api-events](../schema/api-events.schema.json),
[api-rules](../schema/api-rules.schema.json),
[api-error](../schema/api-error.schema.json). The
`TestAPIAnswersMatchTheSchemas` test checks the node's real answers
against them, so the schema and the code do not drift apart. A field the
schema does not describe does not pass.

## The borders

- **the same address and the same rules as the admin UI**: loopback by
  default, outward only with a certificate. Without accounts the admin UI
  does not come up, and neither does the API; without
  `admin_ui.tokens_file` the API is off;
- **a token only in the `Authorization` header**. In an address it would
  settle in proxy logs and in the shell history;
- **the session cookie does nothing in the API, and a token does nothing
  in the admin UI's forms**;
- the same headers as the pages: `Cache-Control: no-store`,
  `X-Robots-Tag: noindex`;
- **the API is the node's local surface**, not part of the exchange with
  the cloud: it does not change the [protocol](protocol/) and sends
  nothing out.

## What it does not have yet

- **writing rules** — adding a ready one, enabling and disabling, moving
  to `active`, deleting, replaying a draft over history. That is the next
  step; until it, a `write` token can do what a `read` one can;
- domains and certificates — later, under a scope of their own.
