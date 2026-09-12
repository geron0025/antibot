# The aggregate format: what the node sends to the cloud

Format version: **1**.

The `rule`, `shadow` and `with_cookie` fields were added on
12 September 2026 — before any node had sent an aggregate, so the format
version stayed the first.

This document was fixed before the first line of code. The reason is
plain: once there are many installations the format can no longer be
changed — history in the old shape will have accumulated on the far side,
and on this side there will be nodes that are not going to be updated
tomorrow. A field can always be added; removing or reinterpreting an
existing one cannot.

## What is sent and when

**By default, nothing.** Until a subscription token is in the
configuration, the sending code does not run at all. This is not a
"switch telemetry off" setting but the absence of an addressee: with no
token the node does not know where to send and does not try.

An enabled node closes a window every **5 minutes**, accumulates closed
windows and sends them in a batch every **15 minutes** in one HTTPS
request.

Five minutes was chosen so that a burst shows up as a line of its own: an
hourly window would smear a two-minute raid into an unnoticeable addition
to the background, and a one-minute window would multiply the volume
fivefold for a precision nobody uses.

## What never gets into an aggregate

| Not sent | Why |
|---|---|
| The full IP address | personal data; a prefix is enough to identify a network |
| The User-Agent string | forged freely and carries identifying tails |
| Request paths and parameters | the contents of somebody else's site, often with identifiers inside |
| Headers and their values | cookies, tokens and authorization live there |
| The cookie value | only a counter of requests that came with a cookie goes out — `with_cookie` |
| Request and response bodies | the same, and worse |
| Rule conditions | they may hold office addresses, paths, names; only the `id` of the rule that fired goes out |

What is sent is the **composition** of the headers as a hash rather than
the headers themselves; the client's **family** rather than its string;
the **network prefix** rather than the address.

The address is truncated to `/24` for IPv4 and `/48` for IPv6. `/48` and
not `/64` for IPv6 because providers hand a subscriber a `/64` out of a
shared `/48`, and by `/64` the same client would scatter into thousands
of rows.

## The aggregate row

Rows are grouped by a key; everything that is not the key is a counter.

**The key:**

| Field | Type | What |
|---|---|---|
| `window` | RFC 3339 string | the start of the five-minute window, UTC |
| `domain` | string | the protected domain, punycode |
| `ja4` | string | the TLS fingerprint |
| `h2` | string | the HTTP/2 fingerprint in the Akamai format; empty for HTTP/1.1 |
| `headers` | string | the hash of the header composition |
| `ua_family` | string | `chrome`, `firefox`, `safari`, `curl`, `python`, `go`, `bot`, `unknown` |
| `ua_matches_ja4` | boolean | whether the claimed client agrees with the TLS fingerprint |
| `net` | string | the network prefix: `203.0.113.0/24`, `2001:db8::/48` |
| `rule` | string | the `id` of the rule that decided; empty when none did; `own network` — a request from the own networks |
| `shadow` | array of strings | the `id`s of rules in `shadow` mode that fired, alphabetically; an empty array when none did |

**The counters:**

| Field | Type | What |
|---|---|---|
| `requests` | integer | requests in total |
| `with_cookie` | integer | of these, how many came with a cookie — presence only, the value is not read |
| `blocked` | integer | rejected by a rule in `active` mode |
| `shadowed` | integer | a rule in `shadow` mode fired |
| `limited` | integer | rejected by the rate limiter |
| `status` | object | `{"2xx": 41, "4xx": 3}` — classes of response codes |
| `uniq_paths` | integer | how many **distinct** paths, a HyperLogLog estimate |
| `uniq_addrs` | integer | how many distinct addresses inside the prefix |
| `methods` | object | `{"GET": 40, "HEAD": 4}` |
| `bytes_out` | integer | bytes served |

`uniq_paths` and `uniq_addrs` are estimates rather than exact numbers:
keeping sets is expensive, and an approximate count is enough to tell
"one address hammering one path" from "fifty addresses walking the
catalogue". It is precisely this pair that separates a scanner from a
scraper, and a farm from one persistent client.

`ua_matches_ja4` is not a derived field but a conclusion of the node: the
claimed client was compared against the fingerprint base at the moment of
the request. It cannot be computed after the fact in the cloud, because
by then the base is already a different one.

Clarifications on what the node puts into the key and the counters:

- `rule` and `shadow` are in the key rather than counters beside it:
  every request of a row was decided the same way, and what the row says
  about a rule — cookies, paths, answers — is exact rather than a share
  of a mix. That is what they are for: the cloud analyses the statistics
  and tells the owner that a rule has started cutting people, and for
  that it has to know which rule. An `id` is the owner's text, and the
  rules engine does not limit it; it goes over the wire at most
  64 characters long and without control characters, and `shadow` holds
  at most 16 rules.
- `domain` is only a domain the node serves. `Host` is sent by the
  client, and a scanner writes whatever it likes there. A name not named
  by a route, exactly or by a pattern (the default route `*` does not
  count), an address instead of a name and a string longer than
  253 characters go out as an empty string `""`: otherwise scanner junk
  would travel to the cloud, and a single overlong name would get the
  whole batch rejected by the schema.
- `net` is empty when the client's address could not be determined.
- `methods` counts `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `PATCH`,
  `OPTIONS`, `CONNECT` and `TRACE` by name, and everything else under the
  key `OTHER`. The method is sent by the client too, and without a list a
  single row could carry a thousand made-up verbs.

## The size limit

No more than **5000** rows in one window. Beyond that the 4999 largest
by `requests` stay, and the rest are folded into one row whose `domain`,
`ja4`, `h2`, `headers`, `ua_family`, `net` and `rule` equal `"~rest"` and
whose `shadow` is `["~rest"]`, with the counters summed. Two key fields are not folded: `window` stays the start
of the window and `ua_matches_ja4` is `true`. The schema requires a date
and a boolean there, and `true` means the same as the node's default —
"no grounds to believe the client is lying". The `uniq_paths` and
`uniq_addrs` of the folded row are merged, not summed: one path seen by
two rows is still one path.

The same limit applies to **the whole batch** — `rows.maxItems` in the
schema. A window is never split between batches: when the closed windows
together exceed the limit, they go out in several batches. A batch
carries one `facts_version`, so a change of base between windows starts a
new one as well.

The limit is mandatory: under a distributed attack the number of unique
combinations grows with the number of addresses, and without it the node
would start sending megabytes at exactly the moment its owner least needs
trouble with the channel. A folded row keeps the scale of what is
happening while losing the detail.

The node holds no more than 20,000 distinct keys in memory per open
window; new keys beyond that go straight into `~rest`. A limit on
sending without a limit on memory would protect the channel but not the
node itself.

## The whole batch

```json
{
  "format": 1,
  "batch": "8f14e45fceea167a5a36dedd4bea2543-20260908T1700Z",
  "node": "8f14e45fceea167a5a36dedd4bea2543",
  "node_version": "0.1.0",
  "facts_version": 137,
  "sent_at": "2026-09-08T17:20:00Z",
  "rows": [
    {
      "window": "2026-09-08T17:00:00Z",
      "domain": "shop.example.ru",
      "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
      "h2": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
      "headers": "9c1185a5c5e9fc54",
      "ua_family": "chrome",
      "ua_matches_ja4": false,
      "net": "203.0.113.0/24",
      "rule": "",
      "shadow": ["watch-hosting-go"],
      "requests": 412,
      "with_cookie": 0,
      "blocked": 0,
      "shadowed": 412,
      "limited": 0,
      "status": {"2xx": 412},
      "uniq_paths": 389,
      "uniq_addrs": 47,
      "methods": {"GET": 412},
      "bytes_out": 8912384
    }
  ]
}
```

`node` is a random identifier created on the first run and kept in the
node's state. It is not derived from a domain, an address or the
hardware: the cloud needs only to tell installations apart, not to
recognize them.

`facts_version` is in the batch so that the cloud knows which base the
node was using when it decided `ua_matches_ja4`.

## Delivery

`POST` to the address from the configuration,
`Content-Type: application/json`, `Content-Encoding: gzip`, the
subscription token in the `Authorization` header.

| Answer | What the node does |
|---|---|
| `202` | the batch was accepted, the buffer is freed |
| `400`, `413` | the format or the size was rejected — **no retry**, writes to the log, frees the buffer |
| `401`, `403` | the token is no good, sending sleeps for an hour |
| `429`, `5xx` | retry with a growing delay: 1, 2, 4… up to 30 minutes |

`batch` is an idempotency key: a repeat of the same batch after a broken
connection must not double the counters on the far side. The node derives
it from its identifier and the start of the batch's first window rather
than picking it at random: a window belongs to exactly one batch, and a
batch assembled again after a crash gets the same key. The cloud drops a
repeated key.

Batches go one at a time, **the oldest first**, and while it has not
been accepted the ones after it wait: the cloud receives the windows in
order.

The buffer of unsent batches is limited to **200** (about two days).
Beyond that the oldest are dropped. An unreachable cloud has no right to
fill somebody else's disk: the service here is the traffic, not the
reporting.

The buffer lives on disk, in `cloud.state_dir`, and survives a restart.
The open window is saved there too, once a minute and on stop: a crash
of the process loses at most a minute of counting, a graceful stop loses
nothing.

**Sending does not touch the hot path.** It lives in its own goroutine,
and the cloud being unreachable affects serving requests in no way beyond
a line in the log.

## The schema

The machine-readable schema is
[../../schema/aggregate.schema.json](../../schema/aggregate.schema.json).
The receiver must reject a batch that does not match it: `400` without a
retry. Extra fields are forbidden deliberately — an "unknown field" on
the cloud's side means somebody is sending something other than what we
described, and it is better to find that out at once.
