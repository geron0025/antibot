# The fact set format: what the cloud sends to the node

Format version: **1**.

A fact set is two bases: **networks** (who owns a range) and
**fingerprints** (what a client travels with). Nothing but statements
about the world is in it: no rules, no actions, no decisions.

## The border that does not move

**A fact set cannot block anything.** It changes what a client is called
— the rule of the node's owner decides what to do with such a client. An
arriving row "this network is hosting" prohibits nothing while the owner
has no rule about hosting, and prohibits exactly what that rule says.

This is how it is built, not a promise. A delivery channel into somebody
else's production that can change the behaviour of the protection
directly will sooner or later take somebody's site down — and that will
be the end of it. Hence:

- the set is **signed**, an unsigned one is not applied;
- the set is **versioned**, the version is monotonic, a lower one is not
  accepted;
- previous versions are kept, a **rollback** is one command;
- all of it **switches off** with the line `facts.enabled: false`.

## Networks

```json
{
  "prefix": "203.0.113.0/24",
  "asn": 64496,
  "owner": "Example Hosting Ltd",
  "country": "DE",
  "class": "hosting",
  "protected": false,
  "confidence": "verified",
  "source": "whois:RIPE",
  "verified_at": "2026-09-01",
  "first_seen": "2026-08-14",
  "since": 137
}
```

`class` is one of: `cloud`, `hosting`, `isp`, `mobile`, `crawler`,
`proxy_pool`, `education`, `enterprise`, `unknown`.

`protected: true` means **"do not touch this network at all"**. It is set
on telecom operators with live subscribers and on confirmed search
crawlers. It is the most valuable thing in the base, and it was obtained
more expensively than everything else: to pick out 44 networks of one
cloud pool the previous project needed about eighty whois queries, and
along the way Vodafone, Reliance Jio, Charter, Sky UK, Telefónica and
Telstra had to be taken off the list of suspects — and then PetalBot,
Huawei's crawler, which looked like a pool of 226 addresses. A mistake in
any one row would have cost live visitors or positions in search results.

`confidence` is `verified` (checked by a human or by reverse DNS),
`derived` (inferred from whois and observations) or `reported` (came from
subscribers' observations and has not been checked yet). Rules cannot
see this field yet: it is not among the condition fields
(`antibot rules fields`).

`source` and `verified_at` are mandatory on every record. A catalogue
that does not remember where it took a statement from, and when, starts
lying with confidence — in the previous project it once handed out a
network of Anthropic as a network of Google Cloud.

## Fingerprints

```json
{
  "kind": "ja4",
  "value": "t13d1516h2_8daaf6152771_02713d6af862",
  "family": "chrome",
  "versions": "120-131",
  "platform": "windows",
  "automated": false,
  "headless": false,
  "confidence": "verified",
  "source": "capture",
  "verified_at": "2026-09-01",
  "since": 137
}
```

`kind` is `ja4`, `h2` or `headers`. `family` is what the node puts into
`ua_family` and what it compares the claimed User-Agent against to get
`ua_matches_ja4`.

`automated: true` means the client is not a browser (curl, python, Go, a
library). `headless: true` means a browser started without a screen. They
are separate deliberately: a headless browser is still Chrome with a
genuine TLS fingerprint, and confusing it with curl loses both.

## New records arrive under observation

`since` is the version of the set the record appeared in; from it the
node derives the `network.age` field — how many versions ago the record
appeared. Records from the last **three** versions are new: if a rule
fired on them alone, the node should write to the log that the decision
was made on a fresh fact. This is not implemented yet in the current
build.

A rule may require a hold explicitly:

```json
{"all": [
  {"field": "network.class", "op": "eq", "value": "hosting"},
  {"field": "network.age", "op": "gt", "value": 3}
]}
```

The point is that the first wrongly classified range would kill somebody
else's site with the subscription, and the owner would not even
understand what changed — they did not touch their rules.

## The whole set

```json
{
  "format": 1,
  "version": 137,
  "created_at": "2026-09-08T04:00:00Z",
  "networks": [ "…" ],
  "fingerprints": [ "…" ],
  "counts": {"networks": 18422, "fingerprints": 1140}
}
```

Next to it, a manifest with a signature:

```json
{
  "version": 137,
  "created_at": "2026-09-08T04:00:00Z",
  "size": 4718592,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "key_id": "2026-a",
  "signature": "…base64 Ed25519…"
}
```

What is signed is the `sha256` of the set's contents bound together with
the version and the date — so that a signature cannot be moved from one
set to another.

`key_id` selects a key from the trusted list. The list is compiled into
the binary and supplemented by the `facts/keys.json` file; several keys exist so
that rotating one does not require updating every installation at the
same time.

The set is delivered **whole**, without deltas. Eighteen thousand
networks in gzip take a few megabytes once a day, while deltas would
require the node to keep and repair a history of applications — that is,
exactly the complexity the node is kept simple to avoid.

## Distribution by token

Three addresses, all relative to `facts.url` from the node's
configuration:

| Request | What it returns |
|---|---|
| `GET <url>/manifest?format=1` | the manifest of the latest version |
| `GET <url>/set/<version>` | the whole set, gzip |
| `GET <url>/keys` | the list of trusted keys, signed |

The subscription token goes in the `Authorization: Bearer <token>`
header, the same form as when sending aggregates. The token is mandatory
on all three addresses: there is no anonymous distribution at all,
because the distribution is what the subscription is for.

The token's scope must include downloading the bases (`facts` or `both`).
A token with the `aggregates` scope gets a `403` on these addresses: a
node that only sends observations must not gain the ability to download
the bases, and the split has to hold on the receiver rather than on the
client's word.

### The answers and what the node does

| Answer | What happened | What the node does |
|---|---|---|
| `200` | there is a newer version | checks it and applies it |
| `304` | the same version | nothing, the next attempt on schedule |
| `401` | the token is unknown or revoked | **works on the last set**, retries in an hour |
| `402`, `403` | the subscription does not cover the bases: ended, suspended, or the wrong scope | **the base freezes**, retries once a day |
| `404` | no set has been published yet | changes nothing, retries with a growing delay, as for `5xx` |
| `429`, `5xx` | the cloud is out of shape | retry with a growing delay: 1, 2, 4… up to 6 hours |

The rows about `401` and `403` are the main ones in this document after
the section on the border. **A subscription that ran out does not lift
the protection.** The node keeps working on the last applied set: the
owner's rules stay in force, the network classes stay known, and only
their freshness goes stale.

The opposite design — "did not pay, so the base switches off" — would
mean that an unpaid invoice opens somebody's site to bots. That is not a
sales lever but a way to one day take down a customer who simply did not
pay in time. What is sold is the **freshness** of the base, and an
overdue subscription takes exactly that away.

`403` differs from `401` in meaning: `401` is "this token is no longer
good, it may have been revoked", and in an hour it is worth trying again;
`403` is "the token is intact but the subscription does not cover this",
and nothing will change before the end of the day. Both go into the
node's log, and the version and date of the applied set are shown by
`antibot facts status`: the owner has to learn that the base has frozen
from their own node, not from us.

### What the node reports about itself

In the manifest request, as headers:

| Header | Example | Why |
|---|---|---|
| `If-None-Match` | `"137"` | the applied set's version; this is where `304` comes from |
| `X-Antibot-Node` | `8f14e45f…` | the same identifier as in the aggregate |
| `X-Antibot-Version` | `0.1.0` | the node's version |

The cloud needs the identifier for one thing: to tell installations
apart.

The node reports nothing beyond this: no domains, no addresses, no
composition of rules. Distribution is not an excuse to collect what is
not in the aggregate.

## Compatibility forward

The set's schemas forbid extra fields (`additionalProperties: false`),
and that is the right decision for the aggregate but the wrong one here.
The directions differ:

- **the aggregate goes upwards**, the receiver is the cloud, and it is
  newer than any node. An unknown field means somebody is sending
  something other than what we described, and it is better to find out at
  once: `400` without a retry;
- **the set goes downwards**, the receiver is the node, and it is older
  than the cloud by exactly as long as the owner postpones an update.
  Strictness here would mean no field could ever be added without
  breaking every installation that was not updated today.

Hence the asymmetry, written down deliberately:

1. **The envelope is strict.** Extra top-level fields of the set and the
   manifest are a refusal. The envelope changes only with a change of
   `format`.
2. **The records are tolerant.** An unknown field inside a network or
   fingerprint record is **silently ignored** by the node. A missing
   required field is still a refusal of the whole set.
3. **The format is negotiated by the request.** The node passes
   `?format=1` — the format it can read. The cloud returns the highest
   format not above the requested one. A node that cannot do `format=2`
   keeps receiving the first until it is updated.

Point 3 costs more than the first two, but it is the only one that lets
the envelope be changed one day without appointing a date on which every
installation must update at once.

## Keys and their rotation

Trusted keys live in two places: the list is **compiled into the binary**
and supplemented by the `facts/keys.json` file. The built-in list is the
ground of trust, and it changes with a release and only with a release.

Rotation without a release works like this: a new key arrives **signed by
the current one**. The node accepts the addition of a key only if the
signature on it verifies against a key it already trusts.

```json
{
  "format": 1,
  "keys": [
    {"key_id": "2026-a", "algo": "ed25519", "use": "facts",
     "public": "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
    {"key_id": "2026-b", "algo": "ed25519", "use": "facts",
     "public": "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
     "not_before": "2026-11-01"},
    {"key_id": "2026-p1", "algo": "ed25519", "use": "proposals",
     "public": "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
  ],
  "signed_by": "2026-a",
  "signature": "MEUCIQ…base64 Ed25519…"
}
```

Two limits, without which rotation turns into a way of substitution:

- **A key cannot be removed over the wire.** The list only grows;
  revoking a key is a release of the node. Otherwise whoever got to one
  key would revoke the rest and remain the only signer.
- **A built-in key is not redefined over the wire.** An arriving key with
  the same `key_id` but a different value is a refusal and a line in the
  log: it is either a mistake in our build or an attempt at substitution,
  and both need a human.

`use` separates keys by purpose: `facts` signs sets, `proposals` signs
[rule proposals](proposals.md). A key of one purpose is not good for the
other, and that is checked before the signature rather than after:
otherwise compromising the personal channel would let somebody forge the
base for everyone at once.

`not_before` lets a rotation be spread over time: the key travels ahead
of schedule, signing with it starts later, and by then it is already on
every node that fetched a manifest even once.

The machine-readable schema of the list is
[../../schema/keys.schema.json](../../schema/keys.schema.json).

## Downloading

Once a day plus jitter, a `GET` of the manifest with `If-None-Match`;
`304` means there is nothing to do. If the version is newer, the set is
downloaded.

The checks, in order; any one of them failing means "leave the previous
set in force and write to the log":

1. the manifest parses and contains a known `key_id`;
2. the signature verifies;
3. the `version` is **higher** than the current one — otherwise this is
   an attempt to roll back;
4. the `sha256` of the downloaded set matches the manifest;
5. the set parses whole and every record passes its checks.

Separately: if the new set is **much smaller** than the previous one —
say, half as many `protected` records — it is not applied without an
explicit confirmation. A shrunken base is more dangerous than a stale
one: a vanished row saying "do not touch this operator" turns a sensible
rule into a block on live people, and from the outside it looks like "the
site suddenly stopped opening".

## On disk

```
facts/
├── current          the applied version number, one line
├── 137.json         the applied set
├── 136.json         the previous one — for a rollback
├── 135.json         the one before that
└── keys.json        trusted keys beyond the built-in ones
```

Three versions are kept. A rollback is `antibot facts rollback`: it
rewrites `current` to the previous version and rereads it. No network is
needed for that, and that is a matter of principle: repairs happen when
something is already broken, and depending on the cloud being reachable
at that moment is not acceptable.

A node with no fact set at all is not hindered by this: rules that refer
to unknown facts simply do not match, and the rest work. An empty
`facts/` is not an error but the normal state of a node that was never
connected anywhere.

## The schemas

- [../../schema/fact-set.schema.json](../../schema/fact-set.schema.json) — the set;
- [../../schema/manifest.schema.json](../../schema/manifest.schema.json) — the manifest with the signature.

The node validates the set against the schema before applying it. A
record that fails validation discards the **whole** set rather than only
itself: a partially applied base is a state nobody checked and one that
cannot be reproduced while investigating an incident.
