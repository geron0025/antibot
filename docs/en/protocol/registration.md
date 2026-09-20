# Node registration: how a node gets a token

Format version: **1**.

Like the rest of this folder, this document was fixed before the code,
and it lives in the open part on purpose: registration is the only
request a node makes **before** it has a token, and anybody should be
able to see what goes out in it.

## Why it exists

A token is needed for both arrows of the wire: without one the node
receives no fact sets and sends no aggregates. While tokens were issued
by a human, the customer's path ran through correspondence with us — and
the measure of stage 1 reads "installed it himself, without our help".
Registration removes the correspondence: the node introduces itself to
the cloud and gets a free-level token.

**Registration turns nothing on.** It obtains a token, and that is all.
What to do with it is decided by the owner's checkboxes in the node's
admin UI; until they are ticked the node sends nothing anywhere and
downloads nothing. The token on its own changes not one byte of the
node's behaviour.

## The request

```
POST /register
Content-Type: application/json
```

With no `Authorization` header: there is no token yet, which is the
whole point.

```json
{
  "format": 1,
  "node": "01JB8Z0K4W9Q7N2M5T6X8YV3PR",
  "version": "v0.6.0",
  "facts": true,
  "aggregates": false
}
```

| Field | Type | What |
|---|---|---|
| `format` | integer | format version, currently `1` |
| `node` | string | the installation's identifier — the same one the aggregate carries |
| `version` | string | the node's version, as `antibot version` prints it |
| `facts` | boolean | the owner ticked "receive security updates" |
| `aggregates` | boolean | the owner ticked "send statistics" |

`facts` and `aggregates` commit to nothing and restrict nothing: the
token is issued with the `both` scope either way. They answer the
question of what the node came for — the only chance to learn what
people actually want from the cloud, and worth one boolean field.

Both `false` is a valid request: the owner may have cleared both
checkboxes and still wanted an account for later.

## What the request does not carry

| Not sent | Why |
|---|---|
| The protected domains | the cloud learns them from aggregates, and only if the owner switched sending on |
| The owner's mail and name | registration starts no correspondence; contact details are added in the cloud's admin UI, if the owner leaves them himself |
| Rules and their text | they never leave the node, in any request |
| Visitors' addresses | there are none here by definition |

The cloud does see **the address the request came from** — the owner's
own server, not his visitors. It is recorded: without it there is no way
to bound the number of registrations from one place. The recorded
address is visible in the cloud's admin UI and nowhere else.

## The answer

`201 Created`:

```json
{
  "format": 1,
  "token": "ab_2f9c1d8e7b6a5c4d3e2f1a0b",
  "scope": "both",
  "level": "node",
  "tenant": "node-01JB8Z0K",
  "facts_url": "https://updates.netbota.ru/facts",
  "ingest_url": "https://updates.netbota.ru/ingest"
}
```

| Field | What |
|---|---|
| `token` | the token value; **shown once**, the cloud keeps only its hash |
| `scope` | the token's scope: `both` — good for sets and for aggregates alike |
| `level` | the subscription level: `node`, the free one |
| `tenant` | what the tenant that was created is called; the owner needs it to name himself when he writes to us |
| `facts_url` | where to fetch fact sets from |
| `ingest_url` | where to send aggregates |

The addresses arrive in the answer instead of being compiled into the
node, for the same reason a fact set is versioned: moving the service
must not require a release of the node. If the node's configuration
names the addresses by hand, the configuration wins: the owner keeps the
last word on where his node goes.

A lost token is not reissued along this path, see `409` below. So the
node writes it down at once, before it tells the owner that all went
well.

## What the free level gives

Level `node` receives **the free stream only** — the crawlers from the
lists their owners publish about themselves: Google, Bing, Apple, Yandex
and the rest ([fact-set.md, "Two streams"](fact-set.md#two-streams)).
Network classes, `protected` for carriers with live subscribers, proxy
pools and fingerprints are behind a subscription.

Aggregates from a free tenant are accepted. They do not reach the
catalogue until a human confirms the tenant: otherwise self-registration
would be a way of rewriting the catalogue for everybody — one command to
create a hundred nodes and tell the cloud that a farm's network belongs
to a carrier.

## Refusals

| Code | When | What the node does |
|---|---|---|
| `400` | the body does not parse, `node` is missing, the format is another | shows the owner the error text; retrying is pointless |
| `409` | this installation is already registered | tells the owner a token was issued before and a new one needs us |
| `429` | too many registrations from this address in a day | waits out `Retry-After` and offers to try later |
| `503` | the cloud cannot answer | offers to retry; the checkboxes are not lost meanwhile |

The refusal body is the same as for the cloud's other endpoints:

```json
{"error": "this installation is already registered"}
```

`409` rather than a new token, because the cloud keeps only a hash and
cannot show the old token again, while issuing a second one would mean
that anybody who knows somebody else's `node` gets a token in their
name. An installation that lost its token is a case for a human, and a
rare one.

## Registering again, and reinstalling

The installation's identifier lives in a file beside the node's state.
Remove the node together with its state and the identifier is new, and
registration goes through as a first one: this is a new installation,
and the cloud cannot tell it from any other new one. The tenant stays
the same in one case only — when the owner carried the file with the
token over himself.

The limit on registrations from one address is chosen so as not to
hinder the honest "brought it up, tore it down, brought it up again":
five a day.
