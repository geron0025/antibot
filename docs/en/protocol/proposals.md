# The proposals channel: what the cloud proposes and the owner decides

Format version: **1**.

> In the current build the node neither fetches nor accepts proposals:
> there is no button in the admin UI and no `proposals/` directory yet,
> no advice and no node feedback. The format is fixed in advance, like
> the aggregate format.

The third road between the parts. The first two — the
[aggregate](aggregate.md) going up and the [fact set](fact-set.md) coming
down — carry observations and statements about the world. This one
carries a **draft of a rule**: the cloud analysed one subscriber's statistics
and proposes a rule they can accept with one button in their own admin
UI, or **advises** doing something with a rule that already works. In the
other direction it carries a short **node feedback**: what became of a
proposal.

## The border that does not move

**A proposal is a draft, not a command.** It cannot enable, block or
change anything by itself. Between a proposal and a working rule stands a
human, and there is no way to take them out of there — not with a
setting, not with an answer from the cloud.

This rests on three limits, each checked on the node:

1. **A proposal carries no mode.** There is no `mode` field in it at all
   — not "it must be `shadow`" but no way to express one. An accepted
   proposal is written into `shadow` always, because the node has nowhere
   else to take the value from.
2. **Acceptance is one at a time.** There is no "accept all" button in
   the admin UI, in the command line or in the configuration. No
   "accept automatically" setting exists, and its appearance would mean
   the cancellation of this document.
3. **The identifiers are separated.** The `id` of a proposed rule must
   start with `cloud-`; a rule written by the owner carries no such
   prefix. In `antibot rules list` it is visible where each came from.

The reason is not caution but arithmetic: one mistaken rule spread across
every installation is a simultaneous outage at every customer at once and
the end of the service. The ability to do that must not exist in the
code.

## How this differs from a fact set

| | Fact set | Proposal |
|---|---|---|
| For whom | the same for everyone | for one subscriber |
| What it carries | statements about the world | a draft of a rule |
| Signature | the distribution key | a **separate key** |
| Application | automatic, after the checks | only by the owner's hand |
| If not applied | the base goes stale | nothing happens |

Different keys are not pedantry. A fact set is signed by a key that hands
the same thing to everyone; a proposal is addressed. One key for both
channels would mean that compromising the proposals signature allows
forging the base for everyone at once.

The converse is true too and worth saying out loud: **compromising the
proposals key is limited in its consequences**. A forged proposal still
arrives as a draft, lands in `shadow` and starts cutting off nothing
until a human presses the button and looks at what it would have cut.

## A proposal in full

```json
{
  "format": 1,
  "node": "8f14e45fceea167a5a36dedd4bea2543",
  "created_at": "2026-09-09T04:00:00Z",
  "proposals": [
    {
      "id": "cloud-hosting-no-browser-2026-09",
      "created_at": "2026-09-09T04:00:00Z",
      "expires_at": "2026-10-09T00:00:00Z",
      "requires_facts_version": 137,
      "rule": {
        "id": "cloud-hosting-no-browser-2026-09",
        "name": "hosting without a browser handshake",
        "scope": ["shop.example.ru"],
        "priority": 100,
        "condition": {
          "all": [
            {"field": "network.class", "op": "eq", "value": "hosting"},
            {"field": "ua_matches_ja4", "op": "eq", "value": false},
            {"field": "network.age", "op": "gt", "value": 3}
          ]
        },
        "action": {"type": "block", "status": 403}
      },
      "why": "Over a week, 4128 requests from six networks of class hosting calling themselves Chrome, with the TLS fingerprint of the Go library. Not one request to robots.txt.",
      "evidence": {
        "window": "2026-09-02/2026-09-09",
        "requests": 4128,
        "share": 0.021,
        "networks": 6,
        "addresses": 143,
        "would_block": 4128,
        "would_block_protected": 0
      }
    }
  ]
}
```

### The fields of a proposal

| Field | What |
|---|---|
| `id` | with the `cloud-` prefix; the same `id` again is an update of the proposal |
| `expires_at` | after this date the node hides the proposal |
| `requires_facts_version` | the rule refers to facts; with an older set it will not fire |
| `rule` | a rule in the `rules.json` format, **without** `mode` and `enabled` |
| `why` | one sentence for a human: why this is proposed |
| `evidence` | numbers from **their own** statistics |

`evidence` is mandatory and must be verifiable on the spot. An owner who
receives "we propose to block, trust us" will not press the button — and
rightly so. So the numbers travel next to the proposal, and they are ones
the owner can reproduce themselves: `antibot replay` over their own log
must give the same values.

The most important of them is `would_block_protected`: how many requests
the rule would cut off from networks marked "do not touch". A non-zero
value is a reason not to propose at all, rather than a footnote in small
print.

`share` is the fraction of all requests over the window. A rule touching
a noticeable share of the traffic almost certainly touches people too:
that much traffic is never all bots.

## Advice

The second kind of record is **advice about a rule that already works**:
"the rule is cutting people, turn it off", "the rule touches protected
networks, move it back to `shadow`". A proposal adds a new rule; advice
adds nothing and changes nothing. The owner acts on it with the buttons
they already have.

The cloud does not know the `id`s of the owner's rules — in the aggregate
a rule is named by its [hash](aggregate.md) — so advice refers to a rule
**by hash**. The node shows the advice next to the rule that has that
hash now. With no rule of that hash — the owner changed or deleted it —
the advice is not shown: it was about another rule.

```json
{
  "format": 1,
  "node": "8f14e45fceea167a5a36dedd4bea2543",
  "created_at": "2026-09-09T04:00:00Z",
  "proposals": [],
  "advice": [
    {
      "id": "cloud-advice-cuts-people-2026-09",
      "created_at": "2026-09-09T04:00:00Z",
      "expires_at": "2026-09-23T00:00:00Z",
      "rule": "50c32b7c35cdaae8",
      "suggest": "disable",
      "why": "Over a week the rule cut 3104 requests, 2870 of them with a cookie, from telecom operators' networks. That is what people look like, not bots.",
      "evidence": {
        "window": "2026-09-02/2026-09-09",
        "requests": 3104,
        "share": 0.016,
        "with_cookie": 2870,
        "protected": 0
      }
    }
  ]
}
```

| Field | What |
|---|---|
| `id` | prefixed with `cloud-`; repeating the same `id` updates the advice |
| `rule` | the hash of the rule the advice is about |
| `suggest` | `disable` — turn off, `shadow` — move back to `shadow`, `review` — take a look |
| `why` | one sentence for a human |
| `evidence` | numbers from the aggregates for this rule: requests, share, how many with a cookie, how many from protected networks |

Advice has no field a rule could be written into: the format gives the
cloud no way to pass the node anything but text and numbers.

## Distribution

```
GET <facts.url>/proposals?format=1
Authorization: Bearer <token>
```

The same token as for the aggregates and the fact set. **Proposals have
no scope of their own**: `facts` (or `both`) covers both the bases and
the proposals — it is one direction, downwards, and splitting it further
would mean inventing an entity for the sake of symmetry. Access is
decided by the **subscription level**: proposals belong to the
`facts_and_analysis` level.

| Answer | What the node does |
|---|---|
| `200` | parses it, checks the signature, stores it |
| `304` | nothing |
| `401` | the token is no good: shows the previous proposals, retries in an hour |
| `403` | the wrong subscription level: the previous proposals stay, retries once a day |
| `429`, `5xx` | retry with a growing delay |

The signature is in the response headers, over the **bytes of the body**
as they arrived:

```
X-Antibot-Signature: 2026-p1:MEUCIQ…
```

Before the colon is the `key_id`, after it the Ed25519 signature over the
`sha256` of the body. A signature over bytes rather than over a parsed
document saves both sides from canonicalizing JSON: what is signed is
exactly what was sent.

The proposal keys live in the same `facts/keys.json` file and follow the
same rotation rules, but are marked `use: "proposals"`. The distribution
key is not good for proposals and the other way round — the purpose is
checked before the signature.

## What the node does

The checks, in order; any one failing means "keep the previous proposals
and write to the log":

1. the signature verifies against a key from the **proposals** list;
2. the `node` in the body matches this node's identifier — otherwise
   these are somebody else's proposals and must not be accepted;
3. the document passed validation against the schema;
4. every rule's `id` starts with `cloud-`;
5. every rule's `scope` is a domain this node serves, or `*`.

What passes is stored in `proposals/` next to `facts/`. The list arrives
whole: a proposal that vanished from the list is hidden by the node — the
cloud changed its mind.

### Accepting

The owner presses the button in the admin UI. The node:

1. appends the rule to `rules.json` with `mode: "shadow"` and enabled;
2. goes through the same write path as `antibot rules`: the same set
   validation, the same atomic replacement, the same line in the node's
   log — who accepted what;
3. marks the proposal accepted, so as not to propose it again.

After that the rule lives like any other: the owner watches it in
`shadow`, runs `antibot replay` and moves it to `active` **themselves**,
with the button on the rules page or `antibot rules mode`; the node
applies it without a restart. Moving to `active` is not part of this
channel.

### Declining

A declined proposal is hidden by the node, which remembers the refusal
locally and tells the cloud with the [node feedback](#node-feedback). The
cloud does not send such a proposal again; if it arrives anyway, the node
does not show it.

Decided on 25 September 2026. Before that a refusal was not reported
upwards: a channel from the node to the cloud for "the user pressed no"
was judged a bad trade. Once proposals are what people pay for, the trade
is different: without feedback the cloud keeps sending the same, the
model has nothing to learn from, and the owner has nothing to show what
was done.

## Node feedback

The node tells the cloud what became of each proposal and piece of
advice — and nothing else. Not a byte about visitors, not the text of
rules.

```
POST <cloud.url>/proposals/feedback
Content-Type: application/json
Authorization: Bearer <token>
```

The same cloud address and the same token as the aggregate, and the
feedback goes out only when sending aggregates is on: a node without a
token does not talk to the cloud at all.

```json
{
  "format": 1,
  "node": "8f14e45fceea167a5a36dedd4bea2543",
  "sent_at": "2026-09-12T10:00:00Z",
  "items": [
    {
      "id": "cloud-hosting-no-browser-2026-09",
      "state": "active",
      "at": "2026-09-11T18:20:00Z",
      "rule": "46ed921d7daceb83"
    },
    {
      "id": "cloud-advice-cuts-people-2026-09",
      "state": "rejected",
      "at": "2026-09-10T09:05:00Z",
      "reason": "these are our partners, it is meant to be so"
    }
  ]
}
```

| Field | What |
|---|---|
| `id` | the `id` of the proposal or advice |
| `state` | `accepted` — accepted, lies in `shadow`; `active` — the owner moved it to `active`; `disabled` — turned off; `removed` — deleted; `rejected` — declined; `done` — advice acted on |
| `at` | when it happened |
| `rule` | the rule's hash now — for an accepted proposal; the owner may have edited the condition, and the cloud keeps recognizing the rule by the new hash |
| `reason` | the reason in the owner's words, if they wrote one; up to 500 characters, optional |

`reason` is the only owner's text that leaves the node, and it leaves
only if the owner typed it into the "why" field when declining. The field
is labelled in the admin UI so that it is clear: the cloud will read this.

One feedback carries only the changes since the last accepted one. The
cloud's answers are as for the aggregate: `202` — accepted; `400`, `413`
— do not retry; `401`, `403` — sending sleeps for an hour; `429`, `5xx` —
retry with a growing delay. The schema is strict, like the aggregate's:
an extra field is `400`.

## What this channel does not have

- **No way to enable a rule.** `mode` cannot be expressed by the format.
- **No way to change somebody else's rule.** A proposal only adds a new
  one, with its own `id` prefix; it does not touch the owner's rules.
- **No way to change the node's settings.** No addresses, no networks, no
  ports, no own networks — the format has no fields for that.
- **No automatic acceptance.** Not by an answer from the cloud, not by a
  setting.

If one day something from that list is needed, it is a new document and a
new conversation, not a field in this format.

## The schema

The machine-readable schema is
[../../schema/proposals.schema.json](../../schema/proposals.schema.json).
The node validates the document against the schema before showing a
single proposal to a human. A proposal that fails validation discards the
**whole** list: a partially parsed list is a state nobody checked.
