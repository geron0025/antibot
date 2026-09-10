# The proposals channel: what the cloud proposes and the owner decides

Format version: **1**.

> In the current build the node neither fetches nor accepts proposals:
> there is no button in the admin UI and no `proposals/` directory yet.
> The format is fixed in advance, like the aggregate format.

The third road between the parts. The first two — the
[aggregate](aggregate.md) going up and the [fact set](fact-set.md) coming
down — carry observations and statements about the world. This one
carries a **draft of a rule**: the cloud analysed one subscriber's statistics
and proposes a rule they can accept with one button in their own admin
UI.

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
by editing `mode` in `rules.json`; the node rereads the file without a
restart. Moving to `active` is not part of this channel.

### Declining

A declined proposal is hidden by the node, which remembers the refusal
locally. Nothing about it is reported upwards: there is no channel from
the node to the cloud in this protocol other than the aggregate, and
inventing one for "the user pressed no" is a bad trade. The cloud will
keep sending the proposal for as long as it considers it appropriate; on
the node it will not be seen.

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
