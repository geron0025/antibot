# The cloud: two checkboxes and nothing beyond them

The node works on its own. It terminates TLS, takes fingerprints,
applies your rules and writes events to disk — and none of that needs
the cloud.

There are exactly two things it can do with the cloud, and both only if
you say so. Both are off until you tick them yourself: at your first
login the admin UI asks the two questions, and until they are answered
the node does neither.

| Checkbox | What it means |
|---|---|
| **Receive security updates** | once a day the node downloads a signed set of facts: which networks belong to hosting providers, which addresses are a search engine's real crawler, which fingerprint belongs to which browser. Facts about **what a client is called** |
| **Send statistics** | every fifteen minutes the node sends counters: network prefixes, client families, fingerprints, how many requests and how many were blocked |

What goes out, and what **never** does, is in
[protocol/aggregate.md](protocol/aggregate.md). Full addresses,
`User-Agent` strings, paths, headers, cookies and bodies are not there
and cannot be. Neither are your rules: a rule that fired is named by a
hash of what it does, not by its `id` or its condition. The hash of your
rule is shown by `antibot rules list`.

## What an update of the bases cannot do

A fact set changes only what a client is called. What to do with such a
client is decided by **your rule** and by nothing else. The cloud cannot
switch a rule on at your node: there is no such method in the code, in
this repository or in the closed one.

A set not signed by a key built into this binary is refused and the
previous one stays in force — [facts.md](facts.md).

## The node takes its own token

Both arrows of the wire need a token. A ticked checkbox is the request
for one: the node introduces itself to the cloud, receives a token of
the free level and writes it down. Nothing to copy, nobody to write to.

What goes out in that single request without a token — the
installation's identifier, the node's version and what you ticked — is
described in [protocol/registration.md](protocol/registration.md).

The free level gives the crawlers from the lists their owners publish
about themselves: Google, Bing, Apple, Yandex and the rest. Network
classes, carriers whose ranges must never be cut, proxy pools and
fingerprints come with a subscription.

## Where it lives, and what outranks what

The answer and the token live in `cloud.json`, beside the node's other
state, with mode `600`: there is a token in it.

```yaml
cloud:
  link_file: "/var/lib/antibot/cloud.json"
  # register_url: "https://updates.netbota.ru"   # where to ask
```

**The settings file outranks the page.** If `config.yaml` names
`cloud.token`, the file decides: both arrows are on, and the checkboxes
are shown but change nothing. The domains and the certificates work the
same way — what the machine's owner wrote by hand is not overridden from
a browser.

| What | Where it comes from |
|---|---|
| the token | `cloud.token`, else `cloud.json` |
| the address of the sets | `facts.url`, else the one the cloud sent |
| the address for aggregates | `cloud.url`, else the one the cloud sent |

The addresses arrive in the answer to the registration rather than being
compiled in: moving the service must not require a release of the node.

## On and off at once

Tick it and it starts, clear it and it stops; the node needs no restart.
The Cloud tab of the admin UI's settings shows what is going on: whether there is a token, what
the tenant is called in the cloud, which version of the set is applied,
when the last batch went and what went wrong with it.

**Forget the token** is a separate button on the same page: it clears
both checkboxes and wipes the token. After that the node does not talk
to the cloud at all, and coming back means registering again — and the
cloud issues one token per installation, so that is a case for writing
to us.

## A third thing — only on the paid subscription to analysis

The `facts_and_analysis` subscription level opens a third channel on top
of the two checkboxes: proposals. The cloud analyses the owner's own
traffic and sends drafts of rules and advice about the ones already at
work — [protocol/proposals.md](protocol/proposals.md). The node fetches
them in the same cycle as the base's update, at the same address and
with the same token: `GET <facts.url>/proposals?format=1` right after
`/keys`. A lower level gets `403` for this, and it does not affect the
base's own update at all — the proposals channel has its own, separate
error policy.

The owner looks at the proposals and advice on the "Rules → Proposals"
tab ([admin.md](admin.md)) and decides: accept — the rule lands in
`shadow` — or reject, with a reason or without one. The decision goes
back up as a short line, but only while the second checkbox, "Send
statistics", is also on: a `POST` to `<cloud.url with /ingest removed>/proposals/feedback`,
with the same token.

On disk: `proposals.json` and `proposal-decisions.json` live next to
`rules.json`, in its own directory; `proposals-feedback.json` lives in
`cloud.state_dir`, next to the aggregate's own outgoing batches.

## When the subscription ends

The bases freeze, the defence stays. The rules go on working on the set
already applied; only its freshness goes stale.
