# The network and fingerprint bases

A fact set is two bases: **networks** (who owns a range) and
**fingerprints** (what a client travels with). Nothing but statements
about the world is in it: no rules, no actions, no decisions.

The format is described in
[protocol/fact-set.md](protocol/fact-set.md) — it is shared
between the node and the update service and lives in the open part
deliberately: anyone must be able to see what exactly arrives at a node.

## The border that does not move

**A fact set cannot block anything.** It changes what a client is called
— what to do with such a client is decided by your rule. An arriving row
"this network is hosting" prohibits nothing until you have a rule about
hosting, and then it prohibits exactly what that rule says.

This is how it is built, not a promise. A delivery channel into somebody
else's production that can change the behaviour of the protection
directly will sooner or later take somebody's site down. Hence:

- the set is **signed**, an unsigned one is not applied;
- the set is **versioned**, the version is monotonic, a lower one is not
  accepted;
- previous versions are kept, a **rollback** is one command and needs no
  network;
- all of it **switches off** with the line `facts.enabled: false`.

## What the set fills in

| Rule field | What it means |
|---|---|
| `network.class` | `cloud`, `hosting`, `isp`, `mobile`, `crawler`, `proxy_pool`, `education`, `enterprise`, `unknown` |
| `network.owner` | who owns the range |
| `network.country` | a two-letter code |
| `network.protected` | **"do not touch this network at all"** |
| `network.age` | how many versions ago the row appeared |
| `family` | `chrome`, `firefox`, `safari`, `curl`, `python`, `go` |
| `ua_matches_ja4` | whether the claimed client agrees with the handshake |

`network.protected` is the most valuable thing in the base. It is set on
telecom operators with live subscribers and on confirmed search crawlers,
and it was obtained more expensively than everything else: to pick out 44
networks of one cloud pool the previous generation needed about eighty
whois queries, and along the way Vodafone, Reliance Jio, Charter, Sky UK,
Telefónica and Telstra had to be taken off the list of suspects — and
then PetalBot, Huawei's crawler, which looked like a pool of 226
addresses.

`network.age` is counted **in versions of the set**, not in days. A rule
may require a hold explicitly:

```json
{"all": [
  {"field": "network.class", "op": "eq", "value": "hosting"},
  {"field": "network.age", "op": "gt", "value": 3}
]}
```

The point is that the first wrongly classified range would kill somebody
else's site with the base, and the owner would not even understand what
changed — they did not touch their rules.

## About `ua_matches_ja4`

The field answers the question "does what the client called itself agree
with how it said hello". It accuses only when there are **grounds**:

| What is known | Value |
|---|---|
| the fingerprint is unknown | `true` |
| the `User-Agent` is unrecognized or empty | `true` |
| the client called itself a crawler | `true` |
| both are known and agree | `true` |
| both are known and contradict | **`false`** |

The default `true` means "there are no grounds to say the client is
lying". That is not politeness: a rule is written as "block those whose
`ua_matches_ja4` is false", and a node that accuses everyone it does not
recognize would block the whole internet the moment such a rule is
enabled.

**A self-declared crawler is never accused.** A real Googlebot renders
pages with Chromium and its handshake looks like Chrome; calling that a
lie would cost the site its position in search results. Verifying such a
claim needs **verified networks** (`network.protected`,
`network.class == "crawler"`), not this comparison. That is exactly why
the admin UI shows "called themselves crawlers" as a separate block and
says honestly that it cannot check it.

## Applying from disk

```bash
antibot facts apply /path/to/137.json
antibot facts status
antibot facts rollback
```

`apply` looks for the manifest next to it — `137.manifest.json` — or
takes the path from `-manifest`. Five checks run, in the protocol's
order:

1. the manifest parses and names a **trusted** key;
2. the signature verifies — with a key that signs sets, not proposals;
3. the version is **higher** than the current one, otherwise this is an
   attempt to roll back;
4. the `sha256` of what was downloaded matches the manifest;
5. the set parses whole and every record passes.

Any one of them failing means "leave the previous set in force and write
to the log".

### A shrunken base

Beyond the five checks: a set that lost **half** of its networks or half
of its `protected` rows is not applied without `-force`.

A shrunken base is more dangerous than a stale one: a vanished row saying
"do not touch this operator" turns a sensible rule into a block on live
people, and from the outside it looks like "the site suddenly stopped
opening".

### Rolling back

```bash
antibot facts rollback
```

Returns to the previous of the three versions kept on disk. **No network
is needed for this**, and that is the point: a rollback is done when
something is already broken, and depending on the update service being
reachable at that moment is not acceptable.

## On disk

```
facts/
├── current          the applied version number, one line
├── 137.json         the applied set
├── 136.json         the previous one — for a rollback
├── 135.json         the one before that
└── keys.json        trusted keys beyond the built-in ones
```

Three versions are kept: a rollback has to be possible not immediately
but when the mistake was noticed — and somebody else's disk is not ours
to fill.

## Keys

Trusted keys live in two places: the list is **compiled into the binary**
and supplemented by the `keys.json` file. The built-in one is the ground
of trust, and it changes only with a release of the node.

Rotation without a release: a new key arrives **signed by the current
one**. Two limits, without which rotation turns into a way of
substitution:

- **a key cannot be removed over the wire** — the list only grows;
  revoking a key is a release. Otherwise whoever got to one key would
  revoke the rest and remain the only signer;
- **a built-in key is not redefined over the wire** — an arriving key
  with the same `key_id` but a different value means either a mistake in
  the build or an attempt at substitution, and both need a human.

> In the current build the built-in list is **empty**: the signing key
> does not exist yet. That is not a hole — with no trusted key nothing
> verifies, and the node works on rules that do not reference facts.

## An empty directory is a normal state

A node with no set at all is not hindered by it: rules referring to
unknown facts simply do not match, and the rest work. An empty `facts/`
is the ordinary state of a node that was never connected anywhere.

`antibot facts status` on such a node says exactly that.

## Fetching over the network

```yaml
facts:
  enabled: true
  dir: "/var/lib/antibot/facts"
  url: "https://updates.example.com/facts"
  interval: 24h
cloud:
  token: "ab_…"
```

Once a day plus jitter of up to a tenth: without it every installation
started from the same image asks at the same second, and the update
service sees a daily spike of its own making.

To check by hand without waiting for the schedule:

```bash
antibot facts fetch
```

The same code that runs on the schedule, not a second path to the same
place.

| Answer | What happens |
|---|---|
| `304` | nothing, the same version |
| `401` | the token was not accepted: **works on the previous set**, retries in an hour |
| `402`, `403` | the subscription does not cover the bases: **the base freezes, the protection stays**, retries once a day |
| `404` | no set has been published yet: nothing changes, retry with a growing delay |
| `429`, `5xx` | retry with a growing delay from a minute up to six hours |

The rows about `401` and `403` are the main ones. A subscription that ran
out **does not lift the protection**: the rules stay in force, the
network classes stay known, only their freshness goes stale. The opposite
design would mean an unpaid invoice opens somebody's site to bots.

The token comes from `cloud.token`, one for both directions. `facts.url`
without a token is an error at startup: there is no anonymous
distribution, and a node that quietly does not fetch looks exactly like
one that fetches and finds nothing new.

The node creates the installation's identifier itself on the first run
and keeps it in `node_id_file`. The cloud needs it for exactly one thing
— telling installations apart. When fetching the bases the node reports
no domains, no addresses and no composition of rules about itself.
Aggregates, if sending them is switched on, carry the domain and the
network prefix, `/24` or `/48` — what exactly goes with them is described
in [protocol/aggregate.md](protocol/aggregate.md).

The distribution is described in full in
[protocol/fact-set.md](protocol/fact-set.md), the section on
distribution by token.
