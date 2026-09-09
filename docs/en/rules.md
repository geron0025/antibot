# Rules

A rule is a condition and an action. The condition refers to **facts**
rather than listing addresses:

```json
{
  "id": "hosting-without-browser",
  "name": "hosting without a browser handshake",
  "scope": ["shop.example.ru"],
  "mode": "shadow",
  "priority": 100,
  "condition": {
    "all": [
      {"field": "network.class", "op": "eq", "value": "hosting"},
      {"field": "ua_matches_ja4", "op": "eq", "value": false}
    ]
  },
  "action": {"type": "block", "status": 403}
}
```

That way the rule survives a pool moving: ranges change owners all the
time, and a list of fifty prefixes inside a rule goes stale silently —
and it is precisely a silently stale rule that one day starts cutting off
live people.

## The condition

A tree of `all`, `any`, `not` and comparisons `{field, op, value}`. A node
is either **composite** (exactly one of `all`, `any`, `not`) or a
**comparison**. Mixing is not allowed: a node with both `all` and `field`
filled in reads two ways, and one day it will be read the wrong one.

Not an expression with a syntax of its own — this form is checked by a
schema, a machine composes it more reliably, and the node does not carry
one more language to maintain and fuzz separately.

**Everything that will never match is a parse error, not silence.** An
unknown field, an operator not meant for the kind, `cidr` over a string,
`contains` with an empty string — the rule will not take effect, and the
node says where exactly:

```
condition.all[1]: the field "ja44" does not exist; available: alpn, family, grease, h2, …
```

### Fields

```bash
antibot rules fields
```

| Field | Kind | Where from |
|---|---|---|
| `ip` | address | the client's real address |
| `host` | string | the domain name, normalized |
| `method`, `path`, `proto` | string | from the request |
| `ua`, `referer` | string | from the headers |
| `ja3`, `ja3_hash`, `ja4` | string | the TLS fingerprint |
| `sni`, `alpn`, `tls` | string | from the handshake |
| `grease` | bool | the client sent GREASE |
| `h2` | string | the HTTP/2 fingerprint |
| `headers`, `headers_hash` | string | the header composition |
| `family` | string | **from the fact set**: chrome, curl, go… |
| `ua_matches_ja4` | bool | **from the fact set** |
| `network.class` | string | **from the fact set**: hosting, isp, mobile… |
| `network.owner`, `network.country` | string | **from the fact set** |
| `network.protected` | bool | **from the fact set**: "do not touch at all" |
| `network.age` | number | **from the fact set**: how many versions old the row is |

The ones marked "from the fact set" are empty until a set is applied —
[facts.md](facts.md). A rule referring to them simply does not match
until then.

The exception is `ua_matches_ja4`: it is a bool and cannot be empty. Its
default is `true`, "there are no grounds to say the client is lying".
Otherwise a rule like `ua_matches_ja4 == false` would block every visitor
on a node with no bases.

### Operators

| Field kind | Operators |
|---|---|
| string | `eq`, `ne`, `in`, `not_in`, `contains`, `prefix`, `suffix` |
| address | the same plus `cidr`, `not_cidr` |
| bool | `eq`, `ne` |
| number | `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in` |

`cidr` takes a list of networks. An unmasked network works the way a
human reads it: `203.0.113.7/24` is `203.0.113.0/24`. An address that
does not parse falls into **no** network: otherwise a request without an
address would pass `not_cidr` anywhere.

An empty string is an ordinary value, not "unset". The caveat "the client
did not identify itself" rests on it:
`{"field": "referer", "op": "eq", "value": ""}`.

## The scope

`scope` is the domains a rule applies to: `["*"]`, exact names or
`"*.example.ru"` (the domain itself and all its subdomains). Mandatory
from day one: a node serves more than one site, and a rule written for
one is usually harmful on the rest.

## Modes

| Mode | What it does |
|---|---|
| `shadow` | the match is written into the event's `shadow` field, the request goes on |
| `active` | the rule renders a decision, the walk stops on it |

**A new rule is turned on only through `shadow`.** A watching rule is
useful exactly because somebody reads it: the shadows that fired land in
the event and in the admin UI's summary, and by them you see whom the
rule would have touched.

`mode` is mandatory. An absent `enabled` means "enabled", and that is
safe exactly because the mode has to be set: a rule cannot end up
`active` by an oversight.

## Actions

```json
{"type": "block", "status": 403, "body": "Access denied"}
{"type": "allow"}
{"type": "ratelimit", "limit": 60, "window": "1m", "key": "ip"}
```

`allow` is required as an action of its own — see the exceptions below.

## The order of application

The **first rule that fires in `active` mode** wins, in decreasing order
of priority. At equal priorities the order is set by the `id` rather than
the place in the file: swapping two lines must not change the decisions,
otherwise the replay over history and the hot path diverge for no reason
at all.

From this follows how exceptions are made: **not** by a negation inside
every prohibition, but by an allowing rule higher in priority.

```json
{"id": "allow-monitoring", "priority": 200, "action": {"type": "allow"},
 "condition": {"field": "ip", "op": "cidr", "value": ["203.0.113.0/24"]}}
```

An exception written into ten prohibitions will one day be forgotten in
the eleventh — and nobody will notice, because a forgotten exception
shows nothing of itself.

## The rate limiter

A sliding window **in the process's memory**. Which means:

- with `N` replicas of the node the limit is effectively multiplied by
  `N`;
- after a restart the count starts over.

Said plainly, because otherwise it is discovered through somebody else's
complaint. A shared counter would need the very storage the node was
designed without.

Rejected requests are not counted: a client that stops being frequent
leaves the limit after one window rather than staying under it for as
long as it keeps sending.

`key` is the field to count by, `ip` by default. Only string fields will
do: counting frequency by a bool means two buckets for all the traffic.
The limit is bounded from above (`1048576`): a limit of a billion would
mean not a lenient rule but eaten memory.

A `ratelimit` that fired without exceeding its limit **stops the walk** —
the request passes marked with that rule. A prohibition of lower priority
over the same clients will not apply in that case; this cost a
post-mortem in the previous generation, hence it is said out loud.

## Replaying over history

```bash
antibot replay -for 24h -examples 5
```

It exercises the **very same** matcher the hot path runs, not an SQL
translation of it. So "it showed one thing on history and did another in
production" is impossible here in principle.

What it shows:

- how many requests received each decision;
- **divergences** from what the events recorded: `pass→block` is exactly
  "how many live people the new rule will cut off";
- per rule: how many matched, the share, how many addresses, hosts and
  distinct `User-Agent`s;
- examples one by one, if you ask for `-examples`.

A rule touching more than a percent of the requests is flagged with a
warning: that much traffic is never all bots.

In a replay the rate limiter counts **by the events' time**, not by the
machine's clock, otherwise the numbers are not the ones production saw.

## The command line

```bash
antibot rules list                      # in the order of application
antibot rules add < rule.json           # validated before the write
antibot rules enable ID
antibot rules disable ID                # switch off without deleting
antibot rules remove ID
antibot rules check                     # validate the file, change nothing
antibot rules fields                    # fields and operators
```

The file is replaced whole and atomically; the node notices the change
and rereads the set without a restart. **A broken rule discards the whole
set**, and the previous one stays in force.

Rules are changed only this way — with a command. The one exception is
the enable/disable button in the admin UI, and it goes **through the same
write and the same validation**: the rules file has no second writer.

There is no way to enable a rule from the outside, and there will not be
one.
