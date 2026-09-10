# The admin UI

Shows events, statistics and rules. It can change **exactly one** thing:
enable or disable an already written rule.

It exists because an antibot whose work is invisible never gets put into
blocking mode: a human first looks at whom the node is about to cut off,
and only then allows it to do so.

## Creating a login

```bash
antibot admin passwd owner    # asks for the password twice, without echo
antibot admin list
antibot admin remove owner
```

The password is not passed as a flag and not read from an environment
variable: from the command line it stays in the shell history and is
visible in the process list to anyone sitting on the same machine.

**Without a single account the admin UI does not come up.** The node
works meanwhile and writes what to do into the log:

```
level=WARN msg="the admin UI is not up: there are no accounts"
  file=/var/lib/antibot/admin.json what to do="antibot admin passwd NAME"
```

A password shorter than twelve characters is not accepted. Twelve rather
than eight: one day the admin UI will be exposed to the outside, whatever
the documentation says.

## The pages

| Address | What |
|---|---|
| `/` | overview: how many requests, who was not let through, what the node does not know |
| `/events` | events with filters |
| `/rules` | rules in the order of application, with how often they fired |
| `/login` | the login |

### Overview

Tiles: requests, addresses, who was not let through, the site's 5xx, the
median and p95 of the site's answer time, the volume sent, the rules in
force.

A ring of **answers** and a **chart of requests over time**, in the same
colours. Every answer falls into one class: the site's 2xx, 3xx, 4xx and
5xx, "not let through by the node", and "no status" — events written
before the field existed. What a rule cut off is a class of its own
rather than a 403 among the 4xx: otherwise the node doing its job would
look like the site breaking, and a human would go looking for a page that
never broke. The node's own 404 for an unknown host and its 502 for a
silent upstream count as the site's answers: to the visitor there is no
difference.

The answer time is counted only over the requests that reached the site.
The node answers a block in microseconds, and blocks would pull every
percentile to zero exactly when the node is busiest. A percentile is read
off a histogram and is accurate to a quarter — enough to tell 40 ms from
400.

Breakdowns: the site's answer codes, paths, paths with 5xx and with 4xx,
rules, shadows, addresses, fingerprints, `User-Agent`s and hosts. A click
on a breakdown row or on an answer class opens the events with that
filter.

The charts are drawn on the server as SVG. The admin UI's CSP forbids
inline styles, and the browser silently drops a bar sized with
`style="height: …"`, while SVG geometry lives in attributes the CSP does
not touch. Under the chart are the same numbers as a table: a hover
tooltip adds to them, it does not replace them.

A separate block is **what the node does not know**: the share of
requests without a network class, the share of nameless fingerprints, and
the clients that called themselves a known crawler.

This is not decoration. While half the traffic has no network class, a
rule has to be written blind — by the address and the `User-Agent`
string, that is, by what the client says about itself. And "called itself
Googlebot" is something the node cannot verify: anyone at all can put
that string on themselves, and the admin UI says so plainly instead of
pretending it recognized anybody. Telling a real crawler from an impostor
needs verified networks — [facts.md](facts.md).

### Events

The filters combine with "and": host, address, rule, `ja4`, decision,
answer code and a substring search in the `User-Agent` or the path. The
last 200 events, newest first.

The answer code is either exact (`404`) or a class (`5xx`, `blocked`). A
class means the same as on the overview: `4xx` is the site's 4xx without
the rules' 403s, otherwise a click on the ring would show something other
than what was counted.

A click on an address, a rule or a fingerprint is a filter by it: going
through them one by one starts here.

### Rules

In the **order of application**, not the order of the file: a human looks
here when working out why the wrong thing fired. Next to each — how many
times it fired over the period and from how many addresses; the numbers
come from the log rather than from in-memory counters, because after a
restart the counters reset while the log stays.

The enable/disable button is the single writing action in the whole admin
UI.

## The single writing action

A rule that is cutting off live people gets turned off in the minute it
is noticed, not when somebody finds where `rules.json` lives on somebody
else's server. Hence the button.

There is no condition editor for the opposite reason: the admin UI stands
on somebody else's perimeter, and a hole in it must not become a hole in
the site's protection.

The toggle itself goes **through the same file write and the same set
validation** as `antibot rules`: the rules file has no second writer, just
as the matcher has no second engine. The file is reread before the edit —
it may have been changed by hand. Who toggled what goes into the node's
log: a change of protection does not happen anonymously.

```
level=INFO msg="a rule was toggled from the admin UI"
  rule=block-hosting enabled=false who=owner address=127.0.0.1
```

## The borders

- **a login is mandatory**, the password is stored as a
  PBKDF2-HMAC-SHA256 hash with 600,000 iterations; guessing is limited by
  address — ten attempts per five minutes;
- **loopback by default**. A non-loopback address without a certificate
  is a **refusal at startup**, not a warning: the password would travel
  the network in clear text, and that is not an inconvenience but access
  already granted;
- **CSRF by double submission**: a random value in a cookie and in a
  hidden form field. Together with `SameSite=Strict` that is enough;
- **no JavaScript of our own at all**, the CSP forbids everything
  external, the pages are assembled on the server, the templates and the
  stylesheet are compiled into the binary;
- **sessions in the process's memory** — a restart logs everybody out,
  and that is more correct than keeping on disk something that can be
  logged in with;
- **`X-Robots-Tag: noindex`** — the admin UI shows the events of somebody
  else's site, it has no business in search results;
- **exactly one write path**: any method other than GET is not handled on
  the pages.

## Exposing it

By default the admin UI listens on loopback, and that is the right mode:
look at it through `ssh -L 8090:127.0.0.1:8090`.

If it must face outwards, a certificate is mandatory:

```yaml
admin_ui:
  listen: "0.0.0.0:8090"
  certificate: "/etc/letsencrypt/live/admin.example.ru/fullchain.pem"
  key: "/etc/letsencrypt/live/admin.example.ru/privkey.pem"
  redirect_from: ":8089"
```

Without a certificate the node **will not start** — it does not "warn",
it refuses to bring the listeners up at all. The check runs before the
ports are taken: the admin UI on `0.0.0.0` used to bring the node down a
second after startup, having managed to accept requests.

## What the admin UI does not have

- a rule editor — conditions are composed with a command;
- editing the settings;
- creating accounts — only `antibot admin passwd`. Changing a password
  through the admin UI would mean that whoever stole a session takes the
  access for good;
- exporting events and a page for a single rule — simply not written yet.

Accepting rule proposals from the update service will become the
**second** writing action when it appears; the rule will land in
`shadow`, and enabling it will still be a human's job.
