# The admin UI

Shows events, statistics, rules and domains. It can change a few things,
and all of them are listed: enable or disable an already written rule,
add or remove a domain, upload a ready-made certificate for a site or for
the admin UI itself, issue and revoke an [API](api.md) token, set the
[alerts](alerts.md) command.

It exists because an antibot whose work is invisible never gets put into
blocking mode: a human first looks at whom the node is about to cut off,
and only then allows it to do so.

## A program of its own

The admin UI is not a part of the core but a program of its own,
`antibot-admin`, with its own settings (`admin.yaml`, the sample is
[deploy/admin.example.yaml](../../deploy/admin.example.yaml)) and under
its own user. The core's binary holds none of its code at all: no
templates, no passwords, no file uploads. A vulnerability in the admin UI
cannot end up in the process that carries the site's traffic.

The core does not need the admin UI: with rules already written it works
on its own, and then `antibot-admin` need not be installed on the machine
at all. When the admin UI is there, it knows only three things about the
core:

- **the control socket** — the core's `listen.control`, mode `0660`.
  Through it the admin UI asks about what lives only in the core's
  memory: the alerts, the link to the cloud, the certificates it hands
  out, its version and start time. The list of questions is closed and
  short; nothing more can be had through the socket — neither the core's
  memory nor its `config.yaml` with the cloud token;
- **the events** — the log directory, read only;
- **the shared files** in `/var/lib/antibot/shared`: the rules, the
  domains, the alerts command, the uploaded site certificates. The admin
  UI writes them with the same code as the `antibot rules` and
  `antibot domains` commands, and asks the core to reread the file right
  away.

The permissions are laid out so that the admin UI cannot reach anything
else:

| What | Owner | Mode | For the admin UI |
|---|---|---|---|
| `/var/lib/antibot` | the core | `0750` | read: the events and the socket |
| `/var/lib/antibot/shared` | the core | `0770` | write |
| `cloud.json`, `node.id`, the self-signed certificate's keys | the core | `0600`/`0640` | neither reads nor replaces |
| `/var/lib/antibot-admin` — accounts, API tokens, the admin UI's certificate | the admin UI | `0700` | its own; out of the core's reach |

The core and the admin UI are two users of one group, `antibot` and
`antibot-admin`. Shared writing is allowed only in `shared`: an atomic
file replacement needs write permission on the file's directory, and
were that granted on the whole of `/var/lib/antibot`, the admin UI could
replace the cloud token.

**The core is down — the admin UI works.** Every page then says the core
is not answering. The events, the rules and the domains are visible and
can be changed: they live in files, and the core takes the edit up when
it comes back. The alerts, the cloud and the sites' certificates are not
shown until it returns. A fallen core is brought back by its supervisor —
systemd or docker — not by the admin UI: it has no rights over another
process, and must not have them.

## Creating a login

```bash
antibot-admin accounts passwd owner    # asks for the password twice, without echo
antibot-admin accounts list
antibot-admin accounts remove owner
```

The password is not passed as a flag and not read from an environment
variable: from the command line it stays in the shell history and is
visible in the process list to anyone sitting on the same machine.

**Without a single account the admin UI does not start** — and says what
to do. The core works meanwhile: it does not depend on the admin UI.

```
level=ERROR msg="stopped with an error"
  err="there are no accounts: create one with `antibot-admin accounts passwd`"
```

A password shorter than twelve characters is not accepted. Twelve rather
than eight: one day the admin UI will be exposed to the outside, whatever
the documentation says.

## Language

The admin UI speaks Russian and English. The language of a page is chosen
so:

1. the switch in the account menu and on the login page — the choice is
   remembered in this browser for a year, in the `antibot_lang` cookie;
2. otherwise the browser's language, the `Accept-Language` header;
3. otherwise `language` from [admin.yaml](configuration.md#adminyaml--the-admin-uis-settings),
   `en` by default.

English comes with US formats: `09/25/2026`, `1,234`, `12.5%`. Russian —
`25.09.2026`, `1 234`, `12,5 %`. The time of day is 24-hour in both: it is
a log, and AM and PM get in the way there.

What the admin UI itself writes is translated, and so are the core's
alerts: the bell, the overview and the alerts page show them in the
language of whoever looks, while the delivery command gets them in a
language of its own — see [Alerts](alerts.md#language). These stay as
they are:

- **errors from the code** — of parsing a rule, a domain, a certificate,
  the core's answers. They land in the log too, and are easier to search
  for there in one spelling. The frame around them is translated:
  "the certificate chain: …";
- **values from the files and the protocol** — the modes `shadow` and
  `active`, rule actions, decisions in events, the token scopes `read` and
  `write`;
- the [API](api.md) and the admin UI's log.

The translations live in `internal/admin/locales/`, a file per language.
They are checked at startup: the same keys in every language, every
plural form, the same placeholders — otherwise the admin UI does not
start. Tests make sure no text in the templates bypasses the
translations.

## The pages

| Address | What |
|---|---|
| `/` | overview: how many requests, who was not let through, what the node does not know |
| `/events` | events with filters |
| `/events/export` | a download of the events with the same filters, as the log's lines |
| `/rules` | rules in the order of application, with how often they fired |
| `/rule?id=…` | one rule: its firings over time, whom it touched, the latest events |
| `/rules/crawlers` | rules, verified crawlers: whether they pass before the rules, who came, what was cut |
| `/domains` | domains, their sites' addresses, certificates and terms |
| `/alerts` | alerts: the triggers and their thresholds, what is firing now, the messages |
| `/settings/core` | settings, the core: whether it answers, the version, the start time, a restart |
| `/settings/tokens` | settings, API tokens: issuing, terms, the last use, revoking |
| `/settings/cloud` | settings, the cloud: two checkboxes, the token, how both arrows fare |
| `/settings/alerts` | settings, alert delivery: the command and a test message |
| `/settings` | settings, the admin UI's own certificate: names, term, files, replacing |
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
Googlebot" is a string anyone at all can put on themselves. So every
self-declared crawler has two columns: **from a crawler network** — the
request came from a range the crawler's owner publishes about itself,
which arrives with the fact set — and **not confirmed**. Without a set
there is nothing to confirm against, and the admin UI says so plainly
instead of pretending it recognized anybody. The **cut off** column is
how many requests from crawler networks the node did not let through.
Whether verified crawlers pass before the rules — the tab "Rules →
Verified crawlers".

The **cloud** block says what leaves the node. Without `cloud.token` —
plainly: the node talks to nobody, nothing leaves it. With a token — the
version and date of the fact set, how many aggregate batches wait to be
sent, when the cloud last accepted one and how the last failed attempt
went: the token was refused, the cloud was unreachable. Before, this
showed only on the service port and with `antibot aggregate status`.

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

**The download** is a link above the table: every event matching the
same filters over the last day, as the log's own lines (NDJSON), oldest
first. The span is changed with the `period` parameter, up to 90 days;
more than 500 thousand lines are not handed out at once — the whole log
lies on the node's disk. The events carry the visitors' addresses, so
every download is a line in the admin UI's log: who, how many lines, with
which filters and from where.

### Rules

In the **order of application**, not the order of the file: a human looks
here when working out why the wrong thing fired. Next to each — how many
times it fired over the period and from how many addresses; the numbers
come from the log rather than from in-memory counters, because after a
restart the counters reset while the log stays.

Two things can be done to a rule here: enable or disable it, and move it
from `shadow` to `active` and back. The count of firings next to it —
in shadow too — is what the move is based on.

### Verified crawlers

The second tab of the rules. A verified crawler is a network the fact
set names a crawler's and marks `protected`: search engines, Google's
checks, chat assistants. The node lets them through **before the
rules**, like your own networks — until the owner decides otherwise;
what this is and why — [facts.md](facts.md#verified-crawlers).

This is where that decision is made: the pass is turned off wholly, or
one owner of networks is held back — its crawlers go through the rules
like everyone. Next to it — who came over the period, how many requests,
how many were cut; which rules touched verified crawlers, held back or
with the pass off — in `shadow` too; and the self-declared crawlers, as
on the overview. Collectors of training data are named, but offered no
pass: the rules decide about them.

### One rule

A click on a rule opens its page. The number on the rules page says how
many; this one says **who**: the addresses, fingerprints, `User-Agent`s,
paths, hosts and the site's answer codes the rule fired on over the
period, a chart over time and the latest events it touched. For a rule
in shadow the answer codes are what the visitors got, that is, whom it
would have cut off. The share of all the traffic is right there: a rule
touching a noticeable share of the requests almost certainly touches
people too.

The page also has the rule as written in `rules.json` and the same two
buttons: after them the human comes back to the rule's page rather than
to the list. A click on a breakdown row opens the events with that value
**and this rule**. The rule is named in the address as a parameter
(`/rule?id=…`) rather than a piece of the path: an `id` is the owner's
text, and it may hold a `/`.

### Domains

Every domain is a row of the list: the name, where it came from, the site's server,
the DNS hint and **its certificate**. The certificate belongs to the
domain, so it lives in the domain's row: the names, the term and the
upload of a new pair are all there, rather than in a separate form where
the domain would have to be picked again.

The page has both sources: the `upstreams` lines of the configuration and
the domains added here or with `antibot domains`. The former are visible
but changed only in the configuration; on a name both know, **the
configuration wins** — what the machine's owner wrote by hand is not
overridden from the admin UI, not even by someone who stole a session.
Such a domain is marked as silenced.

No certificate means the node hands out the self-signed one, and the
browser will warn; the row says so plainly.

The **DNS** line is a hint, not a condition: whether the domain points
at this machine, and where it points if not. The node may stand behind
NAT and not know its public address, so "points elsewhere" does not stop
a domain from being added.

**Add a domain** — two fields: the name, and the site's server in one
line — `http://203.0.113.7:8080`, `https://10.0.0.5` or just
`127.0.0.1:3000`: without a scheme it is `http`. The server is an IP or a
name; loopback and private networks are fine: the site often lives on
the same machine. `Host` reaches the site as is.
A `*.example.ru` pattern covers the subdomains. The default route `*` is
not set here: what to answer to made-up names is the configuration's
call.

**The certificate** is uploaded in its domain's row — two files, the
chain (`fullchain.pem`) and the key (`privkey.pem`). The domain is not
typed: it is the one whose row the button is in. A new pair replaces
the previous one — that is what renewal is. A pair for several names or
with a wildcard, uploaded in one row, serves all of its names. Before
it is accepted, the pair is checked:

- the key matches the certificate;
- the term has not ended and has already begun;
- the certificate fits the row's domain; a `*.example.ru` pattern needs
  exactly that wildcard name.

A refusal comes with a clear reason, and **the previous certificate
stays in force**, the way the previous rule set does when the file is
broken. An accepted pair lands in `tls.uploaded_dir` in the certbot
layout — a subdirectory per domain, `fullchain.pem` and `privkey.pem`,
the key with `0600` — and starts serving at once, without a restart.

The node **neither issues nor renews** certificates: renewal is uploading
a fresh pair, or certbot next to the node, as before. When a certificate
for one name lies both in certbot's directory and among the uploads, the
one that lives longer serves: the renewal wins whichever door it came
through.

Since there is no renewal, an expiring certificate is the owner's errand,
and the admin UI has to say so: **14 days** before the end of the term a
warning appears on the overview, and the term is highlighted in the
domain's row.

#### API tokens

The tokens programs use to reach the node's [API](api.md): monitoring, a
panel of the owner's own, a CI job that rolls rules out together with the
site. Each has a name, the start of its value for recognising it, a scope
(`read` or `write`), who issued it and when, the term, the last use and
the state. Revoked and expired ones stay in the list: "which token did
the CI use until the 12th" must have an answer.

The page is shown only when `tokens_file` is set in `admin.yaml`.

### Alerts

Every trigger with the thresholds in force and its state: fine, or firing
since such a time and why. Below — the messages since the start: what
was said and what became of the delivery. The delivery command is set in
the settings, on the "Alert delivery" tab; while there is none, the page
says so above the table. The
firing triggers show on the overview too, as a warning at the top.

**The bell** in the header is on every page: the number of firing
triggers in red, and on a click — what is firing, since when and why,
the five latest messages and a link here. This page has no menu item of
its own — the way to it is the bell, and here the bell is highlighted
like the current item. It is a `<details>`: it opens
without a line of JavaScript. On a narrow
screen the menu's items fold into a "burger" on the left — a `<details>`
too: otherwise they would push the bell and the name off the edge. What
is checked and how a message comes — [alerts.md](alerts.md).

### Settings

Everything that is set once and then left alone is on one page, in tabs:
**Core**, **Cloud**, **Alert delivery**, **API tokens**,
**Admin certificate**. None of them has a menu item of its own, and the
menu keeps only the pages looked at every day: the overview, the events,
the rules, the domains. There is no delivery tab when the core has alerts
turned off, and no tokens tab when the API is off. The old addresses
`/cloud` and `/tokens` lead to the tabs: bookmarks do not break.

#### The core

Whether the core answers, its version, when it was started and how long
it has been running. A new start time is the trace of a restart: if the
core fell and the supervisor brought it back, this is where it shows.

Here too is the **restart**: the admin UI asks the core through the
socket to finish cleanly, the core completes the requests it has begun
and exits, and the supervisor brings it up again. The sites behind the
node are cut off for those seconds, so the button asks for the password
once more. A dead core cannot be raised this way — that is the
supervisor's job, and it does it by itself.

#### The cloud

Two checkboxes — "receive security updates" and "send statistics" — and
what has come of them: whether there is a token, what the tenant is
called in the cloud, which version of the set is applied, when the last
batch went. **Both are off** until the owner ticks them himself; at his
first login the overview sends him here, and that is the only time the
admin UI takes anybody off the page they asked for.

A ticked box on a node with no token is the request for one: the node
introduces itself to the cloud and writes the issued token down. The
change applies at once, with no restart. On the same page is "forget the
token": it clears both boxes and wipes the token.

If `cloud.token` is set in `config.yaml`, that decides: the boxes are
shown but cannot be changed. In detail — [cloud.md](cloud.md).

#### Alert delivery

The command the node sends alerts with, where it comes from
(`config.yaml` or set here), who changed it and when, and the test
message button. How changing it is guarded — below, under "The alerts
command".

#### The admin UI's certificate

**The admin UI's own certificate** is the one it answers the browser
with; the sites' certificates live on the domains page. It shows the names, who issued it (a self-signed one is
called so), the term, the files and where they come from: named in
`admin.yaml` or added here. If the certificate does not cover the name
the page was opened with, the page says so: the browser complains about
the same.

The page does not edit `admin.yaml` — it takes a ready pair, the way a
domain's row does:

- **the pair is named in `admin.yaml`** (`certificate` and `key`) — the
  new one lands in the place of the previous one and serves at once,
  without a restart;
- **there is no pair** — the admin UI works over HTTP, and on loopback
  behind `ssh -L` that is fine. The pair lands in `uploaded_dir` and
  serves **from the admin UI's next start**: a listener already up cannot
  be switched to HTTPS on the fly. If `admin.yaml` later names a pair of
  its own, it wins;
- **the files are certbot's links** — there is no replacing: certbot
  renews, and the admin UI takes the renewed pair up within 30 seconds.
  Replacing a link with a file would cut the renewal off without a word.

The check is the same as for a site's certificate, except for the name:
the key matches, the term has begun and has not ended. The name is not
checked: the admin UI is opened by whatever name, and which one is right
only its owner knows.

## The writing actions

There are fourteen and no others: enable or disable a rule, move it
between `shadow` and `active`, decide whether verified crawlers pass,
add a domain, remove a domain, upload a
site's certificate, replace the admin UI's certificate, issue an API
token, revoke an API token, change the alerts command, send a test
alert, answer the two questions about the cloud, forget the cloud
token, restart the core.

Everything that changes a file of the core's — the rules, the crawlers'
pass, the domains, a site's certificate, the alerts command — the admin UI writes itself and
right away asks the core to reread the file; the core notes it in its
log:

```
level=INFO msg="the rules were reread at the admin UI's word" in_force=2
```

If the core did not answer, the edit is on disk all the same, and the
core takes it up at its next check of the file or at startup. Who changed
what is written to the **admin UI's** log: it is the admin UI that acts,
not the core.

### The password once more

Nine of the fourteen ask for the password once more, although the login
is done: a stolen session must not be enough for them.

| Action | Why |
|---|---|
| move a rule to `active` | from then on it acts on live traffic |
| turn the verified crawlers' pass off, or hold an owner back | a block written in a hurry reaches a search engine |
| remove a domain | the node stops serving it at once |
| replace the admin UI's certificate | whoever holds its key reads the admin UI's traffic |
| issue an API token | a token outlives the session by months |
| revoke an API token | the programs that use it lose access at once |
| change the alerts command | the command runs on the node's machine |
| forget the cloud token | only a new registration brings it back |
| restart the core | every site behind the node is cut off for seconds |

Moving back to `shadow`, disabling a rule and giving crawlers their pass
back ask for nothing: that is a
step towards safety, and it must be quick. The attempts are counted
together with the login form — ten per five minutes from one address.

The password is asked in a dialog over the page: its question says what
exactly is about to happen. The dialog is the admin UI's only script,
`/confirm.js`; its words come from the page, in the page's language.
Without JavaScript the dialog never opens, and each such form shows its
own password field — it works the same.

### A rule: enable and disable

A rule that is cutting off live people gets turned off in the minute it
is noticed, not when somebody finds where `rules.json` lives on somebody
else's server. Hence the button.

There is no condition editor for the opposite reason: the admin UI stands
on somebody else's perimeter, and a hole in it must not become a hole in
the site's protection.

The toggle itself goes **through the same file write and the same set
validation** as `antibot rules`: the rules file has no second writer, just
as the matcher has no second engine. The file is reread before the edit —
it may have been changed by hand. Who toggled what goes into the admin
UI's log: a change of protection does not happen anonymously.

```
level=INFO msg="a rule was toggled from the admin UI"
  rule=block-hosting enabled=false who=owner address=127.0.0.1
```

### A rule: from `shadow` to `active`

A rule is born in `shadow`: it only marks events and cuts nobody off.
Moving it to `active` is the step after which it starts deciding, and a
human takes it after looking at whom it touches — the same page shows how
many times it fired in shadow over the period. The same button brings a
rule back to `shadow` if at work it touched the wrong people. The write
path is the same as `antibot rules mode` and the toggle; the node's log
says who moved what.

```
level=INFO msg="a rule's mode was changed from the admin UI"
  rule=block-hosting mode=active who=owner address=127.0.0.1
```

A proposal from the cloud lands in `shadow` and never takes this step by
itself.

### Domains and certificates

More dangerous than rules: changing the address of a site's server means
taking all its traffic elsewhere. The decision is deliberate — **the node's
owner manages it and carries the risk**, and the admin UI puts up no
extra barriers. What remains is the same as for any change of protection:
a login, CSRF, the same validation and the same atomic file replacement
as the command, and a line in the admin UI's log — who, what and from
where.

```
level=INFO msg="a domain was added from the admin UI"
  host=shop.example.ru to=http://127.0.0.1:8080 who=owner address=127.0.0.1
level=INFO msg="a certificate was uploaded from the admin UI"
  host=shop.example.ru not_after=2026-12-10 who=owner address=127.0.0.1
```

The domains live in a file of their own — `domains.file`, by default
`/var/lib/antibot/shared/domains.json` — rather than in `config.yaml`: the node
never writes the YAML. The file has two writers, the admin UI and
`antibot domains`, and both go through one validation. The file is
reread on the fly, like the rules.

### API tokens: issue and revoke

**Issuing asks for the password once more.** A session is enough to look
around and to switch a rule off, but a token outlives the session by
months: whoever stole a cookie must not turn it into a year of access.
The same reason accounts cannot be changed through the admin UI. The
password attempts are counted together with the login form — ten per
five minutes per address.

The value is shown **once**, in the answer to the issue, and nowhere
else: the admin UI keeps only its hash. A revocation takes effect from
the next request. Both actions land in the admin UI's log:

```
level=INFO msg="an API token was issued from the admin UI"
  token=monitoring scope=read expires=2026-12-12 who=owner address=127.0.0.1
level=INFO msg="an API token was revoked from the admin UI"
  token=monitoring who=owner address=127.0.0.1
```

`antibot-admin api-token` has the same file and the same validation:
what the command issues is visible here and works without a restart.

### The alerts command

**Changing it asks for the password once more**, like issuing a token:
the command runs on the node's machine, and a stolen session must not
become a way to run code there. The command from the core's `config.yaml`
wins: the admin UI shows it and does not change it. The admin UI's own
command lives in the core's `alerts.file`, mode `0640` — it often carries
a bot's token or a mail password, and only the core and the admin UI,
two users of one group, read it.

The command itself does not go into the admin UI's log, for the same reason —
only who, from where, its length and a fingerprint:

```
level=WARN msg="the alert command was changed from the admin UI"
  who=owner address=127.0.0.1 bytes=187 sha256=4c1f09a2b7e3
```

The **"send a test message"** button runs the command with a test
message and shows what came of it.

### The admin UI's certificate

**Replacing it asks for the password once more**, like issuing a token:
whoever holds the key of the admin UI's certificate reads its traffic,
and a stolen session must not be enough to put the thief's key there.
The pair is checked before it is written; both of its parts are first
written next to their place and only then moved into it — a failure in
the middle of the write leaves the previous pair whole. If the admin UI
cannot write next to the files named in `admin.yaml` — a read-only
directory — the refusal says so: replace the files on the machine, and
the admin UI takes them up within 30 seconds.

```
level=WARN msg="the admin UI certificate was replaced from the admin UI"
  names=admin.example.ru not_after=2026-12-10 who=owner address=127.0.0.1
```

## The borders

- **a separate process under a separate user**, and not a line of its
  code in the core's binary; the core needs no access to the admin UI at
  all, and the admin UI needs only the socket and the shared files from
  the core;
- **a login is mandatory**, the password is stored as a
  PBKDF2-HMAC-SHA256 hash with 600,000 iterations; guessing is limited by
  address — ten attempts per five minutes;
- **loopback by default**. A non-loopback address without a certificate
  is a **refusal at startup**, not a warning: the password would travel
  the network in clear text, and that is not an inconvenience but access
  already granted;
- **CSRF by double submission**: a random value in a cookie and in a
  hidden form field. Together with `SameSite=Strict` that is enough;
- **one file of JavaScript of our own**, the password dialog
  (`/confirm.js`); the CSP lets scripts in only from the admin UI's own
  address and none inline, and forbids everything external; the pages are
  assembled on the server, the templates, the stylesheet and the script
  are compiled into the binary, and everything works without the script;
- **sessions in the process's memory** — a restart logs everybody out,
  and that is more correct than keeping on disk something that can be
  logged in with;
- **`X-Robots-Tag: noindex`** — the admin UI shows the events of somebody
  else's site, it has no business in search results;
- **the write paths are listed**: `POST /rules/toggle`, `/rules/mode`, `/domains/add`,
  `/domains/remove`, `/domains/certificate`, `/settings/certificate`,
  `/settings/tokens/issue`, `/settings/tokens/revoke`, `/settings/alerts/command`,
  `/settings/alerts/test`, `/settings/cloud/save`, `/settings/cloud/forget`,
  `/settings/core/restart`. Any method other than GET is not handled on
  the pages themselves;
- **the API on the same address, through another door**: under
  `/api/v1/` only a token in a header lets in, the API does not take the
  session cookie, and the admin UI's forms do not take a token —
  [api.md](api.md);
- **an upload is capped at a megabyte** — two PEM files with room to
  spare, so the admin UI does not become a way to fill the disk.

## Exposing it

By default the admin UI listens on loopback, and that is the right mode:
look at it through `ssh -L 8090:127.0.0.1:8090`.

If it must face outwards, a certificate is mandatory, in `admin.yaml`:

```yaml
listen: "0.0.0.0:8090"
certificate: "/etc/letsencrypt/live/admin.example.ru/fullchain.pem"
key: "/etc/letsencrypt/live/admin.example.ru/privkey.pem"
redirect_from: ":8089"
```

A pair can also be added on the Settings page while the admin UI listens
on loopback: from the next start it works over HTTPS, and then the
address can be opened to the outside.

Without a certificate the admin UI **will not start** — it does not
"warn", it refuses to bring the listener up at all. The check runs before
the port is taken. A pair that does not load stops the start before the
port is taken too. The core does not suffer from it: it is another
process.

The admin UI's certificate is **reread on the fly**, at most once every
30 seconds: one renewed by certbot is taken up without a restart. A pair
that does not load — certbot caught between writing the chain and the
key — keeps the previous one in force, and the admin UI tries again in 30
seconds.

## What the admin UI does not have

- a rule editor — conditions are composed with a command or arrive ready
  through the [API](api.md);
- editing the settings — neither the core's `config.yaml`, which it does
  not read, nor its own `admin.yaml`; the Settings page only takes a
  ready pair for the admin UI itself;
- issuing and renewing certificates — only uploading ready-made ones;
- creating accounts — only `antibot-admin accounts passwd`. Changing a password
  through the admin UI would mean that whoever stole a session takes the
  access for good;
- editing a rule in place — it is replaced by deleting and adding, with
  the command or through the [API](api.md).

Accepting rule proposals from the update service will become one more
writing action when it appears; the rule will land in `shadow`, and
moving it to `active` will still be a human's job — with the same button.
