# Alerts

The node tells its owner that something is wrong with the site itself —
it does not wait for the owner to open the admin UI. It works on a free
node and without the cloud: nothing leaves but what the owner's own
command sends.

**A trigger only tells.** It changes neither the rules nor their mode,
nothing in the protection: a human decides. A rule that is cutting off
live people is not switched off by an alert — the alert says so within
the minute, and the owner switches it off with the button in the admin
UI.

## What is checked

| Trigger | When it fires | Thresholds |
|---|---|---|
| `site_down` — the site does not answer | a 5xx of the site for a share of the requests that reached it | `site_error_share`, `site_min_requests` |
| `rule_spike` — a rule cuts off a lot | one rule cut off a lot over the window, and many times its usual | `rule_min_matches`, `spike_factor` |
| `requests_spike` — a spike of requests | many times more requests than usual | `spike_min_requests`, `spike_factor` |
| `blocked_spike` — a spike of cut-off requests | many times more cut off by the node than usual | `spike_min_blocked`, `spike_factor` |
| `cert_expiring` — a certificate expires | fewer than `cert_days` days left; uploaded ones and certbot's alike | `cert_days` |
| `events_dropped` — the log loses events | the log's queue overflowed within the window | — |
| `disk_low` — the disk runs out | less than `disk_min_mb` free on the log's disk | `disk_min_mb` |
| `facts_stale` — the base is stale | no new fact set for `facts_max_age` while the node fetches them | `facts_max_age` |
| `outbox_stuck` — aggregates do not leave | `outbox_max` batches waiting to be sent | `outbox_max` |

The thresholds and their defaults are in
[configuration.md](configuration.md), the `alerts` section. The admin
UI's "Alerts" page shows every trigger with the thresholds in force.

## When a message comes

- The check runs once a minute, over the last `window` (five minutes by
  default) of finished minutes.
- **One message when a trigger fires, and one — "back to normal" — when
  things have stayed fine for a whole window.** A flapping trigger does
  not send a message a minute, and while a trigger is firing it does not
  repeat itself.
- **"Many times more than usual"** is measured against the average of
  the hour before. Not against the same hour yesterday: yesterday is lost
  on a restart, and a raid is a sharp jump, while a site's morning rise
  takes longer than an hour.
- **No spikes in the first half hour after a start**: the usual is not
  known yet, and every busy site would look attacked. "The site does not
  answer" works from the first minute.
- **A new rule has no usual**, so there is nothing to compare it with:
  the `rule_min_matches` minimum decides. A rule put into `active` that
  starts cutting off hundreds of requests at once will be noticed.
- The counting happens on the hot path, by the minute, in memory, not by
  rereading the log: a trigger has to fire within a minute. After a
  restart the count starts anew.

## The command

The node does not deliver the message itself: it has no mail clients
and no bots of its own — they would be outside dependencies and somebody
else's credentials inside the node. It runs the owner's command through
`sh -c`, with its own user rather than root, and with the `timeout`
limit. A failed command is a line in the node's log, not a retry forever.

The message comes in environment variables:

| Variable | What |
|---|---|
| `ANTIBOT_ALERT_ID` | the trigger and what it is about: `site_down`, `rule_spike:block-hosting`, `cert_expiring:shop.example.ru` |
| `ANTIBOT_ALERT_KIND` | the trigger: `site_down`, `rule_spike`… or `test` |
| `ANTIBOT_ALERT_STATE` | `firing`, `resolved` or `test` |
| `ANTIBOT_ALERT_TEXT` | the message in words |
| `ANTIBOT_ALERT_HOST` | the machine's name — to tell one node from another |
| `ANTIBOT_ALERT_TIME` | when, in RFC 3339, UTC |

and the same as JSON on stdin:

```json
{"id": "site_down", "kind": "site_down", "state": "firing",
 "text": "the site answers with errors: 412 of 530 requests that reached it got a 5xx over the last 5m",
 "host": "web-1", "time": "2026-09-13T12:05:00Z"}
```

**Nothing of the message is pasted into the command's text.** The text
carries strings the owner did not write: a name from a certificate, a
path, a `User-Agent`. The shell expands `"$ANTIBOT_ALERT_TEXT"` into one
argument and never parses it again, so a `$(…)` inside a message stays
text. The variables go in double quotes, always.

**Where it is set.** In `config.yaml`, the `alerts.command` key, or on
the admin UI's "Alerts" page. The configuration's command wins: the admin
UI shows it but does not change it — what the machine's owner wrote by
hand is not replaced through a stolen session. Changing the command in
the admin UI asks for the password once more: the command runs on the
node's machine. The command itself does not go into the node's log — it
often carries a bot's token or a mail password — only who, from where,
its length and a fingerprint.

Without a command the alerts go to the node's log and to the "Alerts"
page.

## Templates

`curl` is in the node's image; for the binary it is installed next to it.
The templates are written as a `>-` block — YAML joins the lines with
spaces into one command.

### Telegram

```yaml
alerts:
  command: >-
    curl -fsS -m 20 "https://api.telegram.org/bot<bot token>/sendMessage"
    --data-urlencode "chat_id=<chat id>"
    --data-urlencode "text=antibot $ANTIBOT_ALERT_HOST · $ANTIBOT_ALERT_STATE · $ANTIBOT_ALERT_TEXT"
```

### A webhook

The message goes out as JSON, as it is — from stdin:

```yaml
alerts:
  command: >-
    curl -fsS -m 20 -H 'Content-Type: application/json'
    --data-binary @- https://hooks.example.com/antibot
```

Services that want a format of their own (Slack, Mattermost) need a
script of their own: building JSON from the variables by pasting them
into a string is exactly what this design avoids, and a quote in the text
would break it.

### Mail

```yaml
alerts:
  command: >-
    printf 'From: antibot <node@example.com>\r\nTo: owner@example.com\r\nSubject: antibot %s: %s\r\n\r\n%s\r\n'
    "$ANTIBOT_ALERT_HOST" "$ANTIBOT_ALERT_ID" "$ANTIBOT_ALERT_TEXT"
    | curl -fsS -m 30 --ssl-reqd smtp://smtp.example.com:587
    --mail-from node@example.com --mail-rcpt owner@example.com
    --user 'node@example.com:<password>' -T -
```

A password in `config.yaml` means the configuration file is not for
everyone either: mode `0640`, owned by whoever the node runs as.

### A program of your own

Any executable: it gets the same variables and the same JSON.

```yaml
alerts:
  command: /usr/local/bin/antibot-notify
```

## Checking it

The "send a test message" button on the "Alerts" page runs the command
with `ANTIBOT_ALERT_STATE=test` and shows what came of it: handed to the
command, the command failed with such an output, or it did not fit into
the timeout.

## Where it shows

- the "Alerts" page: every trigger with its thresholds and state, the
  messages since the start and what became of each delivery;
- the bell in the admin UI's header, on every page: the number firing,
  and on a click — what is firing and the latest messages;
- the overview: the firing triggers, as a warning at the top;
- the node's log:

```
level=WARN msg="an alert is firing" alert=site_down text="the site answers with errors: …"
level=INFO msg="an alert was handed to the command" alert=site_down state=firing took=412ms
level=ERROR msg="the alert command failed" alert=site_down state=firing err="exit status 22" output="…"
```

## What it does not have

- **actions**: a trigger changes nothing in the protection — and never
  will;
- **a retry of a failed delivery**: the next message goes with the next
  firing, and the failed one is visible in the log and on the page;
- **a history on disk**: the page's history lives in memory and starts
  anew with a restart; every message is in the node's log;
- a channel of their own for monitoring: it asks for itself —
  [`GET /api/v1/alerts`](api.md) returns what the "Alerts" page shows.
