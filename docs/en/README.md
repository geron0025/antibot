# Documentation

The main English page is the repository's own
[README.md](../../README.md): what antibot is, why fingerprints, and how
to get it running. This directory holds the rest.

| Document | About |
|---|---|
| [install.md](install.md) | installation: container, binary, certificates |
| [configuration.md](configuration.md) | every configuration key and why it is what it is |
| [rules.md](rules.md) | rules: the model, the fields, the order, replaying over history |
| [facts.md](facts.md) | the network and fingerprint bases: applying, rolling back, the border |
| [admin.md](admin.md) | the admin UI: pages, login, its single writing action |
| [operations.md](operations.md) | running it: events, rotation, working out what broke |
| [protocol/](protocol/) | the exchange with the update service, to the byte |

The schemas are machine-readable and do not depend on a language, so
they live in one copy for both trees: [../schema/](../schema/). They are
the arbiter: should the prose and a schema disagree, the schema is
right.

Documentation in Russian: [../ru/](../ru/).
