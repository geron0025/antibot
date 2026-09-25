// Package control is the channel between the node's core and its admin
// UI: two programs, two processes, and this is all either knows of the
// other.
//
// The core runs alone, with rules from files, and needs no admin UI at
// all. When there is one, it lives in a process of its own, under a user
// of its own, and asks the core over a unix socket for what exists only
// in the core's memory: the alerts, the link to the cloud, how the core
// is doing. What lives in files — events, rules, domains, certificates —
// the admin UI reads and writes itself, and asks the core only to take a
// change up at once rather than at the next look.
//
// The list of what can be asked is closed and short on purpose. The
// admin UI stands on somebody else's perimeter; whoever breaks into it
// gets this list and not a byte more — not the core's memory, not its
// settings file, not its token to the cloud.
//
// HTTP with JSON over the socket: the standard library on both ends, and
// a human debugs it with curl --unix-socket.
package control

import (
	"context"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
)

// Core is what the admin UI may ask of the core. The core implements it
// in its own process; the admin UI gets a Client, which asks the same
// over the socket.
type Core interface {
	// Health says the core is up, since when and in which version. The
	// admin UI shows it, and a restart shows as a new start time.
	Health(ctx context.Context) (Health, error)

	// Stop asks the core to finish cleanly. Bringing it back is the
	// supervisor's job — systemd or docker — not the admin UI's: the
	// admin UI has no rights over the core's process, and must not.
	Stop(ctx context.Context) error

	// Alerts are the triggers, what fires now and what was sent.
	Alerts(ctx context.Context) (Alerts, error)

	// TestAlert sends a test message through the command in force and
	// says what became of it.
	TestAlert(ctx context.Context) (string, error)

	// Cloud is the state of the link to the cloud.
	Cloud(ctx context.Context) (CloudState, error)

	// CloudAnswer records the owner's two checkboxes; CloudRegister asks
	// the cloud for a token first; CloudForget drops the token and both
	// answers.
	CloudAnswer(ctx context.Context, facts, aggregates bool) error
	CloudRegister(ctx context.Context, facts, aggregates bool) error
	CloudForget(ctx context.Context) error

	// Certificates are the sites' certificates the core serves.
	Certificates(ctx context.Context) ([]Certificate, error)

	// Routes are the routes written by hand in the core's settings file:
	// shown by the admin UI, never written by it.
	Routes(ctx context.Context) (map[string]string, error)

	// Reload makes the core take a changed file up now.
	Reload(ctx context.Context, what Reloadable) error
}

// Reloadable names a file the admin UI changes and the core reads.
type Reloadable string

const (
	ReloadRules        Reloadable = "rules"
	ReloadDomains      Reloadable = "domains"
	ReloadCertificates Reloadable = "certificates"
)

// Health is how the core is doing.
type Health struct {
	Version string    `json:"version"`
	Started time.Time `json:"started"`
}

// Alerts is the alerts page's data. Enabled false means the core's
// settings turn the alerts off, and the rest is empty.
type Alerts struct {
	Enabled  bool             `json:"enabled"`
	Triggers []alerts.Trigger `json:"triggers"`
	Firing   []alerts.Status  `json:"firing"`
	History  []alerts.Entry   `json:"history"`

	// ConfigCommand is the command from the core's settings file, which
	// wins over the one the admin UI keeps and is never changed by it.
	ConfigCommand string `json:"config_command,omitempty"`

	// ConfigLanguage is the language of the messages from the core's
	// settings file, which wins over the one the admin UI keeps.
	ConfigLanguage string `json:"config_language,omitempty"`
}

// Certificate is one certificate the core serves.
type Certificate struct {
	Path     string    `json:"path"`
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"not_after"`
}

// CloudState is what the admin UI says about the node's link to the
// cloud: whether there is one at all, and how both directions fare.
//
// The first line matters most for a node without a token: it says in so
// many words that nothing leaves it. An owner who installed a node from a
// public repository has every reason to ask.
type CloudState struct {
	// Token is whether there is a token at all — from the settings file
	// or taken by the node itself. Without one nothing leaves the node,
	// neither aggregates nor requests for the bases.
	Token bool `json:"token"`

	// Answered says the owner has been asked the two questions. A node
	// that was never asked is sent to the welcome page at login; one
	// that answered "no" to both is not asked again.
	Answered bool `json:"answered"`

	// FromConfig says the settings file names the token. Then the two
	// checkboxes are shown but decide nothing: what the machine's owner
	// wrote by hand outranks a web page.
	FromConfig bool `json:"from_config"`

	// Tenant and Level are what the cloud called this installation when
	// it registered. The owner needs the name to call himself by it.
	Tenant string `json:"tenant,omitempty"`
	Level  string `json:"level,omitempty"`

	FactsVersion int       `json:"facts_version,omitempty"`
	FactsBuilt   time.Time `json:"facts_built,omitzero"`
	Fetching     bool      `json:"fetching"`
	Sending      bool      `json:"sending"`

	Outbox      int       `json:"outbox,omitempty"`
	LastSent    time.Time `json:"last_sent,omitzero"`
	LastProblem string    `json:"last_problem,omitempty"`
}

// Refusal is a refusal with words already chosen for a human: the admin
// UI shows its text as it is. Any other error is the core's own and goes
// to the page as an error.
type Refusal struct{ Text string }

func (r *Refusal) Error() string { return r.Text }

// Refuse wraps a message meant for the owner rather than the log.
func Refuse(text string) error { return &Refusal{Text: text} }
