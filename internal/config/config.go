// Package config reads and validates the node's settings file.
//
// The settings are the only thing a human sets by hand. Everything else
// the node knows it either takes off the traffic or receives over the
// network, and therefore changes without editing files and without a
// restart.
package config

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/geron0025/antibot/internal/i18n"
)

// Config is the whole configuration file.
type Config struct {
	Listen    Listen     `yaml:"listen"`
	TLS       TLS        `yaml:"tls"`
	Upstreams []Upstream `yaml:"upstreams"`

	// TrustedProxies are the networks allowed to set X-Forwarded-For. An
	// empty list means the header is ignored and the TCP peer is taken as
	// the client's address.
	//
	// The default is exactly this because the opposite is forged with one
	// line of curl: trusting the header by default means handing anyone
	// who wants it the ability to call themselves anybody.
	TrustedProxies []string `yaml:"trusted_proxies"`

	// OwnNetworks are checked before the rules and always pass. This is
	// not a high-priority rule but a separate layer: an own network
	// written into ten rules will one day be forgotten in the eleventh.
	OwnNetworks []string `yaml:"own_networks"`

	// CrawlersFile keeps the owner's decision about the verified
	// crawlers: whether they pass before the rules, and which owners of
	// crawler networks are held back. Without the file they pass; the
	// admin UI writes it. Empty turns the pass off altogether.
	CrawlersFile string `yaml:"crawlers_file"`

	// NodeIDFile holds the identifier of this installation — the one the
	// cloud uses to tell installations apart. A separate file rather
	// than a setting: it is created by the node itself on the first run,
	// and the configuration is often mounted read-only.
	NodeIDFile string `yaml:"node_id_file"`

	Events  Events       `yaml:"events"`
	AdminUI MovedAdminUI `yaml:"admin_ui"`
	Rules   Rules        `yaml:"rules"`
	Domains Domains      `yaml:"domains"`
	Facts   Facts        `yaml:"facts"`
	Cloud   Cloud        `yaml:"cloud"`
	Alerts  Alerts       `yaml:"alerts"`
}

// Alerts are the triggers that tell the owner something is wrong with
// the site, and the owner's command that delivers the message. A
// trigger only tells: it never changes the protection.
type Alerts struct {
	Enabled bool `yaml:"enabled"`

	// Command is run through sh -c with the alert in ANTIBOT_ALERT_*
	// variables and as JSON on stdin. Set here, it wins over the one set
	// from the admin UI, which lands in File.
	Command string   `yaml:"command"`
	File    string   `yaml:"file"`
	Timeout Duration `yaml:"timeout"`

	// Language is the one the messages go to the command in. Set here,
	// it wins over the one chosen in the admin UI, which lands in File
	// with the command. Empty leaves the choice to the admin UI.
	Language string `yaml:"language"`

	// Window is the stretch every traffic trigger looks at.
	Window Duration `yaml:"window"`

	SiteErrorShare   float64  `yaml:"site_error_share"`
	SiteMinRequests  int      `yaml:"site_min_requests"`
	SpikeFactor      float64  `yaml:"spike_factor"`
	SpikeMinRequests int      `yaml:"spike_min_requests"`
	SpikeMinBlocked  int      `yaml:"spike_min_blocked"`
	RuleMinMatches   int      `yaml:"rule_min_matches"`
	CertDays         int      `yaml:"cert_days"`
	DiskMinMB        int      `yaml:"disk_min_mb"`
	FactsMaxAge      Duration `yaml:"facts_max_age"`
	OutboxMax        int      `yaml:"outbox_max"`
}

type Listen struct {
	HTTP  string `yaml:"http"`
	HTTPS string `yaml:"https"`
	Admin string `yaml:"admin"`

	// Control is the unix socket the admin UI asks the core over. Empty
	// turns it off: a core run with ready rules and no admin UI needs none.
	Control string `yaml:"control"`
}

type TLS struct {
	// CertificatesDir is scanned anew on every check, so the certificate
	// of a new domain is picked up without a restart.
	CertificatesDir string `yaml:"certificates_dir"`

	// UploadedDir is where the certificates uploaded through the admin
	// UI land, in the same certbot layout. A separate directory rather
	// than CertificatesDir: that one is often certbot's own or mounted
	// read-only, and the node must not write into a catalog somebody
	// else leads.
	UploadedDir string `yaml:"uploaded_dir"`

	SelfSignedDir  string   `yaml:"self_signed_dir"`
	ReloadInterval Duration `yaml:"reload_interval"`
}

type Upstream struct {
	Host string `yaml:"host"`
	To   string `yaml:"to"`
}

type Events struct {
	Dir      string `yaml:"dir"`
	MaxSize  int64  `yaml:"max_size"`
	KeepDays int    `yaml:"keep_days"`
	Queue    int    `yaml:"queue"`
}

// MovedAdminUI is the admin_ui section of settings written before the
// admin UI became a program of its own. Read only to say where it went:
// silently ignoring it would leave the owner wondering why the admin UI
// is not up.
type MovedAdminUI map[string]any

type Rules struct {
	File string `yaml:"file"`

	// ReloadInterval is how often to check whether the file has changed.
	// The check is cheap: one look at the file's metadata.
	ReloadInterval Duration `yaml:"reload_interval"`
}

// Domains is the file with the domains added while the node runs — from
// the admin UI or with `antibot domains`. The upstreams from this very
// configuration stay a separate, hand-led list; on a name both know,
// the configuration wins.
type Domains struct {
	File string `yaml:"file"`

	// ReloadInterval is how often to check whether the file has changed.
	ReloadInterval Duration `yaml:"reload_interval"`
}

type Facts struct {
	// Enabled turns off the use of the fact bases entirely — with the
	// very line promised in the protocol.
	Enabled  bool     `yaml:"enabled"`
	Dir      string   `yaml:"dir"`
	URL      string   `yaml:"url"`
	Interval Duration `yaml:"interval"`
}

type Cloud struct {
	// With an empty Token sending does not work at all. Not "turned off
	// by a setting" — it simply has no addressee.
	Token    string   `yaml:"token"`
	URL      string   `yaml:"url"`
	Interval Duration `yaml:"interval"`

	// StateDir keeps the open aggregate window across a restart and the
	// batches the cloud has not taken yet. Created only when there is a
	// token: a node that sends nothing keeps nothing for sending.
	StateDir string `yaml:"state_dir"`

	// RegisterURL is where a node with no token asks for one. Empty
	// means the address beside URL, and with no URL either, the one the
	// build was born with — which is what a node installed from the
	// README has.
	RegisterURL string `yaml:"register_url"`

	// LinkFile holds what the owner answered in the admin UI about the
	// cloud, and the token if he took one. It is the node's own state,
	// not settings: this file the admin UI does write, and the settings
	// above win over everything in it.
	LinkFile string `yaml:"link_file"`
}

// Defaults are the settings of a node that has just been installed: it
// listens, proxies, writes the log and goes nowhere.
//
// What the admin UI writes lies in /var/lib/antibot/shared: the admin UI
// is another user, and writing a file atomically takes the right to
// write its directory. That right is given for this directory alone —
// not for the rest of /var/lib/antibot, where the token to the cloud and
// the node's identifier live.
func Defaults() Config {
	return Config{
		Listen: Listen{HTTP: ":80", HTTPS: ":443", Admin: "127.0.0.1:8091",
			Control: "/var/lib/antibot/core.sock"},
		NodeIDFile:   "/var/lib/antibot/node.id",
		CrawlersFile: "/var/lib/antibot/shared/crawlers.json",
		TLS: TLS{
			UploadedDir:    "/var/lib/antibot/shared/certificates",
			SelfSignedDir:  "/var/lib/antibot/certs",
			ReloadInterval: Duration(30 * time.Second),
		},
		Events: Events{
			Dir: "/var/lib/antibot/events", MaxSize: 256 << 20,
			KeepDays: 14, Queue: 4096,
		},
		Rules: Rules{
			File:           "/var/lib/antibot/shared/rules.json",
			ReloadInterval: Duration(5 * time.Second),
		},
		Domains: Domains{
			File:           "/var/lib/antibot/shared/domains.json",
			ReloadInterval: Duration(5 * time.Second),
		},
		Facts: Facts{
			Enabled: true, Dir: "/var/lib/antibot/facts",
			Interval: Duration(24 * time.Hour),
		},
		Cloud: Cloud{
			Interval: Duration(15 * time.Minute),
			StateDir: "/var/lib/antibot/aggregate",
			LinkFile: "/var/lib/antibot/cloud.json",
		},
		Alerts: Alerts{
			Enabled: true, File: "/var/lib/antibot/shared/alerts.json",
			Timeout: Duration(30 * time.Second), Window: Duration(5 * time.Minute),
			SiteErrorShare: 0.5, SiteMinRequests: 20,
			SpikeFactor: 5, SpikeMinRequests: 500, SpikeMinBlocked: 200, RuleMinMatches: 50,
			CertDays: 14, DiskMinMB: 1024,
			FactsMaxAge: Duration(7 * 24 * time.Hour), OutboxMax: 12,
		},
	}
}

// Load reads a file on top of the defaults.
func Load(path string) (Config, error) {
	c := Defaults()

	contents, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("config: %w", err)
	}

	// KnownFields: a typo in a field name has to be an error, not a
	// silently ignored intention. Whoever wrote trusted_proxy instead of
	// trusted_proxies finds out right away rather than while
	// investigating an incident with a forged address.
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		return c, fmt.Errorf("config %s: %w", path, err)
	}

	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

// Validate catches what would otherwise surface in production.
func (c *Config) Validate() error {
	if c.Listen.HTTP == "" && c.Listen.HTTPS == "" {
		return fmt.Errorf("no listener is configured")
	}

	for _, list := range []struct {
		name     string
		networks []string
	}{
		{"trusted_proxies", c.TrustedProxies},
		{"own_networks", c.OwnNetworks},
	} {
		for _, s := range list.networks {
			if _, err := netip.ParsePrefix(s); err != nil {
				return fmt.Errorf("%s: %q is not a network like 10.0.0.0/8: %w", list.name, s, err)
			}
		}
	}

	for i, u := range c.Upstreams {
		if u.Host == "" {
			return fmt.Errorf("upstreams[%d]: empty host", i)
		}
		if u.To == "" {
			return fmt.Errorf("upstreams[%d] (%s): empty to", i, u.Host)
		}
	}

	if c.AdminUI != nil {
		return fmt.Errorf("admin_ui: the admin UI is a separate program now, antibot-admin, " +
			"with settings of its own (admin.yaml); move the section there and remove it from here")
	}

	if c.Cloud.Token != "" && c.Cloud.URL == "" {
		return fmt.Errorf("cloud.token is set and cloud.url is not: nowhere to send")
	}
	if c.Cloud.Token != "" && c.Cloud.StateDir == "" {
		return fmt.Errorf("cloud.token is set and cloud.state_dir is not: nowhere to keep what is not sent yet")
	}
	if c.Facts.Enabled && c.Facts.URL != "" {
		if c.Facts.Dir == "" {
			return fmt.Errorf("facts.url is set and facts.dir is not: nowhere to put it")
		}
		// The distribution still has no anonymous form, but the token no
		// longer has to be in this file: a node takes one itself when
		// the owner ticks "receive security updates" in the admin UI.
		// An address with no token anywhere is therefore a node waiting
		// to be asked, not a broken settings file, and refusing to
		// start would leave it unable to be asked at all. Without a
		// token the fetching simply does not begin.
		if c.Cloud.Token == "" && c.Cloud.LinkFile == "" {
			return fmt.Errorf("facts.url is set, and there is neither cloud.token nor " +
				"cloud.link_file to keep a token the node takes itself")
		}
	}
	return c.Alerts.validate()
}

func (a *Alerts) validate() error {
	if !a.Enabled {
		return nil
	}
	window := a.Window.Duration()
	switch {
	case window < time.Minute || window > time.Hour || window%time.Minute != 0:
		return fmt.Errorf("alerts.window %s: whole minutes, from 1m to 1h", window)
	case a.Timeout.Duration() < time.Second || a.Timeout.Duration() > 5*time.Minute:
		return fmt.Errorf("alerts.timeout %s: from 1s to 5m", a.Timeout.Duration())
	case a.SiteErrorShare <= 0 || a.SiteErrorShare > 1:
		return fmt.Errorf("alerts.site_error_share %v: a share above 0, up to 1", a.SiteErrorShare)
	case a.SpikeFactor < 1.5:
		return fmt.Errorf("alerts.spike_factor %v: at least 1.5, or every busy hour is a spike", a.SpikeFactor)
	case a.SiteMinRequests < 1 || a.SpikeMinRequests < 1 || a.SpikeMinBlocked < 1 || a.RuleMinMatches < 1:
		return fmt.Errorf("alerts: the minimum counts are at least 1")
	case a.CertDays < 0 || a.CertDays > 90:
		return fmt.Errorf("alerts.cert_days %d: from 0 to 90", a.CertDays)
	case a.DiskMinMB < 0 || a.OutboxMax < 0 || a.FactsMaxAge.Duration() < 0:
		return fmt.Errorf("alerts: disk_min_mb, outbox_max and facts_max_age are not negative")
	case len(a.Command) > 4096:
		return fmt.Errorf("alerts.command is longer than 4096 bytes")
	}
	if _, ok := i18n.Parse(a.Language); a.Language != "" && !ok {
		return fmt.Errorf("alerts.language %q: the alerts speak %v", a.Language, i18n.Supported)
	}
	return nil
}

// Prefixes parses a list of networks. It is called after Validate, so
// there can be no error here.
func Prefixes(networks []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(networks))
	for _, s := range networks {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}
