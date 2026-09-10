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

	// NodeIDFile holds the identifier of this installation — the one the
	// cloud uses to tell installations apart. A separate file rather
	// than a setting: it is created by the node itself on the first run,
	// and the configuration is often mounted read-only.
	NodeIDFile string `yaml:"node_id_file"`

	Events Events `yaml:"events"`
	Admin  Admin  `yaml:"admin_ui"`
	Rules  Rules  `yaml:"rules"`
	Facts  Facts  `yaml:"facts"`
	Cloud  Cloud  `yaml:"cloud"`
}

type Listen struct {
	HTTP  string `yaml:"http"`
	HTTPS string `yaml:"https"`
	Admin string `yaml:"admin"`
}

type TLS struct {
	// CertificatesDir is scanned anew on every check, so the certificate
	// of a new domain is picked up without a restart.
	CertificatesDir string   `yaml:"certificates_dir"`
	SelfSignedDir   string   `yaml:"self_signed_dir"`
	ReloadInterval  Duration `yaml:"reload_interval"`
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

// Admin is the viewing admin UI.
//
// It changes nothing: rules are changed only by the antibot rules
// command. Hence the defaults: loopback, login required, and without
// accounts it does not come up at all.
type Admin struct {
	Enabled bool `yaml:"enabled"`

	// Listen defaults to loopback. A non-loopback address without a
	// certificate is a refusal at startup: the password would go over the
	// network in clear text.
	Listen string `yaml:"listen"`

	// RedirectFrom is the address on which HTTP answers with code 308.
	// It works only together with a certificate.
	RedirectFrom string `yaml:"redirect_from"`

	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`

	// UsersFile is a separate file rather than these settings: the
	// configuration is often mounted read-only, while a password is
	// changed without restarting the node.
	UsersFile string `yaml:"users_file"`

	SessionTTL Duration `yaml:"session_ttl"`
}

type Rules struct {
	File string `yaml:"file"`

	// ReloadInterval is how often to check whether the file has changed.
	// The check is cheap: one look at the file's metadata.
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
}

// Defaults are the settings of a node that has just been installed: it
// listens, proxies, writes the log and goes nowhere.
func Defaults() Config {
	return Config{
		Listen:     Listen{HTTP: ":80", HTTPS: ":443", Admin: "127.0.0.1:8091"},
		NodeIDFile: "/var/lib/antibot/node.id",
		TLS: TLS{
			SelfSignedDir:  "/var/lib/antibot/certs",
			ReloadInterval: Duration(30 * time.Second),
		},
		Events: Events{
			Dir: "/var/lib/antibot/events", MaxSize: 256 << 20,
			KeepDays: 14, Queue: 4096,
		},
		Admin: Admin{
			Enabled:    true,
			Listen:     "127.0.0.1:8090",
			UsersFile:  "/var/lib/antibot/admin.json",
			SessionTTL: Duration(12 * time.Hour),
		},
		Rules: Rules{
			File:           "/var/lib/antibot/rules.json",
			ReloadInterval: Duration(5 * time.Second),
		},
		Facts: Facts{
			Enabled: true, Dir: "/var/lib/antibot/facts",
			Interval: Duration(24 * time.Hour),
		},
		Cloud: Cloud{
			Interval: Duration(15 * time.Minute),
			StateDir: "/var/lib/antibot/aggregate",
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

	if c.Admin.Enabled {
		if c.Admin.Listen == "" {
			return fmt.Errorf("admin_ui.enabled without admin_ui.listen: nowhere to listen")
		}
		if (c.Admin.Certificate == "") != (c.Admin.Key == "") {
			return fmt.Errorf("admin_ui: certificate and key are set together")
		}
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
		// The subscription token is one for both directions, and the
		// distribution has no anonymous form: without a token the
		// address is unreachable, and a node that quietly does not fetch
		// looks exactly like one that fetches and finds nothing new.
		if c.Cloud.Token == "" {
			return fmt.Errorf("facts.url is set and cloud.token is not: " +
				"the bases are handed out by subscription, there is no anonymous distribution")
		}
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
