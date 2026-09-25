package admin

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/i18n"
)

// Config is the admin UI's own settings file, admin.yaml.
//
// Separate from the core's config.yaml on purpose: the admin UI runs
// under a user of its own and must not read the core's settings — they
// carry the token to the cloud. What it needs of the core is named here:
// the socket, and the files the two share.
type Config struct {
	// Listen defaults to loopback. A non-loopback address without a
	// certificate is a refusal at startup: the password would go over the
	// network in clear text.
	Listen string `yaml:"listen"`

	// RedirectFrom is the address on which HTTP answers with code 308.
	// It works only together with a certificate.
	RedirectFrom string `yaml:"redirect_from"`

	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`

	// UploadedDir is where a pair added on the settings page lands when
	// certificate and key are empty; it serves from the next start. A
	// pair named above is replaced in place instead. Empty turns adding
	// off.
	UploadedDir string `yaml:"uploaded_dir"`

	// UsersFile is a separate file rather than these settings: the
	// settings are often mounted read-only, while a password is changed
	// without a restart.
	UsersFile string `yaml:"users_file"`

	// TokensFile holds the API's tokens, as hashes. Empty turns the API
	// off.
	TokensFile string `yaml:"tokens_file"`

	SessionTTL config.Duration `yaml:"session_ttl"`

	// Language is the one the pages speak when neither the viewer's
	// choice nor their browser names a language the admin UI has: "en"
	// or "ru".
	Language string `yaml:"language"`

	Core CoreFiles `yaml:"core"`
}

// CoreFiles is where the core is: its socket, and the files the admin UI
// reads or writes and the core takes up.
type CoreFiles struct {
	// Socket is the core's control socket, its listen.control.
	Socket string `yaml:"socket"`

	// EventsDir is only read.
	EventsDir string `yaml:"events_dir"`

	// RulesFile and DomainsFile are written the same way the antibot
	// rules and antibot domains commands write them.
	RulesFile   string `yaml:"rules_file"`
	DomainsFile string `yaml:"domains_file"`

	// CertificatesDir is where an uploaded site pair lands: the core's
	// tls.uploaded_dir. Empty turns uploads off.
	CertificatesDir string `yaml:"certificates_dir"`

	// AlertsFile is where the delivery tab keeps the alert command: the
	// core's alerts.file. Empty turns changing it off.
	AlertsFile string `yaml:"alerts_file"`

	// CrawlersFile is where the verified crawlers tab keeps the owner's
	// decision: the core's crawlers_file. Empty turns changing it off.
	CrawlersFile string `yaml:"crawlers_file"`
}

// DefaultConfig is an admin UI installed next to a core with its
// defaults: the core's files in /var/lib/antibot, the admin UI's own in
// /var/lib/antibot-admin, where the core has no access.
func DefaultConfig() Config {
	return Config{
		Listen:      "127.0.0.1:8090",
		UploadedDir: "/var/lib/antibot-admin/admin-ui",
		UsersFile:   "/var/lib/antibot-admin/admin.json",
		TokensFile:  "/var/lib/antibot-admin/api-tokens.json",
		SessionTTL:  config.Duration(12 * time.Hour),
		Language:    "en",
		Core: CoreFiles{
			Socket:          "/var/lib/antibot/core.sock",
			EventsDir:       "/var/lib/antibot/events",
			RulesFile:       "/var/lib/antibot/shared/rules.json",
			DomainsFile:     "/var/lib/antibot/shared/domains.json",
			CertificatesDir: "/var/lib/antibot/shared/certificates",
			AlertsFile:      "/var/lib/antibot/shared/alerts.json",
			CrawlersFile:    "/var/lib/antibot/shared/crawlers.json",
		},
	}
}

// LoadConfig reads admin.yaml over the defaults. An unknown field is an
// error, the way it is in config.yaml: a typo must not be a silently
// ignored intention.
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	contents, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("admin settings: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		return c, fmt.Errorf("admin settings %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("admin settings %s: %w", path, err)
	}
	return c, nil
}

// Validate catches what would otherwise surface at the first request.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen is empty: nowhere to listen")
	}
	if (c.Certificate == "") != (c.Key == "") {
		return fmt.Errorf("certificate and key are set together")
	}
	if _, ok := i18n.Parse(c.Language); !ok {
		return fmt.Errorf("language %q: the admin UI speaks %v", c.Language, i18n.Supported)
	}
	if c.Core.Socket == "" {
		return fmt.Errorf("core.socket is empty: there is no core to ask")
	}
	if c.Core.EventsDir == "" {
		return fmt.Errorf("core.events_dir is empty: there is nothing to show")
	}
	return nil
}
