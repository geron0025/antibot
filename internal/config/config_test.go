package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadsSettingsOnTopOfDefaults(t *testing.T) {
	path := write(t, `
listen:
  https: ":8443"
tls:
  reload_interval: 45s
upstreams:
  - host: "shop.example.ru"
    to: "http://127.0.0.1:3000"
trusted_proxies:
  - "10.0.0.0/8"
own_networks:
  - "203.0.113.7/32"
events:
  keep_days: 30
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("the config did not load: %v", err)
	}

	if c.Listen.HTTPS != ":8443" {
		t.Errorf("https: %q", c.Listen.HTTPS)
	}
	// What the file does not set comes from the defaults.
	if c.Listen.HTTP != ":80" {
		t.Errorf("http: %q — the default was lost", c.Listen.HTTP)
	}
	if c.TLS.ReloadInterval.Duration() != 45*time.Second {
		t.Errorf("reload_interval: %v", c.TLS.ReloadInterval.Duration())
	}
	if c.Events.KeepDays != 30 {
		t.Errorf("keep_days: %d", c.Events.KeepDays)
	}
	if len(c.Upstreams) != 1 || c.Upstreams[0].To != "http://127.0.0.1:3000" {
		t.Errorf("upstreams: %+v", c.Upstreams)
	}
}

// A typo in a field name has to be an error. Otherwise trusted_proxy
// instead of trusted_proxies means the X-Forwarded-For header is not
// trusted while the human wrote exactly the opposite — and will not find
// out any time soon.
func TestTypoInFieldNameIsAnError(t *testing.T) {
	path := write(t, "trusted_proxy:\n  - \"10.0.0.0/8\"\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("a typo in a field name passed silently")
	}
	if !strings.Contains(err.Error(), "trusted_proxy") {
		t.Errorf("the error does not name the field: %v", err)
	}
}

func TestBadValueIsRejected(t *testing.T) {
	cases := map[string]string{
		"not a network":       "trusted_proxies:\n  - \"10.0.0.1\"\n",
		"token without url":   "cloud:\n  token: \"secret\"\n",
		"token without state": "cloud:\n  token: \"secret\"\n  url: \"https://x\"\n  state_dir: \"\"\n",
		"empty upstream":      "upstreams:\n  - host: \"shop.ru\"\n",
		"duration as number":  "tls:\n  reload_interval: 30\n",
		"negative interval":   "tls:\n  reload_interval: -5s\n",
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, contents)); err == nil {
				t.Error("passed without an error")
			}
		})
	}
}

// A node that has just been installed must be operational without a
// single line of configuration: that is the promise of "installed with
// one command".
func TestDefaultsAreValidOnTheirOwn(t *testing.T) {
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("the defaults do not pass validation: %v", err)
	}
	if c.Cloud.Token != "" {
		t.Error("a cloud token is set by default — the node must go nowhere")
	}
}

// The example configuration from the repository must parse with this
// very code. Otherwise it silently drifts apart from the settings, and
// the first person to bring a node up from it gets an error at startup —
// and concludes that antibot itself is broken.
func TestExampleConfigParses(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "config.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no example: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("the example configuration does not parse: %v", err)
	}
}
