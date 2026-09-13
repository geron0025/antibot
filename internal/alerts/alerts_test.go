package alerts

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

var start = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

func options() Options {
	return Options{
		Window: 5 * time.Minute, SiteErrorShare: 0.5, SiteMinRequests: 20,
		SpikeFactor: 5, SpikeMinRequests: 100, SpikeMinBlocked: 50, RuleMinMatches: 20,
		CertDays: 14, FactsMaxAge: 7 * 24 * time.Hour, OutboxMax: 12,
		Timeout: 5 * time.Second,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func watcher(o Options, started time.Time) *Watcher {
	w := New(o)
	w.started = started
	return w
}

func feed(w *Watcher, minute, n int, r facts.Request) {
	r.Time = start.Add(time.Duration(minute) * time.Minute).Add(10 * time.Second)
	for i := 0; i < n; i++ {
		w.Write(r)
	}
}

func at(minute int) time.Time { return start.Add(time.Duration(minute) * time.Minute) }

func states(w *Watcher) []string {
	var out []string
	for _, e := range w.History() {
		out = append([]string{e.ID + " " + e.State}, out...)
	}
	return out
}

var (
	failed  = facts.Request{Decision: "pass", Status: 502}
	served  = facts.Request{Decision: "pass", Status: 200}
	blocked = facts.Request{Decision: "block", Rule: "block-hosting", Status: 403}
)

// One message when the site goes down, none while it stays down, and one
// when it has been fine for a whole window — not one a minute.
func TestSiteDownFiresOnceAndResolvesOnce(t *testing.T) {
	w := watcher(options(), start)
	for m := 0; m < 5; m++ {
		feed(w, m, 10, failed)
	}
	for m := 5; m < 30; m++ {
		feed(w, m, 10, served)
	}
	for m := 5; m <= 20; m++ {
		w.Check(at(m))
	}
	got := strings.Join(states(w), ", ")
	if got != "site_down firing, site_down resolved" {
		t.Fatalf("messages: %s", got)
	}
	h := w.History()
	if !h[0].Time.Equal(at(13)) || !strings.Contains(h[0].Text, "back to normal") {
		t.Fatalf("resolved %v: %s", h[0].Time, h[0].Text)
	}
	if !strings.Contains(h[1].Text, "50 of 50 requests") {
		t.Fatalf("firing: %s", h[1].Text)
	}
}

// A rule that starts cutting a lot is noticed against its own usual; right
// after a start there is no usual yet, and nothing is called a spike.
func TestSpikesAgainstTheHourBefore(t *testing.T) {
	calm := func(w *Watcher) {
		for m := 0; m < 60; m++ {
			feed(w, m, 10, served)
			feed(w, m, 1, blocked)
		}
		for m := 60; m < 65; m++ {
			feed(w, m, 10, served)
			feed(w, m, 30, blocked)
		}
	}

	w := watcher(options(), start)
	calm(w)
	w.Check(at(65))
	firing := map[string]bool{}
	for _, s := range w.Firing() {
		firing[s.ID] = true
	}
	if !firing["rule_spike:block-hosting"] || !firing[BlockedSpike] {
		t.Fatalf("firing: %v", firing)
	}
	if firing[SiteDown] {
		t.Fatal("blocked requests counted as the site failing")
	}

	fresh := watcher(options(), at(60))
	calm(fresh)
	fresh.Check(at(65))
	if len(fresh.Firing()) != 0 {
		t.Fatalf("a spike without a baseline: %v", fresh.Firing())
	}

	// A new rule has no usual of its own: its first minutes of work are
	// compared against zero, and the minimum decides — 15 is below 20,
	// 25 is not.
	w = watcher(options(), start)
	for m := 0; m < 60; m++ {
		feed(w, m, 10, served)
	}
	quiet, busy := blocked, blocked
	quiet.Rule, busy.Rule = "block-quiet", "block-busy"
	for m := 60; m < 65; m++ {
		feed(w, m, 3, quiet)
		feed(w, m, 5, busy)
	}
	w.Check(at(65))
	firing = map[string]bool{}
	for _, s := range w.Firing() {
		firing[s.ID] = true
	}
	if firing["rule_spike:block-quiet"] || !firing["rule_spike:block-busy"] {
		t.Fatalf("new rules: %v", firing)
	}
}

// The checks that are not about the traffic read the node through probes.
func TestNodeChecks(t *testing.T) {
	o := options()
	var dropped int64
	o.Probes = Probes{
		Certificates: func() []Certificate {
			return []Certificate{
				{Names: []string{"a.ru", "www.a.ru"}, NotAfter: at(0).Add(3*24*time.Hour + time.Hour)},
				{Names: []string{"b.ru"}, NotAfter: at(0).Add(60 * 24 * time.Hour)},
			}
		},
		EventsDropped: func() int64 { return dropped },
		EventsDir:     t.TempDir(),
		Facts:         func() (int, time.Time, bool) { return 3, at(0).Add(-10 * 24 * time.Hour), true },
		Outbox:        func() (int, bool) { return 20, true },
	}
	o.DiskMinBytes = 1 << 62
	w := watcher(o, start)

	w.Check(at(1))
	dropped = 7
	w.Check(at(2))

	firing := map[string]string{}
	for _, s := range w.Firing() {
		firing[s.ID] = s.Text
	}
	for _, id := range []string{"cert_expiring:a.ru", EventsDropped, DiskLow, FactsStale, OutboxStuck} {
		if firing[id] == "" {
			t.Errorf("%s is not firing: %v", id, firing)
		}
	}
	if _, ok := firing["cert_expiring:b.ru"]; ok {
		t.Error("a certificate with 60 days left fired")
	}
	if !strings.Contains(firing["cert_expiring:a.ru"], "in 3 days") {
		t.Errorf("%s", firing["cert_expiring:a.ru"])
	}

	// A log that stopped losing events is fine again after a window.
	for m := 3; m <= 14; m++ {
		w.Check(at(m))
	}
	for _, s := range w.Firing() {
		if s.ID == EventsDropped {
			t.Fatal("events_dropped still firing with nothing lost for ten minutes")
		}
	}
}

// The alert reaches the command as data. A string a visitor could have
// made up — in a rule id, in a host name — is never run.
func TestTheCommandGetsTheAlertAsData(t *testing.T) {
	dir := t.TempDir()
	o := options()
	o.Command = func() string {
		return `printf '%s' "$ANTIBOT_ALERT_TEXT" > "` + dir + `/text"; cat > "` + dir + `/stdin.json"`
	}
	w := watcher(o, start)

	text := "$(touch " + dir + "/pwned) `touch " + dir + "/pwned2`; touch " + dir + "/pwned3"
	a := Alert{ID: "x", Kind: SiteDown, State: Firing, Text: text, Host: "node-1", Time: at(1)}
	if result := w.run(context.Background(), a); !strings.HasPrefix(result, "handed to the command") {
		t.Fatal(result)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "text"))
	if string(got) != text {
		t.Fatalf("the text arrived as %q", got)
	}
	for _, name := range []string{"pwned", "pwned2", "pwned3"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("the alert's text ran as code: %s exists", name)
		}
	}
	var back Alert
	raw, _ := os.ReadFile(filepath.Join(dir, "stdin.json"))
	if err := json.Unmarshal(raw, &back); err != nil || back != a {
		t.Fatalf("stdin: %s %v", raw, err)
	}
}

func TestWhatBecomesOfADelivery(t *testing.T) {
	o := options()
	o.Timeout = 300 * time.Millisecond
	command := ""
	o.Command = func() string { return command }
	w := watcher(o, start)
	a := Alert{ID: "x", State: Firing, Time: at(1)}

	for cmd, want := range map[string]string{
		"":                      "not sent: no command is set",
		"echo boom >&2; exit 3": "failed: exit status 3: boom",
		"sleep 5":               "failed: did not finish in 300ms",
		"cat > /dev/null; true": "handed to the command",
	} {
		command = cmd
		if got := w.run(context.Background(), a); !strings.HasPrefix(got, want) {
			t.Errorf("%q: %q, want %q", cmd, got, want)
		}
	}

	command = "true"
	if got := w.Test(context.Background()); !strings.HasPrefix(got, "handed") {
		t.Fatal(got)
	}
	if h := w.History(); len(h) != 1 || h[0].State != Test || !strings.HasPrefix(h[0].Delivery, "handed") {
		t.Fatalf("%+v", h)
	}
}

// Firing alerts go through the queue to the command while Run works.
func TestRunDelivers(t *testing.T) {
	dir := t.TempDir()
	o := options()
	o.Command = func() string { return `echo "$ANTIBOT_ALERT_ID $ANTIBOT_ALERT_STATE" >> "` + dir + `/got"` }
	w := watcher(o, start)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.deliverAll(ctx)

	for m := 0; m < 5; m++ {
		feed(w, m, 10, failed)
	}
	w.Check(at(5))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if raw, _ := os.ReadFile(filepath.Join(dir, "got")); string(raw) == "site_down firing\n" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "got"))
	t.Fatalf("delivered: %q", raw)
}

func TestCommandFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.json")
	c, err := OpenCommand(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Get(); got.Command != "" {
		t.Fatalf("%+v", got)
	}
	if err := c.Set("curl -s https://example.com", "owner", at(0)); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}

	// Another writer — the other process — is seen on the next read.
	other, _ := OpenCommand(path)
	if err := other.Set("true", "cli", at(1)); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Get(); got.Command != "true" || got.UpdatedBy != "cli" {
		t.Fatalf("%+v", got)
	}

	if err := c.Set(strings.Repeat("a", MaxCommand+1), "owner", at(2)); err == nil {
		t.Error("an overlong command was taken")
	}
	if err := c.Set("true\x00false", "owner", at(2)); err == nil {
		t.Error("a NUL byte was taken")
	}
}
