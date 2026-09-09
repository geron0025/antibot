package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
	"github.com/geron0025/antibot/internal/rules"
)

func ruleSet(t *testing.T, contents string) *rules.Set {
	t.Helper()
	set, err := rules.Parse([]byte(contents), rules.NewWindows())
	if err != nil {
		t.Fatalf("building the set: %v", err)
	}
	return set
}

func logDir(t *testing.T, list []facts.Request) string {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "events-2026-09-08.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range list {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const blockHosting = `{"version":1,"rules":[
  {"id":"block-hosting","scope":["*"],"mode":"active","priority":100,
   "condition":{"field":"network.class","op":"eq","value":"hosting"},
   "action":{"type":"block"}}]}`

// The main property of a replay: it produces exactly the same decision as
// the hot path on the same signals. There is one engine — and the test
// guards precisely that, not the arithmetic.
func TestReplayMatchesTheHotPath(t *testing.T) {
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	list := []facts.Request{
		{Time: start, IP: "203.0.113.1", Host: "example.ru", NetClass: "hosting"},
		{Time: start.Add(time.Second), IP: "198.51.100.2", Host: "example.ru"},
		{Time: start.Add(2 * time.Second), IP: "203.0.113.3", Host: "example.ru", NetClass: "hosting"},
	}
	dir := logDir(t, list)

	result, err := Run(Options{Dir: dir, Samples: 10}, ruleSet(t, blockHosting))
	if err != nil {
		t.Fatal(err)
	}

	// The same thing, but through the matcher directly.
	direct := ruleSet(t, blockHosting)
	own := map[string]int{}
	for _, r := range list {
		copy := r
		own[direct.Decide(&copy).Action]++
	}

	for action, count := range own {
		if result.Decisions[action] != count {
			t.Errorf("decision %s: the replay gave %d, the matcher directly %d",
				action, result.Decisions[action], count)
		}
	}
	if result.Events != 3 || result.IPs != 3 {
		t.Errorf("%d events, %d addresses; want 3 and 3", result.Events, result.IPs)
	}
}

func TestPerRuleStatistics(t *testing.T) {
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	list := []facts.Request{
		{Time: start, IP: "203.0.113.1", Host: "a.ru", UA: "curl", NetClass: "hosting"},
		{Time: start, IP: "203.0.113.1", Host: "b.ru", UA: "curl", NetClass: "hosting"},
		{Time: start, IP: "203.0.113.2", Host: "a.ru", UA: "wget", NetClass: "hosting"},
		{Time: start, IP: "198.51.100.9", Host: "a.ru", UA: "Mozilla"},
	}
	result, err := Run(Options{Dir: logDir(t, list), Samples: 2},
		ruleSet(t, blockHosting))
	if err != nil {
		t.Fatal(err)
	}

	s := result.Rules["block-hosting"]
	if s == nil {
		t.Fatal("the rule did not make it into the statistics")
	}
	if s.Matched != 3 || s.IPs != 2 || s.Hosts != 2 || s.UAs != 2 {
		t.Errorf("matched %d, addresses %d, hosts %d, UAs %d; want 3, 2, 2, 2",
			s.Matched, s.IPs, s.Hosts, s.UAs)
	}
	if len(s.Samples) != 2 {
		t.Errorf("%d samples, and 2 were asked for", len(s.Samples))
	}
	if share := result.Share("block-hosting"); share < 0.74 || share > 0.76 {
		t.Errorf("share %.3f, want 0.75", share)
	}
	if result.Blocked() != 3 {
		t.Errorf("blocked %d, want 3", result.Blocked())
	}
}

// A divergence from the recorded decision is what a replay is made for:
// "how many requests will the new rule cut off compared to what was".
func TestDivergenceFromWhatWasRecorded(t *testing.T) {
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	list := []facts.Request{
		{Time: start, IP: "203.0.113.1", Host: "a.ru", NetClass: "hosting", Decision: "pass"},
		{Time: start, IP: "198.51.100.9", Host: "a.ru", Decision: "pass"},
	}
	result, err := Run(Options{Dir: logDir(t, list)}, ruleSet(t, blockHosting))
	if err != nil {
		t.Fatal(err)
	}
	if result.Divergences["pass→block"] != 1 {
		t.Errorf("divergences: %v, want one pass→block", result.Divergences)
	}
}

// Shadows are counted on a par with decisions: a watching rule is set up
// in order to be looked at before it is turned on.
func TestShadowsMakeItIntoTheStatistics(t *testing.T) {
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	list := []facts.Request{
		{Time: start, IP: "203.0.113.1", Host: "a.ru", UA: "curl/8.4", NetClass: "hosting"},
	}
	set := ruleSet(t, `{"version":1,"rules":[
	  {"id":"watch-curl","scope":["*"],"mode":"shadow","priority":300,
	   "condition":{"field":"ua","op":"contains","value":"curl"},
	   "action":{"type":"block"}},
	  {"id":"block-hosting","scope":["*"],"mode":"active","priority":100,
	   "condition":{"field":"network.class","op":"eq","value":"hosting"},
	   "action":{"type":"block"}}]}`)

	result, err := Run(Options{Dir: logDir(t, list)}, set)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rules["watch-curl"] == nil || result.Rules["watch-curl"].Matched != 1 {
		t.Errorf("the observation was not counted: %v", result.Rules)
	}
	if result.Decisions[proxy.ActionBlock] != 1 {
		t.Errorf("the decision must come from the active rule: %v", result.Decisions)
	}
}

// In a replay the rate limiter counts by the events' time rather than by
// the machine's clock: otherwise the numbers are not the ones production
// saw.
func TestTheLimiterCountsByEventTime(t *testing.T) {
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	var list []facts.Request
	// Five requests in a row within one second, then one an hour later.
	for i := 0; i < 5; i++ {
		list = append(list, facts.Request{
			Time: start.Add(time.Duration(i) * time.Millisecond),
			IP:   "203.0.113.1", Host: "a.ru", Path: "/api",
		})
	}
	list = append(list, facts.Request{
		Time: start.Add(time.Hour), IP: "203.0.113.1", Host: "a.ru", Path: "/api",
	})

	result, err := Run(Options{Dir: logDir(t, list)}, ruleSet(t, `{"version":1,"rules":[
	  {"id":"rl","scope":["*"],"mode":"active","priority":10,
	   "condition":{"field":"path","op":"prefix","value":"/api"},
	   "action":{"type":"ratelimit","limit":2,"window":"1m"}}]}`))
	if err != nil {
		t.Fatal(err)
	}

	// Two passed, three hit the limit, and the sixth passed again: an
	// hour later the window has long been empty.
	if result.Decisions[proxy.ActionRatelimit] != 3 || result.Decisions[proxy.ActionPass] != 3 {
		t.Errorf("decisions %v; want 3 limited and 3 passed", result.Decisions)
	}
}

func TestTimeWindow(t *testing.T) {
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	list := []facts.Request{
		{Time: start, IP: "203.0.113.1", Host: "a.ru", NetClass: "hosting"},
		{Time: start.Add(2 * time.Hour), IP: "203.0.113.2", Host: "a.ru", NetClass: "hosting"},
	}
	result, err := Run(Options{
		Dir:  logDir(t, list),
		From: start.Add(time.Hour),
	}, ruleSet(t, blockHosting))
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 1 {
		t.Errorf("%d events, want 1: the rest are outside the window", result.Events)
	}
}

// A torn line is an ordinary thing: the log may have been copied while it
// was being written. A replay must count through to the end and say how
// many lines it did not understand.
func TestBrokenLinesDoNotBreakTheReplay(t *testing.T) {
	dir := t.TempDir()
	contents := `{"t":"2026-09-08T12:00:00Z","ip":"203.0.113.1","host":"a.ru","net_class":"hosting"}
{"t":"2026-09-08T12:00:01Z","ip":"203.0.11
{"t":"2026-09-08T12:00:02Z","ip":"203.0.113.3","host":"a.ru","net_class":"hosting"}
`
	if err := os.WriteFile(filepath.Join(dir, "events-2026-09-08.ndjson"), []byte(contents), 0o640); err != nil {
		t.Fatal(err)
	}
	result, err := Run(Options{Dir: dir}, ruleSet(t, blockHosting))
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 2 || result.Broken != 1 {
		t.Errorf("%d events, %d broken; want 2 and 1", result.Events, result.Broken)
	}
}

// A replay must read what the log wrote — not a "similar format" but
// exactly it. Checked end to end: the log writes, the replay reads.
func TestReplayReadsWhatTheLogWrites(t *testing.T) {
	dir := t.TempDir()
	l, err := events.Open(events.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	l.Write(facts.Request{
		Time: start, IP: "203.0.113.1", Host: "a.ru",
		NetClass: "hosting", UA: "curl/8.4", Decision: "pass",
	})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := Run(Options{Dir: dir, Samples: 1}, ruleSet(t, blockHosting))
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 1 || result.Broken != 0 {
		t.Fatalf("%d events, %d broken", result.Events, result.Broken)
	}
	s := result.Rules["block-hosting"]
	if s == nil || s.Matched != 1 {
		t.Fatal("the rule did not fire on the event from the log")
	}
	if len(s.Samples) != 1 || s.Samples[0].UA != "curl/8.4" {
		t.Errorf("the signals were lost on write and read: %+v", s.Samples)
	}
}
