package summary

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
)

func logDir(t *testing.T, list []facts.Request) string {
	t.Helper()
	dir := t.TempDir()
	l, err := events.Open(events.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list {
		l.Write(r)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func start() time.Time { return time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC) }

func TestCountsDecisionsAndBreakdowns(t *testing.T) {
	t0 := start()
	list := []facts.Request{
		{Time: t0, IP: "203.0.113.1", Host: "a.ru", UA: "curl", JA4: "t13d1", Decision: "block", Rule: "block-hosting"},
		{Time: t0.Add(time.Minute), IP: "203.0.113.1", Host: "a.ru", UA: "curl", JA4: "t13d1", Decision: "block", Rule: "block-hosting"},
		{Time: t0.Add(2 * time.Minute), IP: "203.0.113.2", Host: "a.ru", UA: "curl", JA4: "t13d1", Decision: "ratelimit", Rule: "rl-api"},
		{Time: t0.Add(3 * time.Minute), IP: "198.51.100.9", Host: "b.ru", UA: "Mozilla", JA4: "t13d2", Decision: "pass"},
	}
	s, err := Build(Options{Dir: logDir(t, list)})
	if err != nil {
		t.Fatal(err)
	}

	if s.Events != 4 || s.IPCount != 3 || s.HostCount != 2 {
		t.Errorf("%d events, %d addresses, %d hosts; want 4, 3, 2", s.Events, s.IPCount, s.HostCount)
	}
	if s.Decisions[proxy.ActionBlock] != 2 || s.Decisions[proxy.ActionRatelimit] != 1 || s.Decisions[proxy.ActionPass] != 1 {
		t.Errorf("decisions %v", s.Decisions)
	}
	if s.Blocked() != 3 {
		t.Errorf("blocked %d, want 3", s.Blocked())
	}
	if len(s.Rules) == 0 || s.Rules[0].Value != "block-hosting" || s.Rules[0].Count != 2 {
		t.Errorf("top rules: %+v", s.Rules)
	}

	// How many addresses a fingerprint spans is the second number,
	// without which the first means nothing.
	if len(s.JA4) == 0 || s.JA4[0].Value != "t13d1" || s.JA4[0].IPs != 2 {
		t.Errorf("ja4 breakdown: %+v", s.JA4)
	}
}

// An event without a recorded decision counts as passed: in the log
// before the rules appeared there was no decision at all.
func TestAnEmptyDecisionCountsAsPass(t *testing.T) {
	s, err := Build(Options{Dir: logDir(t, []facts.Request{
		{Time: start(), IP: "203.0.113.1", Host: "a.ru"},
	})})
	if err != nil {
		t.Fatal(err)
	}
	if s.Decisions[proxy.ActionPass] != 1 {
		t.Errorf("decisions %v", s.Decisions)
	}
}

// What the node does not know is the main thing on the overview page for
// someone who does not pay yet: while the network has no class and the
// fingerprint is nameless, rules have to be written blind.
func TestUnknown(t *testing.T) {
	t0 := start()
	list := []facts.Request{
		{Time: t0, IP: "203.0.113.1", Host: "a.ru", UA: "Mozilla/5.0 (compatible; Googlebot/2.1)"},
		{Time: t0, IP: "203.0.113.2", Host: "a.ru", UA: "curl", NetClass: "hosting", Family: "curl"},
		{Time: t0, IP: "203.0.113.3", Host: "a.ru", UA: "GPTBot/1.0"},
		{Time: t0, IP: "66.249.66.1", Host: "a.ru", UA: "Mozilla/5.0 (compatible; Googlebot/2.1)",
			NetClass: "crawler", Family: "chrome"},
	}
	s, err := Build(Options{Dir: logDir(t, list)})
	if err != nil {
		t.Fatal(err)
	}

	if s.Unknown.NoNetClass != 2 || s.Unknown.NoFamily != 2 {
		t.Errorf("without a network class %d, without a family %d; want 2 and 2",
			s.Unknown.NoNetClass, s.Unknown.NoFamily)
	}
	if share := s.ShareWithoutNetClass(); share != 0.5 {
		t.Errorf("share without a network class %.3f", share)
	}

	// A claim is confirmed only by a crawler network from the fact set:
	// the same Googlebot string from anywhere else stays a claim, and the
	// admin UI must say so plainly.
	got := map[string]Crawler{}
	for _, row := range s.Unknown.SelfDeclaredCrawlers {
		got[row.Value] = row
	}
	if g := got["googlebot"]; g.Count != 2 || g.Verified != 1 || g.Unverified() != 1 {
		t.Errorf("googlebot: %+v", g)
	}
	if g := got["gptbot"]; g.Count != 1 || g.Verified != 0 {
		t.Errorf("gptbot: %+v", g)
	}
}

func TestTimeSeries(t *testing.T) {
	t0 := start()
	var list []facts.Request
	for i := 0; i < 60; i++ {
		decision := "pass"
		if i%3 == 0 {
			decision = "block"
		}
		list = append(list, facts.Request{
			Time: t0.Add(time.Duration(i) * time.Minute),
			IP:   "203.0.113.1", Host: "a.ru", Decision: decision,
		})
	}
	s, err := Build(Options{
		Dir:  logDir(t, list),
		From: t0, To: t0.Add(time.Hour), Buckets: 6,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Series) != 6 {
		t.Fatalf("%d buckets, want 6", len(s.Series))
	}
	total, blocked := 0, 0
	for _, point := range s.Series {
		total += point.Events
		blocked += point.Blocked
	}
	if total != 60 || blocked != 20 {
		t.Errorf("the series holds %d events and %d blocks; want 60 and 20", total, blocked)
	}
	if s.Series[0].Events != 10 {
		t.Errorf("the first bucket holds %d events, want 10", s.Series[0].Events)
	}
}

// What the node cut off is not the site's error: a 403 from a rule
// counted among the site's 4xx would send a human looking for a broken
// page that is not there.
func TestAnswersKeepTheNodeApartFromTheSite(t *testing.T) {
	t0 := start()
	list := []facts.Request{
		{Time: t0, IP: "203.0.113.1", Host: "a.ru", Path: "/", Decision: "pass", Status: 200, Bytes: 1000},
		{Time: t0, IP: "203.0.113.1", Host: "a.ru", Path: "/old", Decision: "pass", Status: 301},
		{Time: t0, IP: "203.0.113.2", Host: "a.ru", Path: "/wp-login.php", Decision: "pass", Status: 404},
		{Time: t0, IP: "203.0.113.3", Host: "a.ru", Path: "/api", Decision: "allow", Status: 502},
		{Time: t0, IP: "203.0.113.4", Host: "a.ru", Path: "/", Decision: "block", Rule: "r", Status: 403},
		{Time: t0, IP: "203.0.113.4", Host: "a.ru", Path: "/", Decision: "ratelimit", Rule: "rl", Status: 429},
		// Written before the status field existed.
		{Time: t0, IP: "203.0.113.5", Host: "a.ru", Path: "/"},
	}
	s, err := Build(Options{Dir: logDir(t, list)})
	if err != nil {
		t.Fatal(err)
	}

	want := [AnswerCount]int{1, 1, 1, 1, 2, 1}
	if s.Answers != want {
		t.Errorf("answers %v, want %v", s.Answers, want)
	}
	for _, row := range s.Statuses {
		if row.Value == "403" || row.Value == "429" {
			t.Errorf("the node's own %s is among the site's answer codes: %+v", row.Value, s.Statuses)
		}
	}
	if len(s.ServerErrorPaths) != 1 || s.ServerErrorPaths[0].Value != "/api" {
		t.Errorf("paths with 5xx: %+v", s.ServerErrorPaths)
	}
	if len(s.ClientErrorPaths) != 1 || s.ClientErrorPaths[0].Value != "/wp-login.php" {
		t.Errorf("paths with 4xx: %+v", s.ClientErrorPaths)
	}
	if s.Bytes != 1000 {
		t.Errorf("bytes %d, want 1000", s.Bytes)
	}

	var inSeries [AnswerCount]int
	for _, p := range s.Series {
		for a, n := range p.Answers {
			inSeries[a] += n
		}
	}
	if inSeries != want {
		t.Errorf("the series holds %v, the totals %v: the chart and the ring would disagree", inSeries, want)
	}
}

// The site's answer time is counted over what reached the site: blocks
// are answered in microseconds and would pull every percentile to zero
// exactly when the node is busiest.
func TestLatencyLeavesBlocksOut(t *testing.T) {
	t0 := start()
	var list []facts.Request
	for i := 1; i <= 100; i++ {
		list = append(list, facts.Request{
			Time: t0, IP: "203.0.113.1", Host: "a.ru", Decision: "pass",
			Status: 200, Duration: time.Duration(i) * time.Millisecond,
		})
	}
	for i := 0; i < 300; i++ {
		list = append(list, facts.Request{
			Time: t0, IP: "203.0.113.2", Host: "a.ru", Decision: "block",
			Status: 403, Duration: 10 * time.Microsecond,
		})
	}
	s, err := Build(Options{Dir: logDir(t, list)})
	if err != nil {
		t.Fatal(err)
	}

	l := s.Latency
	if l.Count != 100 {
		t.Errorf("%d answers timed, want 100", l.Count)
	}
	// The histogram is off by at most a quarter, and never above the
	// longest answer seen.
	if l.P50 < 50*time.Millisecond || l.P50 > 63*time.Millisecond {
		t.Errorf("p50 %v, want 50–63ms", l.P50)
	}
	if l.P99 < 99*time.Millisecond || l.P99 > 100*time.Millisecond {
		t.Errorf("p99 %v, want 99–100ms", l.P99)
	}
}

func TestStatusFilter(t *testing.T) {
	t0 := start()
	dir := logDir(t, []facts.Request{
		{Time: t0, IP: "203.0.113.1", Host: "a.ru", Path: "/missing", Decision: "pass", Status: 404},
		{Time: t0.Add(time.Second), IP: "203.0.113.2", Host: "a.ru", Path: "/", Decision: "block", Status: 403},
		{Time: t0.Add(2 * time.Second), IP: "203.0.113.3", Host: "a.ru", Path: "/", Decision: "ratelimit", Status: 429},
	})

	cases := map[string][]string{
		"4xx":     {"203.0.113.1"},
		"403":     {"203.0.113.2"},
		"blocked": {"203.0.113.3", "203.0.113.2"},
		"5xx":     nil,
	}
	for status, want := range cases {
		list, err := Latest(dir, Filter{Status: status}, 10)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range list {
			got = append(got, r.IP)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("status=%s selected %v, want %v", status, got, want)
		}
	}
}

func TestLatestNewestFirst(t *testing.T) {
	t0 := start()
	var list []facts.Request
	for i := 0; i < 10; i++ {
		list = append(list, facts.Request{
			Time: t0.Add(time.Duration(i) * time.Minute),
			IP:   fmt.Sprintf("203.0.113.%d", i), Host: "a.ru", Path: fmt.Sprintf("/%d", i),
		})
	}
	dir := logDir(t, list)

	latest, err := Latest(dir, Filter{}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 3 {
		t.Fatalf("got %d events, asked for 3", len(latest))
	}
	if latest[0].Path != "/9" || latest[2].Path != "/7" {
		t.Errorf("the order is not newest to oldest: %s, %s", latest[0].Path, latest[2].Path)
	}
}

func TestFiltersCombineWithAnd(t *testing.T) {
	t0 := start()
	list := []facts.Request{
		{Time: t0, IP: "203.0.113.1", Host: "a.ru", Decision: "block", Rule: "p1", UA: "curl"},
		{Time: t0.Add(time.Minute), IP: "203.0.113.2", Host: "b.ru", Decision: "block", Rule: "p1", UA: "curl"},
		{Time: t0.Add(2 * time.Minute), IP: "203.0.113.3", Host: "a.ru", Decision: "pass", UA: "Mozilla", Shadow: []string{"p2"}},
	}
	dir := logDir(t, list)

	checks := []struct {
		name   string
		filter Filter
		want   int
	}{
		{"by host", Filter{Host: "a.ru"}, 2},
		{"by decision", Filter{Decision: "block"}, 2},
		{"host and decision together", Filter{Host: "a.ru", Decision: "block"}, 1},
		{"by rule", Filter{Rule: "p1"}, 2},
		{"by shadow", Filter{Rule: "p2"}, 1},
		{"by address", Filter{IP: "203.0.113.3"}, 1},
		{"search over the UA", Filter{Search: "curl"}, 2},
		{"the search finds nothing", Filter{Search: "made up"}, 0},
		{"the passed ones", Filter{Decision: "pass"}, 1},
	}
	for _, c := range checks {
		found, err := Latest(dir, c.filter, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != c.want {
			t.Errorf("%s: found %d, want %d", c.name, len(found), c.want)
		}
	}
}

// An empty log is the ordinary state of a node that has just been
// installed. The admin UI must open on it too.
func TestAnEmptyLog(t *testing.T) {
	dir := t.TempDir()
	s, err := Build(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if s.Events != 0 || s.Series != nil {
		t.Errorf("on an empty log: %d events, series %v", s.Events, s.Series)
	}
	if _, err := Latest(dir, Filter{}, 10); err != nil {
		t.Errorf("the event list on an empty log: %v", err)
	}
}

// The log directory may not exist at all — until the first event.
func TestNoDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "none")
	if _, err := Build(Options{Dir: path}); err == nil {
		t.Error("a missing directory passed silently")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("the directory created itself")
	}
}
