// Package summary computes from the event log what the admin UI shows.
//
// It counts on top of the same reader as the rule replay: the numbers in
// the admin UI and the numbers in a replay must agree, otherwise a human
// has nothing to decide by which of them to believe.
package summary

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
)

// MaxKeys is how many distinct values to count within one breakdown.
// Beyond that only the total counter grows: a summary over a day must not
// eat the memory of a node that is serving traffic at the same time.
const MaxKeys = 200_000

// Answer is the class of the answer a client got.
//
// What the node cut off is a class of its own rather than a 403 among the
// site's 4xx: otherwise the node doing its job would look like the site
// failing, and a human would go looking for a broken page that is not
// there.
type Answer int

const (
	AnswerOK          Answer = iota // 2xx from the site
	AnswerRedirect                  // 3xx from the site
	AnswerClientError               // 4xx from the site
	AnswerServerError               // 5xx from the site, the node's 502 included
	AnswerBlocked                   // not let through by a rule
	AnswerNone                      // no status recorded: events older than the field

	// AnswerCount is how many classes there are.
	AnswerCount
)

var answerNames = [AnswerCount]string{"2xx", "3xx", "4xx", "5xx", "blocked", "none"}

// String is the name of the class, the same one the event filter takes.
func (a Answer) String() string {
	if a < 0 || a >= AnswerCount {
		return ""
	}
	return answerNames[a]
}

// AnswerOf classifies a request by its outcome.
//
// The node's own 404 for an unknown host and its 502 for a silent
// upstream count as the site's: to the visitor there is no difference,
// and both mean something is wrong with the site rather than with the
// client.
func AnswerOf(r *facts.Request) Answer {
	if r.Decision == proxy.ActionBlock || r.Decision == proxy.ActionRatelimit {
		return AnswerBlocked
	}
	switch {
	case r.Status >= 500:
		return AnswerServerError
	case r.Status >= 400:
		return AnswerClientError
	case r.Status >= 300:
		return AnswerRedirect
	case r.Status >= 100:
		return AnswerOK
	default:
		return AnswerNone
	}
}

// Options of a summary.
type Options struct {
	Dir      string
	From, To time.Time

	// Top is how many rows to keep in each breakdown.
	Top int

	// Buckets is how many intervals to split the period into for the time
	// series.
	Buckets int
}

func (o *Options) applyDefaults() {
	if o.Top <= 0 {
		o.Top = 10
	}
	if o.Buckets <= 0 {
		o.Buckets = 24
	}
}

// Row is a line of a breakdown: the value, how many requests and from how
// many addresses.
//
// The addresses are not there for completeness: the same fingerprint over
// three thousand addresses means live people, and over seven means a rank
// tracker. Without the second number the first means nothing.
type Row struct {
	Value string `json:"value"`
	Count int    `json:"count"`
	IPs   int    `json:"ips"`
}

// Point of a time series.
type Point struct {
	Time    time.Time        `json:"t"`
	Events  int              `json:"events"`
	Blocked int              `json:"blocked"`
	Answers [AnswerCount]int `json:"answers"`
}

// Latency is how long the site took to answer, by percentiles.
//
// Only the requests that reached the site are counted: a block is answered
// by the node in microseconds and would drag every percentile down to
// zero exactly when the node is busiest.
type Latency struct {
	Count int           `json:"count"`
	P50   time.Duration `json:"p50"`
	P95   time.Duration `json:"p95"`
	P99   time.Duration `json:"p99"`
}

// Unknown is what the node does not know about its own visitors.
//
// This is not an ornament of the summary but its whole point for someone
// who does not pay yet: while half the traffic has no network class and
// the fingerprints are nameless, rules have to be written blind.
type Unknown struct {
	NoNetClass int `json:"no_net_class"`
	NoFamily   int `json:"no_family"`

	// SelfDeclaredCrawlers are the clients that called themselves a known
	// crawler. The node cannot verify such a claim without the bases:
	// anyone at all can put the string "Googlebot" on themselves, and a
	// reverse DNS lookup needs the network.
	SelfDeclaredCrawlers []Row `json:"self_declared_crawlers"`
}

// Summary is everything the admin UI shows on its overview page.
type Summary struct {
	From, To time.Time `json:"-"`

	Events    int   `json:"events"`
	Read      int   `json:"read"`
	Broken    int   `json:"broken"`
	IPCount   int   `json:"ip_count"`
	HostCount int   `json:"host_count"`
	Bytes     int64 `json:"bytes"`

	// Truncated says whether any breakdown hit the key limit. Keeping
	// quiet about that is not allowed: the numbers in such a breakdown
	// are incomplete.
	Truncated bool `json:"truncated"`

	Decisions map[string]int   `json:"decisions"`
	Answers   [AnswerCount]int `json:"answers"`
	Latency   Latency          `json:"latency"`

	Rules   []Row `json:"rules"`
	Shadows []Row `json:"shadows"`
	Hosts   []Row `json:"hosts"`
	IPs     []Row `json:"ips"`
	JA4     []Row `json:"ja4"`
	UA      []Row `json:"ua"`
	Paths   []Row `json:"paths"`

	// Statuses are the codes the site answered with; what the node cut off
	// is not among them, it is in Rules.
	Statuses []Row `json:"statuses"`

	// ServerErrorPaths and ClientErrorPaths are where the site failed:
	// the first is a broken page, the second is most often somebody
	// probing for one.
	ServerErrorPaths []Row `json:"server_error_paths"`
	ClientErrorPaths []Row `json:"client_error_paths"`

	Unknown Unknown `json:"unknown"`
	Series  []Point `json:"series"`
}

// Blocked is how many requests the node did not let through.
func (s *Summary) Blocked() int {
	return s.Decisions[proxy.ActionBlock] + s.Decisions[proxy.ActionRatelimit]
}

// ShareWithoutNetClass is the fraction of requests whose network is
// entirely unknown. The very line that one day brings a human to buy a
// subscription.
func (s *Summary) ShareWithoutNetClass() float64 {
	if s.Events == 0 {
		return 0
	}
	return float64(s.Unknown.NoNetClass) / float64(s.Events)
}

// ShareWithoutFamily is the fraction of requests with a nameless
// fingerprint.
func (s *Summary) ShareWithoutFamily() float64 {
	if s.Events == 0 {
		return 0
	}
	return float64(s.Unknown.NoFamily) / float64(s.Events)
}

// Build reads the log and computes the summary.
func Build(o Options) (*Summary, error) {
	o.applyDefaults()

	s := &Summary{From: o.From, To: o.To, Decisions: map[string]int{}}
	breakdowns := map[string]*breakdown{
		"rules": newBreakdown(), "shadows": newBreakdown(),
		"hosts": newBreakdown(), "ips": newBreakdown(),
		"ja4": newBreakdown(), "ua": newBreakdown(), "paths": newBreakdown(),
		"crawlers": newBreakdown(), "statuses": newBreakdown(),
		"server_errors": newBreakdown(), "client_errors": newBreakdown(),
	}
	ips := map[string]struct{}{}
	var latency histogram

	// A histogram by minutes rather than a list of times: over a day that
	// is fifteen hundred entries instead of one mark per request. The
	// summary must not noticeably occupy a node that is serving traffic
	// at the same time.
	minutes := map[int64]*[AnswerCount]int{}
	var first, last time.Time

	result, err := events.Read(events.Filter{Dir: o.Dir, From: o.From, To: o.To},
		func(r facts.Request) error {
			s.Events++
			s.Decisions[decisionOr(r.Decision)]++
			s.Bytes += r.Bytes

			answer := AnswerOf(&r)
			s.Answers[answer]++
			switch answer {
			case AnswerServerError:
				breakdowns["server_errors"].add(r.Path, r.IP)
			case AnswerClientError:
				breakdowns["client_errors"].add(r.Path, r.IP)
			}
			if answer != AnswerBlocked && answer != AnswerNone {
				breakdowns["statuses"].add(strconv.Itoa(r.Status), r.IP)
				latency.add(r.Duration)
			}

			if r.IP != "" && len(ips) < MaxKeys {
				ips[r.IP] = struct{}{}
			}

			breakdowns["hosts"].add(r.Host, r.IP)
			breakdowns["ips"].add(r.IP, r.IP)
			breakdowns["ja4"].add(r.JA4, r.IP)
			breakdowns["ua"].add(r.UA, r.IP)
			breakdowns["paths"].add(r.Path, r.IP)
			breakdowns["rules"].add(r.Rule, r.IP)
			for _, shadow := range r.Shadow {
				breakdowns["shadows"].add(shadow, r.IP)
			}

			if r.NetClass == "" {
				s.Unknown.NoNetClass++
			}
			if r.Family == "" {
				s.Unknown.NoFamily++
			}
			if name := declaredCrawler(r.UA); name != "" {
				breakdowns["crawlers"].add(name, r.IP)
			}

			if !r.Time.IsZero() {
				if first.IsZero() || r.Time.Before(first) {
					first = r.Time
				}
				if r.Time.After(last) {
					last = r.Time
				}
				minute := r.Time.Unix() / 60
				bucket, ok := minutes[minute]
				if !ok {
					bucket = &[AnswerCount]int{}
					minutes[minute] = bucket
				}
				bucket[answer]++
			}
			return nil
		})
	if err != nil {
		return nil, err
	}

	s.Read, s.Broken = result.Read, result.Broken
	s.IPCount = len(ips)
	s.HostCount = breakdowns["hosts"].distinct()
	s.Latency = Latency{
		Count: latency.count,
		P50:   latency.percentile(0.50),
		P95:   latency.percentile(0.95),
		P99:   latency.percentile(0.99),
	}

	s.Rules = breakdowns["rules"].top(o.Top)
	s.Shadows = breakdowns["shadows"].top(o.Top)
	s.Hosts = breakdowns["hosts"].top(o.Top)
	s.IPs = breakdowns["ips"].top(o.Top)
	s.JA4 = breakdowns["ja4"].top(o.Top)
	s.UA = breakdowns["ua"].top(o.Top)
	s.Paths = breakdowns["paths"].top(o.Top)
	s.Statuses = breakdowns["statuses"].top(o.Top)
	s.ServerErrorPaths = breakdowns["server_errors"].top(o.Top)
	s.ClientErrorPaths = breakdowns["client_errors"].top(o.Top)
	s.Unknown.SelfDeclaredCrawlers = breakdowns["crawlers"].top(o.Top)

	for _, b := range breakdowns {
		if b.truncated {
			s.Truncated = true
		}
	}

	s.Series = series(minutes, first, last, o)
	return s, nil
}

func decisionOr(d string) string {
	if d == "" {
		return proxy.ActionPass
	}
	return d
}

// breakdown counts by a single signal: how many requests and from which
// addresses.
type breakdown struct {
	counters  map[string]*counter
	truncated bool
}

type counter struct {
	count int
	ips   map[string]struct{}
}

func newBreakdown() *breakdown {
	return &breakdown{counters: map[string]*counter{}}
}

func (b *breakdown) add(value, ip string) {
	if value == "" {
		return
	}
	c, ok := b.counters[value]
	if !ok {
		if len(b.counters) >= MaxKeys {
			b.truncated = true
			return
		}
		c = &counter{ips: map[string]struct{}{}}
		b.counters[value] = c
	}
	c.count++
	if ip != "" && len(c.ips) < MaxKeys {
		c.ips[ip] = struct{}{}
	}
}

func (b *breakdown) distinct() int { return len(b.counters) }

func (b *breakdown) top(n int) []Row {
	rows := make([]Row, 0, len(b.counters))
	for value, c := range b.counters {
		rows = append(rows, Row{Value: value, Count: c.count, IPs: len(c.ips)})
	}
	// At an equal number of requests, whatever is spread over fewer
	// addresses comes first: that is exactly what a single client looks
	// like, as opposed to a thousand different ones.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		if rows[i].IPs != rows[j].IPs {
			return rows[i].IPs < rows[j].IPs
		}
		return rows[i].Value < rows[j].Value
	})
	if len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

// latencyBounds are the upper edges of the latency histogram: from half a
// millisecond to two minutes, each a quarter wider than the one before.
// A percentile read off them is off by at most a quarter — enough to
// tell 40 ms from 400 — in a fixed sixty counters, however long the
// period is.
var latencyBounds = func() []time.Duration {
	var bounds []time.Duration
	for b := 500 * time.Microsecond; b < 2*time.Minute; b = time.Duration(float64(b) * 1.25) {
		bounds = append(bounds, b)
	}
	return bounds
}()

type histogram struct {
	counts [64]int
	count  int
	max    time.Duration
}

func (h *histogram) add(d time.Duration) {
	i := sort.Search(len(latencyBounds), func(i int) bool { return latencyBounds[i] >= d })
	h.counts[i]++
	h.count++
	if d > h.max {
		h.max = d
	}
}

// percentile returns the upper edge of the bucket the percentile falls
// into, but never more than the longest answer actually seen.
func (h *histogram) percentile(p float64) time.Duration {
	if h.count == 0 {
		return 0
	}
	rank := int(math.Ceil(p * float64(h.count)))
	seen := 0
	for i, c := range h.counts {
		seen += c
		if seen >= rank {
			if i < len(latencyBounds) && latencyBounds[i] < h.max {
				return latencyBounds[i]
			}
			return h.max
		}
	}
	return h.max
}

// crawlers are the names clients call themselves by. The list is not
// there for blocking but for exactly the opposite: to show a human that
// without the bases the node cannot tell a real crawler from an
// impostor.
var crawlers = []string{
	"googlebot", "bingbot", "yandexbot", "applebot", "petalbot",
	"duckduckbot", "baiduspider", "ahrefsbot", "semrushbot", "mj12bot",
	"dotbot", "bytespider", "gptbot", "claudebot", "ccbot", "perplexitybot",
	"facebookexternalhit", "twitterbot", "telegrambot", "slackbot",
}

func declaredCrawler(ua string) string {
	lower := strings.ToLower(ua)
	for _, name := range crawlers {
		if strings.Contains(lower, name) {
			return name
		}
	}
	return ""
}

// series lays the per-minute histogram out into time buckets.
func series(minutes map[int64]*[AnswerCount]int, first, last time.Time, o Options) []Point {
	if len(minutes) == 0 {
		return nil
	}

	start, end := o.From, o.To
	if start.IsZero() {
		start = first
	}
	if end.IsZero() {
		end = last
	}
	width := end.Sub(start) / time.Duration(o.Buckets)
	if width <= 0 {
		width = time.Minute
	}

	points := make([]Point, o.Buckets)
	for i := range points {
		points[i].Time = start.Add(time.Duration(i) * width)
	}
	for minute, bucket := range minutes {
		t := time.Unix(minute*60, 0).UTC()
		n := int(t.Sub(start) / width)
		if n < 0 {
			n = 0
		}
		if n >= o.Buckets {
			n = o.Buckets - 1
		}
		for a, count := range bucket {
			points[n].Answers[a] += count
			points[n].Events += count
		}
		points[n].Blocked += bucket[AnswerBlocked]
	}
	return points
}

// Filter selects the events for the log page.
//
// The fields are combined by "and": with a host and a decision set, the
// events shown are those where both matched.
type Filter struct {
	Host     string
	Decision string
	Rule     string
	IP       string
	JA4      string
	Search   string // a substring of the User-Agent or the path

	// Status is either an exact code, "502", or an answer class, "5xx"
	// or "blocked". A class is matched the way the overview counts it, so
	// that a click on "4xx" shows the site's 4xx and not the node's 403s.
	Status string
}

func (f *Filter) matches(r *facts.Request) bool {
	if f.Host != "" && r.Host != f.Host {
		return false
	}
	if f.Decision != "" && decisionOr(r.Decision) != f.Decision {
		return false
	}
	if f.Rule != "" && r.Rule != f.Rule && !contains(r.Shadow, f.Rule) {
		return false
	}
	if f.IP != "" && r.IP != f.IP {
		return false
	}
	if f.JA4 != "" && r.JA4 != f.JA4 {
		return false
	}
	if f.Status != "" && !statusMatches(f.Status, r) {
		return false
	}
	if f.Search != "" {
		needle := strings.ToLower(f.Search)
		if !strings.Contains(strings.ToLower(r.UA), needle) &&
			!strings.Contains(strings.ToLower(r.Path), needle) {
			return false
		}
	}
	return true
}

func statusMatches(want string, r *facts.Request) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	if code, err := strconv.Atoi(want); err == nil {
		return r.Status == code
	}
	return AnswerOf(r).String() == want
}

func contains(list []string, what string) bool {
	for _, s := range list {
		if s == what {
			return true
		}
	}
	return false
}

// Latest returns the most recent events matching the filter, newest
// first.
//
// The files are read from the end: the last hundred events lie in the
// tail of the last file, and there is no point rereading two weeks of log
// for their sake.
func Latest(dir string, f Filter, n int) ([]facts.Request, error) {
	if n <= 0 {
		n = 100
	}
	files, err := events.Files(dir)
	if err != nil {
		return nil, err
	}

	collected := make([]facts.Request, 0, n)
	for _, path := range events.Reversed(files) {
		// Within a file the lines go in ascending time order, so the file
		// is read whole and what is needed is taken from the end.
		inFile := make([]facts.Request, 0, n)
		if _, err := events.Read(events.Filter{Files: []string{path}}, func(r facts.Request) error {
			if f.matches(&r) {
				inFile = append(inFile, r)
			}
			return nil
		}); err != nil {
			return nil, err
		}

		for i := len(inFile) - 1; i >= 0 && len(collected) < n; i-- {
			collected = append(collected, inFile[i])
		}
		if len(collected) >= n {
			break
		}
	}
	return collected, nil
}
