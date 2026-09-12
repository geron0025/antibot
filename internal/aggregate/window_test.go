package aggregate

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
)

var t0 = time.Date(2026, 9, 8, 17, 0, 0, 0, time.UTC)

func request(ip, host string) facts.Request {
	return facts.Request{
		Time: t0.Add(time.Minute), IP: ip, Host: host, Method: "GET",
		Path: "/account/42/orders?token=secret", Proto: "HTTP/2.0",
		UA:           "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
		Referer:      "https://shop.example.ru/cart?session=abcdef",
		JA4:          "t13d1516h2_8daaf6152771_02713d6af862",
		H2:           "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		Headers:      "host,user-agent,cookie,authorization",
		HeadersHash:  "9c1185a5c5e9fc54",
		UAMatchesJA4: true, Decision: proxy.ActionPass, Status: 200, Bytes: 1000,
	}
}

// What the protocol promises never leaves the node: the full address,
// the User-Agent string, the path, the header names and values. The
// test looks at the very bytes that would be posted.
func TestNothingPersonalLeaves(t *testing.T) {
	r := request("203.0.113.77", "shop.example.ru")
	w := newWindow(t0)
	w.add(keyOf(&r, nil), &r)

	raw, err := json.Marshal(w.close())
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, secret := range []string{
		"203.0.113.77", "Mozilla", "Chrome/128", "/account", "token=secret",
		"session=abcdef", "authorization", "user-agent,cookie",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("the aggregate carries %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, `"net":"203.0.113.0/24"`) {
		t.Errorf("the network prefix is missing:\n%s", out)
	}
	if !strings.Contains(out, `"ua_family":"chrome"`) {
		t.Errorf("the family is missing:\n%s", out)
	}
}

func TestPrefix(t *testing.T) {
	cases := map[string]string{
		"203.0.113.77":        "203.0.113.0/24",
		"::ffff:203.0.113.77": "203.0.113.0/24",
		"2001:db8:1:2:3::1":   "2001:db8:1::/48",
		"":                    "",
		"not an address":      "",
	}
	for in, want := range cases {
		if got := prefixOf(in); got != want {
			t.Errorf("prefixOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// Host is the client's string. Only a served, well-formed name leaves.
func TestDomainIsOnlyAServedName(t *testing.T) {
	served := func(h string) bool { return h == "shop.example.ru" || h == "xn--e1afmkfd.xn--p1ai" }
	cases := map[string]string{
		"shop.example.ru":          "shop.example.ru",
		"xn--e1afmkfd.xn--p1ai":    "xn--e1afmkfd.xn--p1ai",
		"scanner-junk.example.com": "",
		"198.51.100.1":             "",
		"2001:db8::1":              "",
		"shop.example.ru<script>":  "",
		strings.Repeat("a.", 200):  "",
		"":                         "",
	}
	for in, want := range cases {
		if got := domainOf(in, served); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", in, got, want)
		}
	}
	// Without a list every well-formed name counts, junk still does not.
	if got := domainOf("a.example", nil); got != "a.example" {
		t.Errorf("without a list: %q", got)
	}
	if got := domainOf("a b", nil); got != "" {
		t.Errorf("junk without a list: %q", got)
	}
}

func TestCounters(t *testing.T) {
	w := newWindow(t0)
	add := func(mut func(*facts.Request)) {
		r := request("203.0.113.1", "shop.example.ru")
		mut(&r)
		w.add(keyOf(&r, nil), &r)
	}
	add(func(r *facts.Request) {})
	add(func(r *facts.Request) { r.Decision, r.Status, r.Bytes = proxy.ActionBlock, 403, 0 })
	add(func(r *facts.Request) { r.Decision, r.Status, r.Bytes = proxy.ActionRatelimit, 429, 0 })
	// A shadow rule would split the row: TestRulesSplitRows covers it.
	add(func(r *facts.Request) { r.Method = "HEAD"; r.Path = "/other" })
	add(func(r *facts.Request) { r.Method = "PROPFIND-MADE-UP"; r.IP = "203.0.113.2" })

	rows := w.close()
	if len(rows) != 1 {
		t.Fatalf("%d rows, want one", len(rows))
	}
	got := rows[0]
	if got.Requests != 5 || got.Blocked != 1 || got.Limited != 1 || got.Shadowed != 0 {
		t.Errorf("counters: %+v", got)
	}
	if got.Status["2xx"] != 3 || got.Status["4xx"] != 2 {
		t.Errorf("status classes: %v", got.Status)
	}
	if got.Methods["GET"] != 3 || got.Methods["HEAD"] != 1 || got.Methods["OTHER"] != 1 {
		t.Errorf("methods: %v", got.Methods)
	}
	if got.BytesOut != 3000 || got.UniqPaths != 2 || got.UniqAddrs != 2 {
		t.Errorf("bytes %d, paths %d, addrs %d", got.BytesOut, got.UniqPaths, got.UniqAddrs)
	}
	if got.Window != "2026-09-08T17:00:00Z" {
		t.Errorf("window %q", got.Window)
	}
}

// Status and methods are objects even when empty: null breaks the schema.
func TestEmptyClassesAreObjects(t *testing.T) {
	raw, _ := json.Marshal((&counts{}).row(t0, restKey))
	if strings.Contains(string(raw), "null") {
		t.Fatalf("null in %s", raw)
	}
}

func distinct(w *window, n int, requests func(i int) int) {
	for i := 0; i < n; i++ {
		r := request(fmt.Sprintf("10.%d.%d.1", i>>8&255, i&255), "shop.example.ru")
		k := keyOf(&r, nil)
		for j := 0; j < requests(i); j++ {
			w.add(k, &r)
		}
	}
}

// Past MaxRows the smallest fold into one ~rest row, and the total is
// kept: the scale survives the cut.
func TestCollapseKeepsTheTotal(t *testing.T) {
	w := newWindow(t0)
	distinct(w, MaxRows+3, func(i int) int { return i%7 + 1 })

	var total uint64
	for _, c := range w.rows {
		total += c.Requests
	}

	rows := w.close()
	if len(rows) != MaxRows {
		t.Fatalf("%d rows, want %d", len(rows), MaxRows)
	}
	var sum uint64
	for _, r := range rows {
		sum += r.Requests
	}
	if sum != total {
		t.Errorf("total %d after folding, %d before", sum, total)
	}

	last := rows[len(rows)-1]
	if last.Key != restKey || last.Window != "2026-09-08T17:00:00Z" {
		t.Errorf("the last row is not ~rest: %+v", last.Key)
	}
	if last.UniqAddrs < 3 {
		t.Errorf("the folded row lost its addresses: %d", last.UniqAddrs)
	}
	// The largest come first.
	if rows[0].Requests != 7 {
		t.Errorf("the first row has %d requests, want the largest", rows[0].Requests)
	}
}

// Exactly MaxRows keys is no reason to fold.
func TestNoFoldAtTheLimit(t *testing.T) {
	w := newWindow(t0)
	distinct(w, MaxRows, func(int) int { return 1 })
	rows := w.close()
	if len(rows) != MaxRows || rows[len(rows)-1].Key == restKey {
		t.Fatalf("%d rows, last %+v", len(rows), rows[len(rows)-1].Key)
	}
}

// Memory is bounded while the window is open, not only when it is sent.
func TestLiveLimitBoundsMemory(t *testing.T) {
	w := newWindow(t0)
	distinct(w, liveLimit+50, func(int) int { return 1 })
	if len(w.rows) != liveLimit {
		t.Fatalf("%d keys held, limit %d", len(w.rows), liveLimit)
	}
	if w.overflow == nil || w.overflow.Requests != 50 {
		t.Fatalf("overflow %+v", w.overflow)
	}

	rows := w.close()
	var sum uint64
	for _, r := range rows {
		sum += r.Requests
	}
	if len(rows) != MaxRows || sum != liveLimit+50 {
		t.Errorf("%d rows with %d requests", len(rows), sum)
	}
}

// The rule that decided and the shadow rules are in the key: every row
// is decided one way, so its cookie count belongs to one rule.
func TestRulesSplitRows(t *testing.T) {
	w := newWindow(t0)
	add := func(mut func(*facts.Request)) {
		r := request("203.0.113.1", "shop.example.ru")
		mut(&r)
		w.add(keyOf(&r, nil), &r)
	}
	add(func(r *facts.Request) { r.Cookie = true })
	add(func(r *facts.Request) { r.Decision, r.Rule, r.Status = proxy.ActionBlock, "block-hosting", 403 })
	add(func(r *facts.Request) {
		r.Decision, r.Rule, r.Status, r.Cookie = proxy.ActionBlock, "block-hosting", 403, true
	})
	add(func(r *facts.Request) { r.Shadow = []string{"watch-b", "watch-a"} })
	add(func(r *facts.Request) { r.Shadow = []string{"watch-a", "watch-b", "watch-a"} })

	rows := map[string]Row{}
	for _, row := range w.close() {
		shadow, _ := json.Marshal(row.Shadow)
		rows[row.Rule+" "+string(shadow)] = row
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows, want 3: %+v", len(rows), rows)
	}
	if r := rows[" []"]; r.Requests != 1 || r.WithCookie != 1 {
		t.Errorf("undecided: %+v", r)
	}
	if r := rows["block-hosting []"]; r.Requests != 2 || r.Blocked != 2 || r.WithCookie != 1 {
		t.Errorf("block-hosting: %+v", r)
	}
	if r := rows[` ["watch-a","watch-b"]`]; r.Requests != 2 || r.Shadowed != 2 || r.WithCookie != 0 {
		t.Errorf("shadow: %+v", r)
	}
}

// A rule id is the owner's free text. It goes out clipped and without
// control characters, and it cannot break the list it is part of.
func TestRuleIDsAreCleaned(t *testing.T) {
	r := request("203.0.113.1", "shop.example.ru")
	r.Rule = strings.Repeat("я", 100) + "\xff"
	r.Shadow = []string{"a\nb", "c"}
	k := keyOf(&r, nil)
	if n := utf8.RuneCountInString(k.Rule); n != maxRuleID || !utf8.ValidString(k.Rule) {
		t.Errorf("rule of %d characters, valid %v", n, utf8.ValidString(k.Rule))
	}
	if raw, _ := json.Marshal(k.Shadow); string(raw) != `["ab","c"]` {
		t.Errorf("shadow %s", raw)
	}

	// The key comes back from the saved state as it was.
	var back Key
	raw, _ := json.Marshal(k)
	if err := json.Unmarshal(raw, &back); err != nil || back != k {
		t.Errorf("state round trip: %v, %+v", err, back)
	}

	many := make([]string, 40)
	for i := range many {
		many[i] = fmt.Sprintf("watch-%02d", i)
	}
	r.Shadow = many
	var list []string
	raw, _ = json.Marshal(keyOf(&r, nil).Shadow)
	json.Unmarshal(raw, &list)
	if len(list) != maxShadow || list[0] != "watch-00" {
		t.Errorf("shadow rules %v", list)
	}

	r.Shadow = nil
	if raw, _ := json.Marshal(keyOf(&r, nil).Shadow); string(raw) != "[]" {
		t.Errorf("no shadow rules is %s, want an empty array", raw)
	}
}
