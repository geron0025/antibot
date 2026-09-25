package summary

import (
	"sort"
	"time"

	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/facts"
)

// Crawlers is what the admin UI's tab of verified crawlers shows: the
// crawlers the fact set names, what came from them and what the rules
// did to them.
//
// "Verified" means the network, not the string: a request counts here
// when it came from a range the crawler's owner publishes about itself.
// A self-declared Googlebot from anywhere else is in Declared as a claim.
type Crawlers struct {
	Events int `json:"events"`

	// NoFacts is true when not one request of the period has a network
	// class: without the fact set no crawler can be told from anybody.
	NoFacts bool `json:"no_facts"`

	Owners   []CrawlerOwner `json:"owners"`
	Rules    []CrawlerRule  `json:"rules"`
	Declared []Crawler      `json:"declared"`
}

// CrawlerOwner is one owner of crawler networks. Protected ones are let
// past the blocks by the crawler exception; the others — collectors of
// training data — are named, and what to do with them is the owner's
// call.
type CrawlerOwner struct {
	Owner     string `json:"owner"`
	Protected bool   `json:"protected"`
	Requests  int    `json:"requests"`
	Cut       int    `json:"cut"`
}

// CrawlerRule is a rule that touched verified crawlers: Cut is how many
// of their requests it turned away, Shadow how many it would have in
// shadow mode.
type CrawlerRule struct {
	Rule   string `json:"rule"`
	Cut    int    `json:"cut"`
	Shadow int    `json:"shadow"`
}

// BuildCrawlers reads the log once for the crawlers tab.
func BuildCrawlers(dir string, from, to time.Time) (*Crawlers, error) {
	c := &Crawlers{}
	type ownerKey struct {
		owner     string
		protected bool
	}
	owners := map[ownerKey]*CrawlerOwner{}
	ruleHits := map[string]*CrawlerRule{}
	declared := newBreakdown()
	verified, cut := map[string]int{}, map[string]int{}
	withClass := 0

	hit := func(id string) *CrawlerRule {
		r := ruleHits[id]
		if r == nil {
			r = &CrawlerRule{Rule: id}
			ruleHits[id] = r
		}
		return r
	}

	_, err := events.Read(events.Filter{Dir: dir, From: from, To: to}, func(r facts.Request) error {
		c.Events++
		if r.NetClass != "" {
			withClass++
		}
		blocked := AnswerOf(&r) == AnswerBlocked

		if name := declaredCrawler(r.UA); name != "" {
			declared.add(name, r.IP)
			if r.NetClass == crawlerClass {
				verified[name]++
				if blocked {
					cut[name]++
				}
			}
		}

		if r.NetClass != crawlerClass {
			return nil
		}
		k := ownerKey{r.NetOwner, r.NetProtected}
		o := owners[k]
		if o == nil {
			o = &CrawlerOwner{Owner: r.NetOwner, Protected: r.NetProtected}
			owners[k] = o
		}
		o.Requests++
		if blocked {
			o.Cut++
		}
		// Only the protected are the owner's worry: a rule cutting a
		// collector of training data may well be the point of it.
		if r.NetProtected {
			if blocked && r.Rule != "" {
				hit(r.Rule).Cut++
			}
			for _, id := range r.Shadow {
				hit(id).Shadow++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	c.NoFacts = c.Events > 0 && withClass == 0
	for _, o := range owners {
		c.Owners = append(c.Owners, *o)
	}
	sort.Slice(c.Owners, func(i, j int) bool {
		a, b := c.Owners[i], c.Owners[j]
		if a.Protected != b.Protected {
			return a.Protected
		}
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return a.Owner < b.Owner
	})
	for _, r := range ruleHits {
		c.Rules = append(c.Rules, *r)
	}
	sort.Slice(c.Rules, func(i, j int) bool {
		a, b := c.Rules[i], c.Rules[j]
		if a.Cut+a.Shadow != b.Cut+b.Shadow {
			return a.Cut+a.Shadow > b.Cut+b.Shadow
		}
		return a.Rule < b.Rule
	})
	for _, row := range declared.top(50) {
		c.Declared = append(c.Declared, Crawler{Row: row, Verified: verified[row.Value], Cut: cut[row.Value]})
	}
	return c, nil
}
