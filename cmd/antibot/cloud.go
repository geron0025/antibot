package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geron0025/antibot/internal/admin"
	"github.com/geron0025/antibot/internal/aggregate"
	"github.com/geron0025/antibot/internal/catalog"
	"github.com/geron0025/antibot/internal/cloudlink"
	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/facts"
)

// aggregateSink is the aggregator's place in the hot path, held whether
// or not there is an aggregator.
//
// The sink is wired in once, at startup, because the request path must
// not be rebuilt when somebody ticks a checkbox. An atomic pointer and
// a nil check per request is the whole cost of the owner being able to
// turn the sending on without restarting his node.
type aggregateSink struct {
	ptr atomic.Pointer[aggregate.Aggregator]
}

func (s *aggregateSink) Write(r facts.Request) {
	if agg := s.ptr.Load(); agg != nil {
		agg.Write(r)
	}
}

// Status is the aggregator's, or the zero one when nothing is sending.
func (s *aggregateSink) Status() (aggregate.Status, bool) {
	if agg := s.ptr.Load(); agg != nil {
		return agg.Status(), true
	}
	return aggregate.Status{}, false
}

// cloudLink runs the two directions of the wire and follows the owner's
// answer.
//
// Both directions used to be decided once, at startup, from the
// settings file: with a token they ran, without one they did not exist.
// That is still true of a node whose settings name a token — nothing
// about it changed. What changed is the node that got its token from the
// admin UI a minute ago: it would otherwise sit doing nothing until
// somebody restarted it, right at the moment the owner is deciding
// whether any of this works.
type cloudLink struct {
	cfg   config.Config
	state *cloudlink.Store
	facts *catalog.Store
	sink  *aggregateSink
	node  func() string
	serve func(host string) bool
	log   *slog.Logger

	mu      sync.Mutex
	ctx     context.Context
	fetch   context.CancelFunc
	agg     *aggregate.Aggregator
	aggStop context.CancelFunc
	aggDone chan struct{}
}

// settings is what the two sources add up to.
type settings struct {
	Token      string
	FactsURL   string
	IngestURL  string
	Fetching   bool
	Sending    bool
	FromConfig bool
}

// effective folds the settings file and the owner's answer together.
//
// The file wins wherever it says anything, exactly as it does for the
// domains and the certificates: what the machine's owner wrote by hand
// must not be overridden through a web page. A settings file naming a
// token is therefore a node that behaves as it always did, and the
// checkboxes are shown as what they are — not in charge here.
func (l *cloudLink) effective() settings {
	st := l.state.State()

	s := settings{
		Token:     firstSet(l.cfg.Cloud.Token, st.Token),
		FactsURL:  firstSet(l.cfg.Facts.URL, st.FactsURL),
		IngestURL: firstSet(l.cfg.Cloud.URL, st.IngestURL),
	}
	s.FromConfig = l.cfg.Cloud.Token != ""

	wantFacts, wantAggregates := st.Facts, st.Aggregates
	if s.FromConfig {
		// A token in the settings file is the owner saying yes in the
		// place that outranks the page.
		wantFacts, wantAggregates = true, true
	}

	s.Fetching = wantFacts && l.cfg.Facts.Enabled && s.Token != "" && s.FactsURL != ""
	s.Sending = wantAggregates && s.Token != "" && s.IngestURL != ""
	return s
}

// registerURL is where a node with no token asks for one.
func (l *cloudLink) registerURL() string {
	if l.cfg.Cloud.RegisterURL != "" {
		return l.cfg.Cloud.RegisterURL
	}
	if l.cfg.Cloud.URL != "" {
		// The settings name the whole address of the aggregate door,
		// and registration is the door beside it.
		return strings.TrimSuffix(strings.TrimSuffix(l.cfg.Cloud.URL, "/"), "/ingest")
	}
	return cloudlink.DefaultURL
}

// apply brings what is running in line with what is wanted. Safe to
// call as often as anybody likes: it starts and stops nothing that is
// already in the state asked for.
func (l *cloudLink) apply() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ctx == nil {
		return
	}

	want := l.effective()

	switch {
	case want.Fetching && l.fetch == nil:
		fetcher := catalog.NewFetcher(l.facts, want.FactsURL, want.Token,
			l.node(), Version, l.log)
		if fetcher == nil {
			break
		}
		ctx, cancel := context.WithCancel(l.ctx)
		l.fetch = cancel
		go fetcher.Run(ctx, l.cfg.Facts.Interval.Duration())
		l.log.Info("fetching the bases", "url", want.FactsURL)
	case !want.Fetching && l.fetch != nil:
		l.fetch()
		l.fetch = nil
		l.log.Info("the bases are no longer fetched")
	}

	switch {
	case want.Sending && l.agg == nil:
		agg, err := aggregate.Open(aggregate.Options{
			Dir:          l.cfg.Cloud.StateDir,
			URL:          want.IngestURL,
			Token:        want.Token,
			NodeID:       l.node(),
			Version:      Version,
			Interval:     l.cfg.Cloud.Interval.Duration(),
			Served:       l.serve,
			FactsVersion: func() int { return l.facts.Current().Version() },
			Log:          l.log,
		})
		if err != nil {
			// No reason to stop the node: the traffic is served whether
			// or not the cloud hears about it.
			l.log.Error("the aggregate will not be sent", "err", err)
			break
		}
		// Its context is not the signal's: on the way out the process
		// waits for the open window to be saved, and the requests served
		// during the shutdown are counted.
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		l.agg, l.aggStop, l.aggDone = agg, cancel, done
		l.sink.ptr.Store(agg)
		go func() {
			agg.Run(ctx)
			close(done)
		}()
		l.log.Info("sending the aggregate", "url", want.IngestURL)
	case !want.Sending && l.agg != nil:
		l.stopAggregate()
		l.log.Info("the aggregate is no longer sent")
	}
}

// start ties the link to the life of the node and brings up whatever
// the settings and the answer already ask for.
func (l *cloudLink) start(ctx context.Context) {
	l.mu.Lock()
	l.ctx = ctx
	l.mu.Unlock()
	l.apply()
}

// stop takes both directions down and waits for the open window to
// reach the disk.
func (l *cloudLink) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fetch != nil {
		l.fetch()
		l.fetch = nil
	}
	l.stopAggregate()
}

// stopAggregate is called with the lock held.
func (l *cloudLink) stopAggregate() {
	if l.agg == nil {
		return
	}
	l.sink.ptr.Store(nil)
	l.aggStop()
	<-l.aggDone
	l.agg, l.aggStop, l.aggDone = nil, nil, nil
}

func firstSet(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Answer records the two checkboxes. The change applies at once: the
// store tells the link, and the link starts or stops what it must.
func (l *cloudLink) Answer(facts, aggregates bool) error {
	return l.state.Answer(facts, aggregates, time.Now())
}

// Register asks the cloud for a token for this installation.
//
// The token is written down before anything else happens: the cloud
// issues one per installation and cannot show it twice, so a token that
// arrived and was not saved is a tenant its owner can never use.
func (l *cloudLink) Register(ctx context.Context, facts, aggregates bool) error {
	node := l.node()
	if node == "" {
		return admin.CloudRefusal("this node has no identifier: see the log, " +
			"the file in node_id_file could not be read or created")
	}

	answer, err := cloudlink.Register(ctx, l.registerURL(), node, Version, facts, aggregates, nil)
	if err != nil {
		return cloudWords(err)
	}
	if err := l.state.Keep(*answer, time.Now()); err != nil {
		return err
	}
	return l.state.Answer(facts, aggregates, time.Now())
}

// Forget drops the token and both answers.
func (l *cloudLink) Forget() error { return l.state.Forget() }

// cloudWords turns a failed registration into something the owner can
// act on. The three cases differ in what he should do next, which is
// the only reason they are told apart at all.
func cloudWords(err error) error {
	var soon *cloudlink.TooSoon
	var refused *cloudlink.Refused
	switch {
	case errors.Is(err, cloudlink.ErrAlreadyRegistered):
		return admin.CloudRefusal("this installation already took a token once. " +
			"The cloud keeps only its hash and cannot show it again — write to us, " +
			"or set cloud.token in config.yaml if you still have it")
	case errors.As(err, &soon):
		return admin.CloudRefusal(fmt.Sprintf("the cloud has had enough registrations "+
			"from this address for now; try again in %s", soon.RetryAfter.Round(time.Minute)))
	case errors.As(err, &refused):
		return admin.CloudRefusal("the cloud refused: " + refused.Text)
	default:
		return admin.CloudRefusal("the cloud did not answer: " + err.Error())
	}
}
