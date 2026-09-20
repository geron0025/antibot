package main

import (
	"log/slog"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/catalog"
	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/edgetls"
	"github.com/geron0025/antibot/internal/events"
)

// alertOptions connects the triggers to the node: the thresholds from the
// settings, the probes into the parts they watch, and the command in
// force — the configuration's, or else the one set from the admin UI.
func alertOptions(cfg config.Config, certs *edgetls.Set, eventLog *events.Log, factStore *catalog.Store,
	link *cloudLink, file *alerts.CommandFile, log *slog.Logger) alerts.Options {
	a := cfg.Alerts

	probes := alerts.Probes{
		Certificates: func() []alerts.Certificate {
			list := certs.List()
			out := make([]alerts.Certificate, 0, len(list))
			for _, c := range list {
				out = append(out, alerts.Certificate{Names: c.Names, NotAfter: c.NotAfter})
			}
			return out
		},
		EventsDropped: eventLog.Dropped.Load,
		EventsDir:     cfg.Events.Dir,
		// Asked on every check rather than decided at startup: the
		// owner turns the fetching on and off from the admin UI, and a
		// trigger about a base that has gone stale must not fire at a
		// node that was told to stop fetching an hour ago.
		Facts: func() (int, time.Time, bool) {
			set := factStore.Current()
			return set.Version(), set.CreatedAt(), link.effective().Fetching
		},
		Outbox: func() (int, bool) {
			st, sending := link.sink.Status()
			return st.Outbox, sending
		},
	}

	return alerts.Options{
		Window:           a.Window.Duration(),
		SiteErrorShare:   a.SiteErrorShare,
		SiteMinRequests:  a.SiteMinRequests,
		SpikeFactor:      a.SpikeFactor,
		SpikeMinRequests: a.SpikeMinRequests,
		SpikeMinBlocked:  a.SpikeMinBlocked,
		RuleMinMatches:   a.RuleMinMatches,
		CertDays:         a.CertDays,
		DiskMinBytes:     uint64(a.DiskMinMB) << 20,
		FactsMaxAge:      a.FactsMaxAge.Duration(),
		OutboxMax:        a.OutboxMax,
		Probes:           probes,
		Command: func() string {
			if a.Command != "" {
				return a.Command
			}
			if file != nil {
				if c, err := file.Get(); err == nil {
					return c.Command
				}
			}
			return ""
		},
		Timeout: a.Timeout.Duration(),
		Log:     log,
	}
}
