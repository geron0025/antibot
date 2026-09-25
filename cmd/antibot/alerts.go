package main

import (
	"log/slog"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/catalog"
	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/edgetls"
	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/i18n"
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
		Language: deliveryLanguage(a, file),
		Timeout:  a.Timeout.Duration(),
		Log:      log,
	}
}

// deliveryLanguage is the language of the messages for the command:
// config.yaml when it names one — what the machine's owner wrote by hand
// is not replaced through the admin UI — then the file the admin UI
// writes, read at every message, then English. A command in config.yaml
// takes the file out of play altogether, its language with it: the admin
// UI offers no choice then, and a language nobody sees must not steer.
func deliveryLanguage(a config.Alerts, file *alerts.CommandFile) func() i18n.Lang {
	return func() i18n.Lang {
		if l, ok := i18n.Parse(a.Language); ok {
			return l
		}
		if file != nil && a.Command == "" {
			if c, err := file.Get(); err == nil {
				if l, ok := i18n.Parse(c.Language); ok {
					return l
				}
			}
		}
		return i18n.EN
	}
}
