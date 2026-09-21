package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/geron0025/antibot/internal/events"
)

// serveService brings up the service listener: a liveness check and
// counters.
//
// A separate port rather than a path on 80 and 443: those serve the
// traffic of the customer's domains, and /healthz on them would turn into
// a page that does not exist on every protected site. This port is not
// published outwards.
func serveService(ctx context.Context, ln net.Listener, log *events.Log, agg *aggregateSink, logger *slog.Logger) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "alive")
	})

	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		stats := map[string]any{
			"version": Version,
			// Dropped events must be visible from the outside: a log that
			// loses events silently is worse than no log at all, because
			// people draw conclusions from it.
			"events_dropped": log.Dropped.Load(),
		}
		// Absent rather than zero while nothing is being sent: zero
		// would claim the sending works and has nothing to report.
		if st, sending := agg.Status(); sending {
			stats["aggregate_dropped"] = st.Dropped
			stats["aggregate_outbox"] = st.Outbox
			if !st.LastSent.IsZero() {
				stats["aggregate_last_sent"] = st.LastSent.UTC().Format(time.RFC3339)
			}
			if st.LastProblem != "" {
				stats["aggregate_problem"] = st.LastProblem
			}
		}
		json.NewEncoder(w).Encode(stats)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown(srv)
	}()

	logger.Info("listening on the service port", "address", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("service port: %w", err)
	}
	return nil
}
