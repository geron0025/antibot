package admin

import (
	"context"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/control"
)

// coreTimeout bounds one question to the core. The core answers from
// memory in microseconds; a core that takes longer is stuck, and a page
// must not hang with it.
const coreTimeout = 3 * time.Second

func (s *Server) coreContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, coreTimeout)
}

// coreAlerts asks the core for the alerts. An error is a core that did
// not answer; alerts turned off are an answer with Enabled false.
func (s *Server) coreAlerts(ctx context.Context) (control.Alerts, error) {
	ctx, cancel := s.coreContext(ctx)
	defer cancel()
	return s.o.Core.Alerts(ctx)
}

// coreCloud is the link to the cloud, nil while the core is down.
func (s *Server) coreCloud(ctx context.Context) *CloudState {
	ctx, cancel := s.coreContext(ctx)
	defer cancel()
	state, err := s.o.Core.Cloud(ctx)
	if err != nil {
		return nil
	}
	return &state
}

// coreCertificates are the sites' certificates the core serves; empty
// while the core is down.
func (s *Server) coreCertificates(ctx context.Context) []control.Certificate {
	ctx, cancel := s.coreContext(ctx)
	defer cancel()
	list, err := s.o.Core.Certificates(ctx)
	if err != nil {
		return nil
	}
	return list
}

// coreRoutes are the routes from the core's settings file; empty while
// the core is down.
func (s *Server) coreRoutes(ctx context.Context) map[string]string {
	ctx, cancel := s.coreContext(ctx)
	defer cancel()
	routes, err := s.o.Core.Routes(ctx)
	if err != nil {
		return nil
	}
	return routes
}

// reload tells the core a file has changed. The change is on disk
// whatever the core says: a core that is down reads it at its start, and
// one that did not hear reads it at its next look. So a failure is
// logged and not shown as a failure of the change.
func (s *Server) reload(ctx context.Context, what control.Reloadable) {
	ctx, cancel := s.coreContext(ctx)
	defer cancel()
	if err := s.o.Core.Reload(ctx, what); err != nil {
		s.o.Log.Warn("the core was not told to reread a file; it will at its next look",
			"what", string(what), "err", err)
	}
}

// covering finds the certificate that would serve the name, the way the
// core picks one: the exact name first, then a wildcard one level up. A
// "*.example.ru" pattern needs exactly that wildcard name. Of several,
// the one that lasts longest.
func covering(list []control.Certificate, name string) *control.Certificate {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	find := func(want string) *control.Certificate {
		var best *control.Certificate
		for i := range list {
			for _, have := range list[i].Names {
				if strings.EqualFold(have, want) && (best == nil || list[i].NotAfter.After(best.NotAfter)) {
					best = &list[i]
				}
			}
		}
		return best
	}
	if c := find(n); c != nil {
		return c
	}
	if strings.HasPrefix(n, "*.") {
		return nil
	}
	if i := strings.IndexByte(n, '.'); i >= 0 {
		return find("*" + n[i:])
	}
	return nil
}
