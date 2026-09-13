package admin

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// CloudState is what the overview says about the node's link to the
// cloud: whether there is one at all, and how both directions fare.
//
// The first line matters most for a node without a token: it says in so
// many words that nothing leaves it. An owner who installed a node from a
// public repository has every reason to ask.
type CloudState struct {
	// Token is whether cloud.token is set. Without one nothing leaves
	// the node — neither aggregates nor requests for the bases.
	Token bool

	FactsVersion int
	FactsBuilt   time.Time
	Fetching     bool

	Outbox      int
	LastSent    time.Time
	LastProblem string
}

// certificate keeps the admin UI's own pair and rereads the files when
// they change: a renewed certificate is taken up without a restart, the
// way the sites' certificates are. A pair that does not load — certbot
// caught between writing the chain and the key — keeps the previous one
// in force and is tried again at the next look.
type certificate struct {
	certFile, keyFile string
	log               *slog.Logger
	every             time.Duration

	mu      sync.Mutex
	current *tls.Certificate
	checked time.Time
	certMod time.Time
	keyMod  time.Time
}

// loadCertificate loads the pair now: before any port is taken, so that a
// broken pair stops the start instead of breaking the first handshake.
func loadCertificate(certFile, keyFile string, log *slog.Logger) (*certificate, error) {
	c := &certificate{certFile: certFile, keyFile: keyFile, log: log, every: 30 * time.Second}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.reloadLocked(time.Now(), true); err != nil {
		return nil, err
	}
	return c, nil
}

// get hands the pair to a handshake, looking at the files at most once
// per interval.
func (c *certificate) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := time.Now(); now.Sub(c.checked) >= c.every {
		c.reloadLocked(now, false)
	}
	return c.current, nil
}

func (c *certificate) reloadLocked(now time.Time, first bool) error {
	c.checked = now
	certInfo, certErr := os.Stat(c.certFile)
	keyInfo, keyErr := os.Stat(c.keyFile)
	if !first && certErr == nil && keyErr == nil &&
		certInfo.ModTime().Equal(c.certMod) && keyInfo.ModTime().Equal(c.keyMod) {
		return nil
	}

	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if first {
			return fmt.Errorf("the admin UI certificate: %w", err)
		}
		c.log.Warn("the admin UI certificate was not reread, the previous one is in force",
			"certificate", c.certFile, "err", err)
		return err
	}
	c.current = &pair
	if certErr == nil && keyErr == nil {
		c.certMod, c.keyMod = certInfo.ModTime(), keyInfo.ModTime()
	}
	if !first {
		c.log.Info("the admin UI certificate was reread", "certificate", c.certFile)
	}
	return nil
}
