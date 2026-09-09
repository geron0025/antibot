package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/geron0025/antibot/internal/admin"
	"github.com/geron0025/antibot/internal/catalog"
	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/edgetls"
	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/h2fp"
	"github.com/geron0025/antibot/internal/nodeid"
	"github.com/geron0025/antibot/internal/proxy"
	"github.com/geron0025/antibot/internal/rules"
	"github.com/geron0025/antibot/internal/tlsfp"
)

func serveCommand(ctx context.Context, args []string, log *slog.Logger) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	path := flags.String("config", "/etc/antibot/config.yaml", "settings file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}

	eventLog, err := events.Open(events.Options{
		Dir:      cfg.Events.Dir,
		MaxSize:  cfg.Events.MaxSize,
		KeepDays: cfg.Events.KeepDays,
		Queue:    cfg.Events.Queue,
		Log:      log,
	})
	if err != nil {
		return err
	}
	defer eventLog.Close()

	routes := make(map[string]string, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		routes[u.Host] = u.To
	}

	// The rate limiter lives in this process's memory: with several node
	// replicas the limit is multiplied by their number. Stated in the
	// README.
	windows := rules.NewWindows()
	go windows.Cleanup(ctx, time.Minute)

	ruleStore, err := rules.Open(cfg.Rules.File, windows, log)
	if err != nil {
		return err
	}
	go ruleStore.Watch(ctx, cfg.Rules.ReloadInterval.Duration())

	// The fact set is opened before the listeners: a broken set must not
	// stop the node — it works without facts — but the human has to see
	// the reason at startup rather than guess it from empty columns.
	factStore, err := catalog.Open(cfg.Facts.Dir, cfg.Facts.Enabled, log)
	if err != nil {
		return err
	}

	handler := proxy.New(&proxy.Handler{
		Routes:         proxy.NewRouter(routes),
		Events:         eventLog,
		Decider:        ruleStore,
		Facts:          factStore,
		TrustedProxies: config.Prefixes(cfg.TrustedProxies),
		OwnNetworks:    config.Prefixes(cfg.OwnNetworks),
		Log:            log,
	})

	fallback, err := edgetls.SelfSigned(cfg.TLS.SelfSignedDir)
	if err != nil {
		return fmt.Errorf("self-signed certificate: %w", err)
	}
	certs := edgetls.Open(cfg.TLS.CertificatesDir, fallback, log)
	if cfg.TLS.CertificatesDir == "" {
		log.Warn("no certificates configured: working on the self-signed one, the browser will complain")
	}

	stop := make(chan struct{})
	defer close(stop)
	go certs.Watch(cfg.TLS.ReloadInterval.Duration(), stop)

	// Fetching the bases starts only when there is somewhere to fetch
	// from and something to prove the right with. Without a token there
	// is no addressee, and that is a state, not a failure.
	if fetcher := catalog.NewFetcher(factStore, cfg.Facts.URL, cfg.Cloud.Token,
		nodeIdentity(cfg, log), Version, log); fetcher != nil {
		go fetcher.Run(ctx, cfg.Facts.Interval.Duration())
	}

	// The admin UI is assembled before the node starts accepting traffic:
	// an invalid setting (an outward-facing address without a
	// certificate) must stop the startup rather than bring an
	// already-working node down a second after it started.
	var adminUI *admin.Server
	if cfg.Admin.Enabled {
		users, err := admin.OpenUsers(cfg.Admin.UsersFile)
		if err != nil {
			return err
		}
		// The absence of accounts is no reason to stop the node: it must
		// serve traffic even with no human anywhere near it.
		if !users.Any() {
			log.Warn("the admin UI is not up: there are no accounts",
				"file", cfg.Admin.UsersFile, "what to do", "antibot admin passwd NAME")
		} else {
			adminUI, err = admin.New(admin.Options{
				Addr:      cfg.Admin.Listen,
				HTTPAddr:  cfg.Admin.RedirectFrom,
				Cert:      cfg.Admin.Certificate,
				Key:       cfg.Admin.Key,
				Users:     users,
				Sessions:  admin.NewSessions(cfg.Admin.SessionTTL.Duration()),
				Attempts:  windows,
				EventsDir: cfg.Events.Dir,
				Rules:     ruleStore,
				Version:   Version,
				Log:       log,
			})
			if err != nil {
				return err
			}
		}
	}

	var group sync.WaitGroup
	errs := make(chan error, 4)

	if cfg.Listen.HTTP != "" {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := serveHTTP(ctx, cfg.Listen.HTTP, handler, log); err != nil {
				errs <- err
			}
		}()
	}

	if cfg.Listen.HTTPS != "" {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := serveHTTPS(ctx, cfg.Listen.HTTPS, handler, certs, log); err != nil {
				errs <- err
			}
		}()
	}

	if adminUI != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := adminUI.Serve(ctx); err != nil {
				errs <- err
			}
		}()
	}

	if cfg.Listen.Admin != "" {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := serveService(ctx, cfg.Listen.Admin, eventLog, log); err != nil {
				errs <- err
			}
		}()
	}

	log.Info("the node has started", "http", cfg.Listen.HTTP, "https", cfg.Listen.HTTPS,
		"events", cfg.Events.Dir, "rules", len(ruleStore.Set().Effective()),
		"facts", factStore.Current().Version(), "version", Version)

	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func serveHTTP(ctx context.Context, addr string, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          nil,
	}
	go func() {
		<-ctx.Done()
		shutdown(srv)
	}()

	log.Info("listening for HTTP", "address", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP: %w", err)
	}
	return nil
}

// serveHTTPS brings the listener up by hand rather than through
// http.Server.ServeTLS.
//
// The reason is that we have to wedge in between TLS and HTTP/2 twice:
// before the handshake by intercepting the ClientHello, and after it with
// the frame sniffer. The standard server allows neither: it performs the
// handshake inside itself and hands out a ready-made request.
func serveHTTPS(ctx context.Context, addr string, h http.Handler, certs *edgetls.Set, log *slog.Logger) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("HTTPS: %w", err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	tlsConfig := &tls.Config{
		GetCertificate: certs.Get,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
	}

	log.Info("listening for HTTPS", "address", addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var temporary net.Error
			if errors.As(err, &temporary) && temporary.Timeout() {
				continue
			}
			return fmt.Errorf("HTTPS: %w", err)
		}
		go serveConn(ctx, conn, tlsConfig, h, log)
	}
}

func serveConn(ctx context.Context, conn net.Conn, cfg *tls.Config, h http.Handler, log *slog.Logger) {
	defer conn.Close()

	// A deadline on the handshake: a connection opened and abandoned must
	// not occupy a goroutine and a file descriptor until kingdom come.
	// Scanners do exactly that all the time.
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	interceptor := tlsfp.Intercept(conn)
	tlsConn := tls.Server(interceptor, cfg)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// A break during the handshake is an ordinary thing; it goes to
		// the log only at debug level, otherwise the first scanner floods
		// it.
		log.Debug("the handshake did not happen", "address", conn.RemoteAddr(), "err", err)
		return
	}
	conn.SetDeadline(time.Time{})

	hello, _ := interceptor.Hello()
	state := tlsConn.ConnectionState()
	info := &proxy.ConnInfo{
		Hello: hello, Peer: conn.RemoteAddr(), State: &state,
	}

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		sniffer := h2fp.Sniff(tlsConn)
		info.Sniffer = sniffer
		(&http2.Server{IdleTimeout: 120 * time.Second}).ServeConn(sniffer, &http2.ServeConnOpts{
			Context: proxy.WithConnInfo(ctx, info),
			Handler: h,
		})
		return
	}

	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return proxy.WithConnInfo(ctx, info)
		},
	}
	srv.Serve(singleConnListener(tlsConn))
}

// onceListener hands out one already-accepted connection and ends there.
// It exists so that a connection can be served by the regular http.Server
// with all its timeouts, without bringing up a separate listener for it.
//
// The second Accept does not return an error at once but waits until the
// server closes the connection. Otherwise Serve finishes at that very
// moment, the caller returns, its defer closes the connection — and the
// request breaks off halfway. Exactly this happened at the first live
// check: HTTP/1.1 over TLS was breaking while HTTP/2 worked.
type onceListener struct {
	conn   net.Conn
	handed bool
	closed chan struct{}
}

var errNoMoreConns = errors.New("no more connections")

func singleConnListener(c net.Conn) *onceListener {
	return &onceListener{conn: c, closed: make(chan struct{})}
}

// A pointer receiver is mandatory: with a value the handed flag would
// change in a copy, and the listener would hand out the same connection
// forever.
func (o *onceListener) Accept() (net.Conn, error) {
	if o.handed {
		<-o.closed
		return nil, errNoMoreConns
	}
	o.handed = true
	return &signallingConn{Conn: o.conn, closed: o.closed}, nil
}

func (o *onceListener) Close() error   { return nil }
func (o *onceListener) Addr() net.Addr { return o.conn.LocalAddr() }

// signallingConn tells the listener that the server is done with the
// connection.
type signallingConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (s *signallingConn) Close() error {
	s.once.Do(func() { close(s.closed) })
	return s.Conn.Close()
}

func shutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

// nodeIdentity reads the installation's identifier, creating it on the
// first run. A failure is not fatal: the node serves traffic without an
// identifier, it just cannot introduce itself to the cloud.
func nodeIdentity(cfg config.Config, log *slog.Logger) string {
	id, err := nodeid.Load(cfg.NodeIDFile)
	if err != nil {
		log.Error("the node identifier was not read", "file", cfg.NodeIDFile, "err", err)
		return ""
	}
	return id
}
