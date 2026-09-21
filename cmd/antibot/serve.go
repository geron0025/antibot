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
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/geron0025/antibot/internal/admin"
	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/catalog"
	"github.com/geron0025/antibot/internal/cloudlink"
	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/domains"
	"github.com/geron0025/antibot/internal/edgetls"
	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/facts"
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

	configRoutes := make(map[string]string, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		configRoutes[u.Host] = u.To
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

	domainStore, err := domains.Open(cfg.Domains.File, log)
	if err != nil {
		return err
	}
	go domainStore.Watch(ctx, cfg.Domains.ReloadInterval.Duration())

	// The routes come from two lists: the configuration and the domains
	// file. On a name both know, the configuration wins — what the
	// machine's owner wrote by hand must not be overridden through the
	// admin UI.
	buildRouter := func() *proxy.Router {
		routes := domainStore.Routes()
		for host, to := range configRoutes {
			routes[host] = to
		}
		return proxy.NewRouter(routes)
	}
	router := proxy.NewRouteTable(buildRouter())
	domainStore.OnChange(func() { router.Swap(buildRouter()) })

	// What the owner answered about the cloud at his first login, and
	// the token if he took one. The settings file wins over all of it.
	linkState, err := cloudlink.Open(cfg.Cloud.LinkFile, log)
	if err != nil {
		return err
	}

	// The identifier is needed only to talk to the cloud, and a node
	// that never does does not even create the file. It is made on
	// first use rather than at startup, because the first use may be
	// somebody ticking a checkbox an hour from now.
	var nodeOnce sync.Once
	var nodeID string
	identity := func() string {
		nodeOnce.Do(func() { nodeID = nodeIdentity(cfg, log) })
		return nodeID
	}

	aggSink := &aggregateSink{}
	link := &cloudLink{
		cfg: cfg, state: linkState, facts: factStore, sink: aggSink,
		node: identity, serve: router.Named, log: log,
	}
	linkState.OnChange(link.apply)

	fallback, err := edgetls.SelfSigned(cfg.TLS.SelfSignedDir)
	if err != nil {
		return fmt.Errorf("self-signed certificate: %w", err)
	}
	// The upload directory is created here: a directory the scanner
	// cannot read keeps the whole previous set in force, and the first
	// upload must not depend on being the one to create it.
	if cfg.TLS.UploadedDir != "" {
		if err := os.MkdirAll(cfg.TLS.UploadedDir, 0o750); err != nil {
			return fmt.Errorf("uploaded certificates directory: %w", err)
		}
	}
	certs := edgetls.Open([]string{cfg.TLS.CertificatesDir, cfg.TLS.UploadedDir}, fallback, log)
	if certs.Len() == 0 {
		log.Warn("no certificates yet: working on the self-signed one, the browser will complain")
	}

	// The alerts count on the hot path, next to the log: a trigger has to
	// fire within a minute rather than after a reread of the log.
	var watcher *alerts.Watcher
	var alertCommand *alerts.CommandFile
	if cfg.Alerts.Enabled {
		if cfg.Alerts.File != "" {
			if alertCommand, err = alerts.OpenCommand(cfg.Alerts.File); err != nil {
				return err
			}
		}
		watcher = alerts.New(alertOptions(cfg, certs, eventLog, factStore, link, alertCommand, log))
	}

	// The aggregator's place in the hot path is held whether or not
	// there is one: the request path is built once, and the owner may
	// turn the sending on at any time after that.
	sinks := fanOut{eventLog, aggSink}
	if watcher != nil {
		sinks = append(sinks, watcher)
	}
	var sink proxy.EventLog = eventLog
	if len(sinks) > 1 {
		sink = sinks
	}

	handler := proxy.New(&proxy.Handler{
		Routes:         router,
		Events:         sink,
		Decider:        ruleStore,
		Facts:          factStore,
		TrustedProxies: config.Prefixes(cfg.TrustedProxies),
		OwnNetworks:    config.Prefixes(cfg.OwnNetworks),
		Log:            log,
	})

	stop := make(chan struct{})
	defer close(stop)
	go certs.Watch(cfg.TLS.ReloadInterval.Duration(), stop)

	if watcher != nil {
		go watcher.Run(ctx)
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
			// The API lives on the admin UI's address and needs its tokens
			// file; an empty path in the settings turns the API off.
			var tokens *admin.Tokens
			if cfg.Admin.TokensFile != "" {
				if tokens, err = admin.OpenTokens(cfg.Admin.TokensFile); err != nil {
					return err
				}
			}
			cloudState := func() admin.CloudState {
				set := factStore.Current()
				want := link.effective()
				answer := linkState.State()
				state := admin.CloudState{
					Token: want.Token != "", Fetching: want.Fetching, Sending: want.Sending,
					FromConfig: want.FromConfig, Answered: answer.Answered,
					Tenant: answer.Tenant, Level: answer.Level,
					FactsVersion: set.Version(), FactsBuilt: set.CreatedAt(),
				}
				if st, sending := aggSink.Status(); sending {
					state.Outbox, state.LastSent, state.LastProblem = st.Outbox, st.LastSent, st.LastProblem
				}
				return state
			}
			// A pair added on the settings page serves when config.yaml
			// names none; when it names one, config.yaml wins.
			adminCert, adminKey := cfg.Admin.Certificate, cfg.Admin.Key
			if adminCert == "" {
				if adminCert, adminKey = admin.UploadedPair(cfg.Admin.UploadedDir); adminCert != "" {
					log.Info("the admin UI serves the pair added on its settings page", "certificate", adminCert)
				}
			}
			// The page may change the link only where the settings file
			// says nothing: a token written there by hand outranks
			// anything ticked in a browser.
			var cloudControl admin.CloudControl
			if cfg.Cloud.Token == "" {
				cloudControl = link
			}

			adminUI, err = admin.New(admin.Options{
				Cloud:              cloudState,
				CloudControl:       cloudControl,
				Tokens:             tokens,
				Alerts:             watcher,
				AlertCommand:       alertCommand,
				ConfigAlertCommand: cfg.Alerts.Command,
				Addr:               cfg.Admin.Listen,
				HTTPAddr:           cfg.Admin.RedirectFrom,
				Cert:               adminCert,
				Key:                adminKey,
				CertDir:            cfg.Admin.UploadedDir,
				Users:              users,
				Sessions:           admin.NewSessions(cfg.Admin.SessionTTL.Duration()),
				Attempts:           windows,
				EventsDir:          cfg.Events.Dir,
				Rules:              ruleStore,
				Domains:            domainStore,
				Certs:              certs,
				UploadedCertsDir:   cfg.TLS.UploadedDir,
				ConfigRoutes:       configRoutes,
				Version:            Version,
				Log:                log,
			})
			if err != nil {
				return err
			}
		}
	}

	// Every port is taken before anything is served. A port somebody
	// else holds is a refusal to start, naming the key and the address:
	// a node that comes up without one of its doors looks alive, and
	// the missing door is found out only when somebody needs it.
	ports, err := takePorts(cfg, adminUI)
	if err != nil {
		return err
	}

	// The link starts after every early return: on the way out the
	// process waits for the aggregator to save the open window, and it
	// must not wait for one that never started.
	link.start(ctx)
	defer link.stop()

	var group sync.WaitGroup
	errs := make(chan error, 4)
	run := func(serve func() error) {
		group.Add(1)
		go func() {
			defer group.Done()
			// Said the moment it happens: the rest of the node goes on
			// serving, and its log is where the owner looks.
			if err := serve(); err != nil {
				log.Error("a listener stopped", "err", err)
				errs <- err
			}
		}()
	}

	if ports.http != nil {
		run(func() error { return serveHTTP(ctx, ports.http, handler, log) })
	}
	if ports.https != nil {
		run(func() error { return serveHTTPS(ctx, ports.https, handler, certs, log) })
	}
	if adminUI != nil {
		run(func() error { return adminUI.Serve(ctx) })
	}
	if ports.service != nil {
		run(func() error { return serveService(ctx, ports.service, eventLog, aggSink, log) })
	}

	log.Info("the node has started", "http", cfg.Listen.HTTP, "https", cfg.Listen.HTTPS,
		"events", cfg.Events.Dir, "rules", len(ruleStore.Set().Effective()),
		"facts", factStore.Current().Version(), "aggregate", link.effective().Sending,
		"version", Version)

	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// portSet is the node's listeners, taken before any of them serves.
type portSet struct {
	http, https, service net.Listener
}

// takePorts takes every port the settings name. On a refusal the ones
// already taken are given back, so that a supervisor restarting the node
// does not find its own ports held by the attempt before.
func takePorts(cfg config.Config, adminUI *admin.Server) (p portSet, err error) {
	var taken []net.Listener
	defer func() {
		if err != nil {
			for _, ln := range taken {
				ln.Close()
			}
		}
	}()
	take := func(key, addr string) (net.Listener, error) {
		if addr == "" {
			return nil, nil
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", key, addr, err)
		}
		taken = append(taken, ln)
		return ln, nil
	}

	if p.http, err = take("listen.http", cfg.Listen.HTTP); err != nil {
		return p, err
	}
	if p.https, err = take("listen.https", cfg.Listen.HTTPS); err != nil {
		return p, err
	}
	if p.service, err = take("listen.admin", cfg.Listen.Admin); err != nil {
		return p, err
	}
	if adminUI != nil {
		if err = adminUI.Listen(); err != nil {
			return p, err
		}
	}
	return p, nil
}

func serveHTTP(ctx context.Context, ln net.Listener, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          nil,
	}
	go func() {
		<-ctx.Done()
		shutdown(srv)
	}()

	log.Info("listening for HTTP", "address", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
func serveHTTPS(ctx context.Context, listener net.Listener, h http.Handler, certs *edgetls.Set, log *slog.Logger) error {
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

	log.Info("listening for HTTPS", "address", listener.Addr().String())
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

// fanOut hands every event to each sink: the log on disk and, with a
// token, the aggregator. Both only queue the event, so the handler waits
// for neither.
type fanOut []proxy.EventLog

func (f fanOut) Write(r facts.Request) {
	for _, sink := range f {
		sink.Write(r)
	}
}
