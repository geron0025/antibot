package main

import (
	"context"
	"flag"
	"log/slog"
	"time"

	"github.com/geron0025/antibot/internal/admin"
	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/control"
	"github.com/geron0025/antibot/internal/domains"
	"github.com/geron0025/antibot/internal/rules"
)

// reloadInterval is how often the admin UI rereads the rules and the
// domains: the antibot rules command and the core's own reload may
// change them behind its back.
const reloadInterval = 5 * time.Second

func serveCommand(ctx context.Context, args []string, log *slog.Logger) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	path := flags.String("config", defaultConfig, "the admin UI's settings file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := admin.LoadConfig(*path)
	if err != nil {
		return err
	}

	users, err := admin.OpenUsers(cfg.UsersFile)
	if err != nil {
		return err
	}
	// Here, unlike in the core, no accounts is a refusal to start: an
	// admin UI nobody can log into has nothing to do but wait for a
	// password guess.
	var tokens *admin.Tokens
	if cfg.TokensFile != "" {
		if tokens, err = admin.OpenTokens(cfg.TokensFile); err != nil {
			return err
		}
	}

	// The rules and domains are the core's files, written through the
	// same code as the antibot rules and antibot domains commands. The
	// admin UI's copy only shows and writes: deciding is the core's.
	var ruleStore *rules.Store
	if cfg.Core.RulesFile != "" {
		if ruleStore, err = rules.Open(cfg.Core.RulesFile, nil, log); err != nil {
			return err
		}
		go ruleStore.Watch(ctx, reloadInterval)
	}
	var domainStore *domains.Store
	if cfg.Core.DomainsFile != "" {
		if domainStore, err = domains.Open(cfg.Core.DomainsFile, log); err != nil {
			return err
		}
		go domainStore.Watch(ctx, reloadInterval)
	}
	var alertCommand *alerts.CommandFile
	if cfg.Core.AlertsFile != "" {
		if alertCommand, err = alerts.OpenCommand(cfg.Core.AlertsFile); err != nil {
			return err
		}
	}

	// A pair added on the settings page serves when the settings name
	// none; when they name one, the settings win.
	cert, key := cfg.Certificate, cfg.Key
	if cert == "" {
		if cert, key = admin.UploadedPair(cfg.UploadedDir); cert != "" {
			log.Info("the admin UI serves the pair added on its settings page", "certificate", cert)
		}
	}

	attempts := rules.NewWindows()
	go attempts.Cleanup(ctx, time.Minute)

	ui, err := admin.New(admin.Options{
		Core:             control.NewClient(cfg.Core.Socket),
		Tokens:           tokens,
		AlertCommand:     alertCommand,
		Addr:             cfg.Listen,
		HTTPAddr:         cfg.RedirectFrom,
		Cert:             cert,
		Key:              key,
		CertDir:          cfg.UploadedDir,
		Users:            users,
		Sessions:         admin.NewSessions(cfg.SessionTTL.Duration()),
		Attempts:         attempts,
		EventsDir:        cfg.Core.EventsDir,
		Rules:            ruleStore,
		Domains:          domainStore,
		UploadedCertsDir: cfg.Core.CertificatesDir,
		Version:          Version,
		Log:              log,
	})
	if err != nil {
		return err
	}
	if err := ui.Listen(); err != nil {
		return err
	}
	log.Info("the admin UI has started", "address", cfg.Listen, "core", cfg.Core.Socket, "version", Version)
	return ui.Serve(ctx)
}
