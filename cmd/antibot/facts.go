package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/geron0025/antibot/internal/catalog"
	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/nodeid"
)

// factsCommand shows and rolls back the fact set.
//
// A rollback needs no network, and that is the point: it is done when
// something is already broken, and depending on the cloud being
// reachable at that moment is not acceptable.
func factsCommand(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		factsUsage()
		return fmt.Errorf("no subcommand given")
	}

	switch args[0] {
	case "status":
		return factsStatus(args[1:], log)
	case "rollback":
		return factsRollback(args[1:], log)
	case "apply":
		return factsApply(args[1:], log)
	case "fetch":
		return factsFetch(args[1:], log)
	default:
		factsUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func factsUsage() {
	fmt.Fprint(os.Stderr, `antibot facts — the network and fingerprint bases

  status [-config FILE]              what is applied and what is kept
  rollback [-config FILE]            go back to the previous version
  apply FILE [-manifest FILE] [-force]
                                     apply a set from disk
  fetch [-config FILE]               fetch once from the update service

A fact set carries statements about the world and nothing else. It
changes what a client is called; what to do with such a client is
decided by your rule.

Rolling back needs no network: it is done when something is already
broken.
`)
}

// factsDir takes the directory from the node's settings. No separate
// flag on purpose: the facts live where the configuration says, and
// there must not be two sources of truth.
func factsDir(flags *flag.FlagSet, args []string) (config.Facts, error) {
	configPath := flags.String("config", "/etc/antibot/config.yaml", "settings file")
	dir := flags.String("dir", "", "fact set directory (by default, taken from the settings)")
	if err := flags.Parse(args); err != nil {
		return config.Facts{}, err
	}
	if *dir != "" {
		return config.Facts{Enabled: true, Dir: *dir}, nil
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return config.Facts{}, err
	}
	return cfg.Facts, nil
}

func factsStatus(args []string, log *slog.Logger) error {
	flags := flag.NewFlagSet("facts status", flag.ExitOnError)
	settings, err := factsDir(flags, args)
	if err != nil {
		return err
	}

	store, err := catalog.Open(settings.Dir, settings.Enabled, log)
	if err != nil {
		return err
	}

	if !store.Enabled() {
		fmt.Println("the fact set is switched off: facts.enabled: false")
		return nil
	}

	set := store.Current()
	if set.Version() == 0 {
		fmt.Printf("no set applied (%s)\n", settings.Dir)
		fmt.Println("this is the normal state of a node that was never connected anywhere:")
		fmt.Println("rules referring to unknown facts simply do not match, the rest work")
		return nil
	}

	networks, fingerprints, protected := set.Counts()
	t := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(t, "version\t%d\n", set.Version())
	fmt.Fprintf(t, "built\t%s\n", set.CreatedAt().Local().Format("02.01.2006 15:04"))
	fmt.Fprintf(t, "networks\t%d\n", networks)
	fmt.Fprintf(t, "of them protected\t%d\n", protected)
	fmt.Fprintf(t, "fingerprints\t%d\n", fingerprints)
	fmt.Fprintf(t, "trusted keys\t%d\n", store.Keyring().Trusted())
	fmt.Fprintf(t, "kept on disk\t%v\n", store.Versions())
	return t.Flush()
}

func factsRollback(args []string, log *slog.Logger) error {
	flags := flag.NewFlagSet("facts rollback", flag.ExitOnError)
	settings, err := factsDir(flags, args)
	if err != nil {
		return err
	}

	store, err := catalog.Open(settings.Dir, settings.Enabled, log)
	if err != nil {
		return err
	}
	was := store.Current().Version()

	set, err := store.Rollback()
	if err != nil {
		return err
	}
	fmt.Printf("rolled back from version %d to %d\n", was, set.Version())
	fmt.Println("the running node picks it up on its next check")
	return nil
}

// factsApply puts a set from disk into force — the same five checks the
// loader runs. Needed to bring a base up by hand: in a closed network,
// or while working out what exactly the cloud sent.
func factsApply(args []string, log *slog.Logger) error {
	if len(args) == 0 || args[0] == "" || args[0][0] == '-' {
		return fmt.Errorf("no file given: antibot facts apply FILE")
	}
	setPath := args[0]

	flags := flag.NewFlagSet("facts apply", flag.ExitOnError)
	manifestPath := flags.String("manifest", "", "manifest file (by default, FILE with .manifest.json)")
	force := flags.Bool("force", false, "apply even if the set shrank sharply")
	settings, err := factsDir(flags, args[1:])
	if err != nil {
		return err
	}

	if *manifestPath == "" {
		ext := filepath.Ext(setPath)
		*manifestPath = setPath[:len(setPath)-len(ext)] + ".manifest.json"
	}

	manifestRaw, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	setRaw, err := os.ReadFile(setPath)
	if err != nil {
		return err
	}

	store, err := catalog.Open(settings.Dir, settings.Enabled, log)
	if err != nil {
		return err
	}

	set, err := store.Install(manifestRaw, setRaw, *force)
	if errors.Is(err, catalog.ErrShrunk) {
		return fmt.Errorf("%w\n\nA shrunken base is more dangerous than a stale one: a vanished row\n"+
			"saying \"do not touch this operator\" turns a sensible rule into a block\n"+
			"on live people. Look at what is missing; -force applies it anyway", err)
	}
	if err != nil {
		return err
	}

	networks, fingerprints, protected := set.Counts()
	fmt.Printf("version %d applied: %d networks (%d protected), %d fingerprints\n",
		set.Version(), networks, protected, fingerprints)
	return nil
}

// factsFetch runs one fetch by hand.
//
// The same code the node runs on its schedule — not a second path to the
// same place. Needed when a human is working out why the base is not
// arriving: on a schedule the answer lands in the log hours later.
func factsFetch(args []string, log *slog.Logger) error {
	flags := flag.NewFlagSet("facts fetch", flag.ExitOnError)
	configPath := flags.String("config", "/etc/antibot/config.yaml", "settings file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	store, err := catalog.Open(cfg.Facts.Dir, cfg.Facts.Enabled, log)
	if err != nil {
		return err
	}

	id, err := nodeid.Load(cfg.NodeIDFile)
	if err != nil {
		return err
	}

	fetcher := catalog.NewFetcher(store, cfg.Facts.URL, cfg.Cloud.Token, id, Version, log)
	if fetcher == nil {
		return fmt.Errorf("fetching is not configured: facts.url and cloud.token are needed")
	}

	was := store.Current().Version()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := fetcher.Once(ctx); err != nil {
		return err
	}

	now := store.Current().Version()
	switch {
	case now == was && was == 0:
		fmt.Println("nothing arrived: the update service has no set for this node")
	case now == was:
		fmt.Printf("version %d is already the latest\n", now)
	default:
		networks, fingerprints, protected := store.Current().Counts()
		fmt.Printf("version %d applied: %d networks (%d protected), %d fingerprints\n",
			now, networks, protected, fingerprints)
	}
	return nil
}
