package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"

	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/domains"
)

// domainsCommand leads the domains added at run time. The same file and
// the same validation as the admin UI: one write path, two doors to it.
func domainsCommand(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		domainsUsage()
		return fmt.Errorf("no subcommand given")
	}

	switch args[0] {
	case "list":
		return domainsList(args[1:])
	case "add":
		return domainsAdd(args[1:], log)
	case "remove":
		return domainsRemove(args[1:], log)
	default:
		domainsUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func domainsUsage() {
	fmt.Fprint(os.Stderr, `antibot domains — the served domains added at run time

  list [-config FILE]           show the domains from the file
  add HOST TO [-config FILE]    serve HOST, forwarding to TO
  remove HOST [-config FILE]    stop serving HOST

TO is the address of the site's server: http://203.0.113.7:8080 —
scheme, server, optional port. The Host header is passed as is.

The upstreams written in config.yaml are a separate, hand-led list; on
a name both know, the configuration wins.
`)
}

// domainsFilePath takes the path to domains.json from the node's
// settings — the rules command works the same way, and for the same
// reason: two sources of truth for a path end up disagreeing.
func domainsFilePath(flags *flag.FlagSet, args []string) (string, error) {
	configPath := flags.String("config", "/etc/antibot/config.yaml", "settings file")
	file := flags.String("file", "", "domains file (by default, taken from the settings)")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if *file != "" {
		return *file, nil
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return "", err
	}
	return cfg.Domains.File, nil
}

func domainsList(args []string) error {
	flags := flag.NewFlagSet("domains list", flag.ExitOnError)
	file, err := domainsFilePath(flags, args)
	if err != nil {
		return err
	}

	list, err := domains.Read(file)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Printf("no domains (%s)\n", file)
		return nil
	}

	t := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(t, "HOST\tTO")
	for _, d := range list {
		fmt.Fprintf(t, "%s\t%s\n", d.Host, d.To)
	}
	return t.Flush()
}

func domainsAdd(args []string, log *slog.Logger) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: antibot domains add HOST TO")
	}
	host, to := args[0], args[1]

	flags := flag.NewFlagSet("domains add", flag.ExitOnError)
	file, err := domainsFilePath(flags, args[2:])
	if err != nil {
		return err
	}

	store, err := domains.Open(file, log)
	if err != nil {
		return err
	}
	added, err := store.Add(host, to)
	if err != nil {
		return err
	}
	fmt.Printf("the domain %s is served, forwarding to %s\n", added.Host, added.To)
	return nil
}

func domainsRemove(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		return fmt.Errorf("no host given")
	}
	host := args[0]

	flags := flag.NewFlagSet("domains remove", flag.ExitOnError)
	file, err := domainsFilePath(flags, args[1:])
	if err != nil {
		return err
	}

	store, err := domains.Open(file, log)
	if err != nil {
		return err
	}
	if err := store.Remove(host); err != nil {
		return err
	}
	fmt.Printf("the domain %s is no longer served\n", host)
	return nil
}
