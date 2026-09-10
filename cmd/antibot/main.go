// Command antibot is the node: a proxy that takes client fingerprints and
// applies rules.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// Version is substituted at build time: -ldflags "-X main.Version=0.1.0".
var Version = "not set"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "serve":
		err = serveCommand(ctx, os.Args[2:], log)
	case "rules":
		err = rulesCommand(os.Args[2:], log)
	case "replay":
		err = replayCommand(os.Args[2:])
	case "facts":
		err = factsCommand(os.Args[2:], log)
	case "admin":
		err = adminCommand(os.Args[2:])
	case "aggregate":
		err = aggregateCommand(os.Args[2:])
	case "version":
		fmt.Println("antibot", Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		log.Error("stopped with an error", "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `antibot — a proxy that takes client fingerprints

Commands:
  serve     serve traffic
  rules     show and change the rules
  replay    replay the rules over recorded events
  facts     show and roll back the network and fingerprint bases
  admin     accounts of the viewing admin UI
  aggregate show what is counted and about to be sent to the cloud
  version   show the version

Examples:
  antibot serve -config /etc/antibot/config.yaml
  antibot rules list
  antibot facts status
  antibot replay -for 24h
  antibot admin passwd owner
  antibot aggregate status
`)
}
