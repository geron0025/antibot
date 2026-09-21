// Command antibot-admin is the node's admin UI: a program of its own,
// run under a user of its own, next to the core or not at all.
//
// The core serves traffic with no admin UI anywhere near it. This one
// shows what the core does and changes a counted few things: the rules,
// the domains, the certificates it serves, where alerts go and the link
// to the cloud. What lives in files it reads and writes itself; what
// lives in the core's memory it asks over the core's control socket, and
// that list is closed — see internal/control.
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

// defaultConfig is where the admin UI's settings live by default.
const defaultConfig = "/etc/antibot/admin.yaml"

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
	case "accounts":
		err = accountsCommand(os.Args[2:])
	case "api-token":
		err = apiTokenCommand(os.Args[2:])
	case "version":
		fmt.Println("antibot-admin", Version)
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
	fmt.Fprint(os.Stderr, `antibot-admin — the admin UI of an antibot node

Commands:
  serve      serve the admin UI and the API
  accounts   accounts of the admin UI
  api-token  tokens of the node's API
  version    show the version

Examples:
  antibot-admin serve -config /etc/antibot/admin.yaml
  antibot-admin accounts passwd owner
  antibot-admin api-token issue monitoring
`)
}
