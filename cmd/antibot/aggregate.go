package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/geron0025/antibot/internal/aggregate"
	"github.com/geron0025/antibot/internal/config"
)

// aggregateCommand shows what the node counts and is about to send.
//
// The protocol document says what may leave the node; this command
// shows what actually will, byte for byte. The node is public so that
// anyone can check the first against the second.
func aggregateCommand(args []string) error {
	if len(args) == 0 {
		aggregateUsage()
		return fmt.Errorf("no subcommand given")
	}

	switch args[0] {
	case "status":
		return aggregateStatus(args[1:])
	case "show":
		return aggregateShow(args[1:])
	default:
		aggregateUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func aggregateUsage() {
	fmt.Fprint(os.Stderr, `antibot aggregate — what is sent to the cloud

  status [-config FILE]              sending on or off, open windows, unsent batches
  show [BATCH] [-config FILE]        an unsent batch exactly as it will be posted
                                     (the oldest one when no key is given)

Nothing is counted or sent without cloud.token. What a batch may
contain is fixed in docs/en/protocol/aggregate.md.
`)
}

// aggregateSettings takes the cloud settings from the node's
// configuration, or only the directory when -dir is given.
func aggregateSettings(flags *flag.FlagSet, args []string) (config.Cloud, bool, error) {
	configPath := flags.String("config", "/etc/antibot/config.yaml", "settings file")
	dir := flags.String("dir", "", "aggregate state directory (by default, taken from the settings)")
	if err := flags.Parse(args); err != nil {
		return config.Cloud{}, false, err
	}
	if *dir != "" {
		return config.Cloud{StateDir: *dir}, false, nil
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return config.Cloud{}, false, err
	}
	return cfg.Cloud, true, nil
}

func aggregateStatus(args []string) error {
	cloud, fromConfig, err := aggregateSettings(flag.NewFlagSet("aggregate status", flag.ExitOnError), args)
	if err != nil {
		return err
	}

	switch {
	case !fromConfig:
	case cloud.Token == "":
		fmt.Println("sending:  off — no cloud.token, nothing is counted or sent")
	default:
		fmt.Printf("sending:  on, to %s every %s\n", cloud.URL, cloud.Interval.Duration())
	}
	fmt.Printf("state:    %s\n", cloud.StateDir)

	st, err := aggregate.ReadState(cloud.StateDir)
	if err != nil {
		return err
	}
	ids, err := aggregate.Outbox(cloud.StateDir)
	if err != nil {
		return err
	}
	if len(st.Open) == 0 && len(st.Pending) == 0 && len(ids) == 0 {
		fmt.Println("\nnothing counted and nothing waiting")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	printWindows := func(title string, windows []aggregate.WindowSummary) {
		if len(windows) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s\n", title)
		for _, s := range windows {
			fmt.Fprintf(w, "  %s\t%d rows\t%d requests\n", s.Start.UTC().Format(time.RFC3339), s.Rows, s.Requests)
		}
	}
	printWindows("open windows (as of the last save):", st.Open)
	printWindows("closed, waiting for a batch:", st.Pending)
	if len(ids) > 0 {
		fmt.Fprintf(w, "\nunsent batches, oldest first (%d of at most %d):\n", len(ids), aggregate.OutboxLimit)
		for _, id := range ids {
			fmt.Fprintf(w, "  %s\n", id)
		}
	}
	return w.Flush()
}

func aggregateShow(args []string) error {
	// The key may come before the flags: flag stops at the first
	// argument that is not one.
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet("aggregate show", flag.ExitOnError)
	cloud, _, err := aggregateSettings(flags, args)
	if err != nil {
		return err
	}
	if id == "" {
		id = flags.Arg(0)
	}

	if id == "" {
		ids, err := aggregate.Outbox(cloud.StateDir)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return fmt.Errorf("no unsent batches in %s", cloud.StateDir)
		}
		id = ids[0]
	}

	raw, err := aggregate.ReadBatch(cloud.StateDir, id)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("no unsent batch %s: it has been sent or thrown away", id)
	}
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return err
	}
	_, err = out.WriteTo(os.Stdout)
	return err
}
