package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/replay"
	"github.com/geron0025/antibot/internal/rules"
)

// replayCommand replays a rule set over recorded events.
//
// The only way to learn whom a rule will touch before it starts touching
// anybody.
func replayCommand(args []string) error {
	flags := flag.NewFlagSet("replay", flag.ExitOnError)
	configPath := flags.String("config", "/etc/antibot/config.yaml", "settings file")
	rulesPath := flags.String("rules", "", "rules file (by default, taken from the settings)")
	eventsDir := flags.String("events", "", "event log directory (by default, taken from the settings)")
	period := flags.Duration("for", 0, "over the last stretch of time, 24h for example")
	samples := flags.Int("examples", 0, "how many examples to show per rule")
	asJSON := flags.Bool("json", false, "print JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}

	rulesFile, eventsFrom := *rulesPath, *eventsDir
	if rulesFile == "" || eventsFrom == "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		if rulesFile == "" {
			rulesFile = cfg.Rules.File
		}
		if eventsFrom == "" {
			eventsFrom = cfg.Events.Dir
		}
	}

	contents, err := os.ReadFile(rulesFile)
	if err != nil {
		return fmt.Errorf("rules %s: %w", rulesFile, err)
	}
	// A limiter of its own for the replay: the frequency has to be
	// counted anew from the events rather than continuing somebody's
	// count.
	set, err := rules.Parse(contents, rules.NewWindows())
	if err != nil {
		return err
	}

	options := replay.Options{Dir: eventsFrom, Samples: *samples}
	if *period > 0 {
		options.From = time.Now().Add(-*period)
	}

	result, err := replay.Run(options, set)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	printResult(result)
	return nil
}

func printResult(result *replay.Result) {
	fmt.Printf("Events: %d", result.Events)
	if result.Broken > 0 {
		fmt.Printf(", lines not parsed: %d", result.Broken)
	}
	if !result.From.IsZero() {
		fmt.Printf("\nPeriod: %s — %s",
			result.From.UTC().Format(time.RFC3339), result.To.UTC().Format(time.RFC3339))
	}
	fmt.Printf("\nAddresses: %d\n\n", result.IPs)

	if result.Events == 0 {
		fmt.Println("There are no events over the period — nothing to replay.")
		return
	}

	fmt.Println("Decisions:")
	t := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, action := range byCount(result.Decisions) {
		count := result.Decisions[action]
		fmt.Fprintf(t, "  %s\t%d\t%.2f%%\n", action, count,
			100*float64(count)/float64(result.Events))
	}
	t.Flush()

	if len(result.Divergences) > 0 {
		fmt.Println("\nDiffers from what the events recorded:")
		t = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, transition := range byCount(result.Divergences) {
			fmt.Fprintf(t, "  %s\t%d\n", transition, result.Divergences[transition])
		}
		t.Flush()
	}

	if len(result.Rules) == 0 {
		fmt.Println("\nNot a single rule fired.")
		return
	}

	fmt.Println("\nBy rule:")
	t = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(t, "  ID\tMODE\tMATCHED\tSHARE\tADDRESSES\tHOSTS\tUA")
	for _, s := range byMatched(result) {
		fmt.Fprintf(t, "  %s\t%s\t%d\t%.2f%%\t%d\t%d\t%d\n",
			s.ID, s.Mode, s.Matched, 100*result.Share(s.ID), s.IPs, s.Hosts, s.UAs)
	}
	t.Flush()

	// A rule touching a noticeable share of the traffic almost certainly
	// touches people too. The threshold comes from the previous project's
	// post-mortems: there the shares of working rules were measured in
	// hundredths of a percent.
	for _, s := range byMatched(result) {
		if share := result.Share(s.ID); share > 0.01 {
			fmt.Printf("\nWarning: %s touches %.1f%% of the requests. That much traffic "+
				"is never all bots — go through it by hand.\n", s.ID, 100*share)
		}
	}

	for _, s := range byMatched(result) {
		if len(s.Samples) == 0 {
			continue
		}
		fmt.Printf("\nExamples of %s:\n", s.ID)
		for _, r := range s.Samples {
			fmt.Printf("  %s %s %s %s %q\n",
				r.Time.UTC().Format(time.RFC3339), r.IP, r.Host, r.Path, r.UA)
		}
	}
}

func byCount(m map[string]int) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if m[names[i]] != m[names[j]] {
			return m[names[i]] > m[names[j]]
		}
		return names[i] < names[j]
	})
	return names
}

func byMatched(result *replay.Result) []*replay.RuleStats {
	list := make([]*replay.RuleStats, 0, len(result.Rules))
	for _, s := range result.Rules {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Matched != list[j].Matched {
			return list[i].Matched > list[j].Matched
		}
		return list[i].ID < list[j].ID
	})
	return list
}
