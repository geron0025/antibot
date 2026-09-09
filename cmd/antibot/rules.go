package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/rules"
)

// rulesCommand is the only way to change the rules on a node.
//
// There is no admin UI on the node that edits rules: a rule is the reason
// a client does not reach the site, and the path to changing it must be a
// single one, visible in the shell history.
func rulesCommand(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		rulesUsage()
		return fmt.Errorf("no subcommand given")
	}

	switch args[0] {
	case "list":
		return rulesList(args[1:])
	case "add":
		return rulesAdd(args[1:], log)
	case "enable":
		return rulesToggle(args[1:], true, log)
	case "disable":
		return rulesToggle(args[1:], false, log)
	case "remove":
		return rulesRemove(args[1:], log)
	case "check":
		return rulesCheck(args[1:])
	case "fields":
		return rulesFields()
	default:
		rulesUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func rulesUsage() {
	fmt.Fprint(os.Stderr, `antibot rules — the node's rules

  list [-config FILE] [-json]     show the rules in the order of application
  add [-config FILE] [-file FILE] add a rule from JSON (from stdin by default)
  enable ID [-config FILE]        enable a rule
  disable ID [-config FILE]       disable a rule
  remove ID [-config FILE]        delete a rule
  check [-config FILE]            validate the rules file, changing nothing
  fields                          list the fields available to conditions

A rule is added in shadow mode — first look at whom it touches:
antibot replay -rules ... Moving it to active is an edit of mode.
`)
}

// rulesFilePath takes the path to rules.json from the node's settings.
// There is deliberately no separate flag: the rules live where the
// configuration says, and there must not be two sources of truth.
func rulesFilePath(flags *flag.FlagSet, args []string) (string, error) {
	configPath := flags.String("config", "/etc/antibot/config.yaml", "settings file")
	rulesFile := flags.String("rules", "", "rules file (by default, taken from the settings)")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if *rulesFile != "" {
		return *rulesFile, nil
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return "", err
	}
	return cfg.Rules.File, nil
}

func rulesList(args []string) error {
	flags := flag.NewFlagSet("rules list", flag.ExitOnError)
	asJSON := flags.Bool("json", false, "print JSON")
	file, err := rulesFilePath(flags, args)
	if err != nil {
		return err
	}

	list, err := rules.Read(file)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(list)
	}
	if len(list) == 0 {
		fmt.Printf("no rules (%s)\n", file)
		return nil
	}

	// The same order in which the rules are applied: a list sorted
	// differently from how the node works misleads at exactly the moment
	// a human is working out why the wrong thing fired.
	ordered := make([]rules.Rule, len(list))
	copy(ordered, list)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority > ordered[j].Priority
		}
		return ordered[i].ID < ordered[j].ID
	})

	t := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(t, "PRIORITY\tID\tMODE\tACTION\tSCOPE\tSTATE")
	for _, r := range ordered {
		state := "enabled"
		if r.Enabled != nil && !*r.Enabled {
			state = "disabled"
		}
		fmt.Fprintf(t, "%d\t%s\t%s\t%s\t%s\t%s\n",
			r.Priority, r.ID, r.Mode, r.Action.Type,
			strings.Join(r.Scope, ","), state)
	}
	return t.Flush()
}

func rulesAdd(args []string, log *slog.Logger) error {
	flags := flag.NewFlagSet("rules add", flag.ExitOnError)
	fromFile := flags.String("file", "", "file with the rule in JSON (stdin by default)")
	file, err := rulesFilePath(flags, args)
	if err != nil {
		return err
	}

	var raw []byte
	if *fromFile != "" {
		raw, err = os.ReadFile(*fromFile)
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		return err
	}

	var added rules.Rule
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&added); err != nil {
		return fmt.Errorf("rule: %w", err)
	}
	// A check before the write: an invalid rule must not reach a file the
	// node would then refuse to read as a whole.
	if _, err := added.Compile(); err != nil {
		return err
	}
	if added.Mode == rules.Active {
		fmt.Fprintf(os.Stderr,
			"the rule %q is being added straight into active — it is worth looking at a replay over history first\n",
			added.ID)
	}

	list, err := rules.Read(file)
	if err != nil {
		return err
	}
	for _, r := range list {
		if r.ID == added.ID {
			return fmt.Errorf("the rule %q already exists", added.ID)
		}
	}

	return writeRules(file, append(list, added), log,
		fmt.Sprintf("the rule %s was added", added.ID))
}

func rulesToggle(args []string, enable bool, log *slog.Logger) error {
	if len(args) == 0 {
		return fmt.Errorf("no rule id given")
	}
	id := args[0]

	flags := flag.NewFlagSet("rules enable", flag.ExitOnError)
	file, err := rulesFilePath(flags, args[1:])
	if err != nil {
		return err
	}

	store, err := rules.Open(file, nil, log)
	if err != nil {
		return err
	}
	if err := store.Toggle(id, enable); err != nil {
		return err
	}

	state := "enabled"
	if !enable {
		state = "disabled"
	}
	fmt.Printf("the rule %s is %s\n", id, state)
	return nil
}

func rulesRemove(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		return fmt.Errorf("no rule id given")
	}
	id := args[0]

	flags := flag.NewFlagSet("rules remove", flag.ExitOnError)
	file, err := rulesFilePath(flags, args[1:])
	if err != nil {
		return err
	}

	list, err := rules.Read(file)
	if err != nil {
		return err
	}
	left := make([]rules.Rule, 0, len(list))
	for _, r := range list {
		if r.ID != id {
			left = append(left, r)
		}
	}
	if len(left) == len(list) {
		return fmt.Errorf("there is no rule %q", id)
	}
	return writeRules(file, left, log, fmt.Sprintf("the rule %s was deleted", id))
}

func rulesCheck(args []string) error {
	flags := flag.NewFlagSet("rules check", flag.ExitOnError)
	file, err := rulesFilePath(flags, args)
	if err != nil {
		return err
	}

	list, err := rules.Read(file)
	if err != nil {
		return err
	}
	set, err := rules.Build(list, rules.NewWindows())
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d rules, %d in force — the set is valid\n",
		file, len(list), len(set.Effective()))
	return nil
}

func rulesFields() error {
	t := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(t, "FIELD\tKIND\tOPERATORS")
	for _, field := range facts.Fields() {
		kind, _ := facts.FieldKind(field)
		fmt.Fprintf(t, "%s\t%s\t%s\n", field, kind, strings.Join(rules.Operators(kind), ", "))
	}
	return t.Flush()
}

// writeRules puts the set on disk atomically and through the same
// validation the node uses when reading.
func writeRules(file string, list []rules.Rule, log *slog.Logger, message string) error {
	store, err := rules.Open(file, nil, log)
	if err != nil {
		return err
	}
	if err := store.Write(list); err != nil {
		return err
	}
	fmt.Println(message)
	return nil
}
