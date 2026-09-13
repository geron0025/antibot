package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/geron0025/antibot/internal/admin"
	"github.com/geron0025/antibot/internal/config"
)

// apiTokenCommand issues, lists and revokes the tokens of the node's API.
//
// The command and the admin UI's page write the same file through the
// same code, and a running node picks a change up without a restart.
func apiTokenCommand(args []string) error {
	if len(args) == 0 {
		apiTokenUsage()
		return fmt.Errorf("no subcommand given")
	}

	switch args[0] {
	case "issue":
		return apiTokenIssue(args[1:])
	case "list":
		return apiTokenList(args[1:])
	case "revoke":
		return apiTokenRevoke(args[1:])
	default:
		apiTokenUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func apiTokenUsage() {
	fmt.Fprint(os.Stderr, `antibot api-token — tokens of the node's API

  issue NAME [-scope read|write] [-days 90] [-config FILE]
                               issue a token; the value is printed once
  list [-config FILE]          the tokens, revoked and expired included
  revoke NAME [-config FILE]   stop a live token at once

A token is the owner's: it is issued only on the node and never goes to
the cloud. A monitoring token should only read.
`)
}

// tokensFilePath takes the path to the tokens file from the node's
// settings.
func tokensFilePath(flags *flag.FlagSet, args []string) (string, error) {
	configPath := flags.String("config", "/etc/antibot/config.yaml", "settings file")
	tokensFile := flags.String("tokens", "", "tokens file (by default, taken from the settings)")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if *tokensFile != "" {
		return *tokensFile, nil
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return "", err
	}
	if cfg.Admin.TokensFile == "" {
		return "", fmt.Errorf("admin_ui.tokens_file is empty in %s: the API is off", *configPath)
	}
	return cfg.Admin.TokensFile, nil
}

func apiTokenIssue(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("no name given: antibot api-token issue NAME")
	}
	name := args[0]

	flags := flag.NewFlagSet("api-token issue", flag.ExitOnError)
	scope := flags.String("scope", admin.ScopeRead, "read, or write to change the rules as well")
	days := flags.Int("days", 90, fmt.Sprintf("how many days the token lives, up to %d", admin.MaxTokenDays))
	file, err := tokensFilePath(flags, args[1:])
	if err != nil {
		return err
	}

	tokens, err := admin.OpenTokens(file)
	if err != nil {
		return err
	}
	value, tok, err := tokens.Issue(name, *scope, *days, "cli:"+currentUser(), time.Now())
	if err != nil {
		return err
	}
	// The value alone goes to stdout, so that TOKEN=$(antibot api-token
	// issue ci) takes exactly it; the words go to stderr.
	fmt.Fprintf(os.Stderr, "the token %s (%s) lives until %s; the value is shown once, the node keeps only its hash:\n",
		tok.Name, tok.Scope, tok.ExpiresAt.Format(time.DateOnly))
	fmt.Println(value)
	return nil
}

func apiTokenList(args []string) error {
	flags := flag.NewFlagSet("api-token list", flag.ExitOnError)
	file, err := tokensFilePath(flags, args)
	if err != nil {
		return err
	}
	tokens, err := admin.OpenTokens(file)
	if err != nil {
		return err
	}
	list, err := tokens.List()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Printf("no tokens (%s)\n", file)
		return nil
	}

	now := time.Now()
	t := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(t, "NAME\tSTARTS WITH\tSCOPE\tISSUED\tBY\tEXPIRES\tUSED\tSTATE")
	for _, tok := range list {
		used := "never"
		if tok.UsedAt != nil {
			used = tok.UsedAt.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(t, "%s\t%s…\t%s\t%s\t%s\t%s\t%s\t%s\n",
			tok.Name, tok.Prefix, tok.Scope, tok.CreatedAt.Local().Format(time.DateOnly), tok.CreatedBy,
			tok.ExpiresAt.Local().Format(time.DateOnly), used, tok.State(now))
	}
	return t.Flush()
}

func apiTokenRevoke(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("no name given: antibot api-token revoke NAME")
	}
	name := args[0]

	flags := flag.NewFlagSet("api-token revoke", flag.ExitOnError)
	file, err := tokensFilePath(flags, args[1:])
	if err != nil {
		return err
	}
	tokens, err := admin.OpenTokens(file)
	if err != nil {
		return err
	}
	if err := tokens.Revoke(name, time.Now()); err != nil {
		return err
	}
	fmt.Printf("the token %s was revoked; a running node refuses it from its next request\n", name)
	return nil
}

// currentUser names who issued a token from the command line.
func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}
