package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/geron0025/antibot/internal/admin"
	"github.com/geron0025/antibot/internal/config"
)

// adminCommand creates and removes admin UI accounts.
//
// The accounts are the one thing the admin UI cannot change about itself:
// changing a password through the admin UI would mean that whoever stole
// a session takes the access for good.
func adminCommand(args []string) error {
	if len(args) == 0 {
		adminUsage()
		return fmt.Errorf("no subcommand given")
	}

	switch args[0] {
	case "passwd":
		return adminPasswd(args[1:])
	case "list":
		return adminList(args[1:])
	case "remove":
		return adminRemove(args[1:])
	default:
		adminUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func adminUsage() {
	fmt.Fprint(os.Stderr, `antibot admin — accounts of the viewing admin UI

  passwd NAME [-config FILE]   create an account or change a password
  list [-config FILE]          list the accounts
  remove NAME [-config FILE]   remove an account

The admin UI only shows: events, statistics and rules. Nothing can be
changed through it — rules are changed with antibot rules.
`)
}

// usersFilePath takes the path to the accounts file from the node's
// settings.
func usersFilePath(flags *flag.FlagSet, args []string) (string, error) {
	configPath := flags.String("config", "/etc/antibot/config.yaml", "settings file")
	usersFile := flags.String("users", "", "accounts file (by default, taken from the settings)")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if *usersFile != "" {
		return *usersFile, nil
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return "", err
	}
	return cfg.Admin.UsersFile, nil
}

func adminPasswd(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("no name given: antibot admin passwd NAME")
	}
	name := args[0]

	flags := flag.NewFlagSet("admin passwd", flag.ExitOnError)
	file, err := usersFilePath(flags, args[1:])
	if err != nil {
		return err
	}

	password, err := askPassword()
	if err != nil {
		return err
	}

	users, err := admin.OpenUsers(file)
	if err != nil {
		return err
	}
	if err := users.Set(name, password); err != nil {
		return err
	}
	fmt.Printf("the account %s was written to %s\n", name, file)
	return nil
}

// askPassword reads the password twice and without echo.
//
// Not through a flag and not through an environment variable: a password
// on the command line stays in the shell history and is visible in the
// process list to anyone sitting on the same machine.
func askPassword() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	if !isTerminal() {
		// Not a terminal — read the line as it is: that is how an install
		// from a script works, and there is nothing to hide there.
		return readLine(reader)
	}

	// The echo is turned off through stty rather than with a terminal
	// library: that would drag in x/sys, which raises the required Go
	// version for the sake of one line of input. stty exists both in
	// alpine (busybox) and in macOS; if it is missing, the password will
	// simply be visible — and that is said out loud.
	restore, quiet := turnOffEcho()
	if !quiet {
		fmt.Fprintln(os.Stderr, "warning: the echo did not turn off, the password will be visible")
	}
	defer restore()

	fmt.Fprint(os.Stderr, "Password: ")
	first, err := readLine(reader)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	fmt.Fprint(os.Stderr, "Again: ")
	second, err := readLine(reader)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	if first != second {
		return "", fmt.Errorf("the passwords did not match")
	}
	return first, nil
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("the password was not read: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func isTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// turnOffEcho returns a restore function and a flag saying whether the
// echo was actually turned off.
func turnOffEcho() (func(), bool) {
	if _, err := exec.LookPath("stty"); err != nil {
		return func() {}, false
	}
	if err := stty("-echo"); err != nil {
		return func() {}, false
	}
	return func() { stty("echo") }, true
}

func stty(mode string) error {
	cmd := exec.Command("stty", mode)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func adminList(args []string) error {
	flags := flag.NewFlagSet("admin list", flag.ExitOnError)
	file, err := usersFilePath(flags, args)
	if err != nil {
		return err
	}

	users, err := admin.OpenUsers(file)
	if err != nil {
		return err
	}
	names := users.Names()
	if len(names) == 0 {
		fmt.Printf("there are no accounts (%s); the admin UI does not come up without them\n", file)
		return nil
	}
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

func adminRemove(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("no name given: antibot admin remove NAME")
	}
	name := args[0]

	flags := flag.NewFlagSet("admin remove", flag.ExitOnError)
	file, err := usersFilePath(flags, args[1:])
	if err != nil {
		return err
	}

	users, err := admin.OpenUsers(file)
	if err != nil {
		return err
	}
	if err := users.Remove(name); err != nil {
		return err
	}
	fmt.Printf("the account %s was removed\n", name)
	if !users.Any() {
		fmt.Println("no accounts are left — the admin UI will not come up on the next start")
	}
	return nil
}
