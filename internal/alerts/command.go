package alerts

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxCommand bounds the command's length: a curl with a long URL and a
// few headers fits many times over.
const MaxCommand = 4096

// CommandFormatVersion is the format version of the command file.
const CommandFormatVersion = 1

// Command is the command set from the admin UI, and who set it.
type Command struct {
	Command   string    `json:"command"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

type commandFile struct {
	Version int `json:"version"`
	Command
}

// CommandFile keeps the command set from the admin UI, next to the
// accounts. The configuration's command, when there is one, wins and
// this file is not read: what the machine's owner wrote into config.yaml
// by hand must not be replaced through a stolen session.
//
// Mode 0600: a command often carries a bot's token or a mail password.
type CommandFile struct {
	path string

	mu      sync.Mutex
	cur     Command
	modTime time.Time
	size    int64
}

// OpenCommand reads the command file. A missing file is not an error: no
// command was set from the admin UI yet.
func OpenCommand(path string) (*CommandFile, error) {
	c := &CommandFile{path: path}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.reloadLocked(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CommandFile) reloadLocked() error {
	info, err := os.Stat(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		c.cur, c.modTime, c.size = Command{}, time.Time{}, 0
		return nil
	}
	if err != nil {
		return fmt.Errorf("alert command %s: %w", c.path, err)
	}
	if !c.modTime.IsZero() && info.ModTime().Equal(c.modTime) && info.Size() == c.size {
		return nil
	}
	contents, err := os.ReadFile(c.path)
	if err != nil {
		return fmt.Errorf("alert command %s: %w", c.path, err)
	}
	var f commandFile
	if err := json.Unmarshal(contents, &f); err != nil {
		return fmt.Errorf("alert command %s: %w", c.path, err)
	}
	if f.Version != CommandFormatVersion {
		return fmt.Errorf("alert command %s: version %d, and the node understands %d",
			c.path, f.Version, CommandFormatVersion)
	}
	c.cur, c.modTime, c.size = f.Command, info.ModTime(), info.Size()
	return nil
}

// Get is the command in the file now; the file is reread when it changed.
func (c *CommandFile) Get() (Command, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.reloadLocked(); err != nil {
		return Command{}, err
	}
	return c.cur, nil
}

// Set replaces the command. An empty one turns the delivery off.
func (c *CommandFile) Set(command, by string, now time.Time) error {
	if len(command) > MaxCommand {
		return fmt.Errorf("the command is longer than %d bytes", MaxCommand)
	}
	if strings.ContainsRune(command, 0) {
		return errors.New("the command holds a NUL byte")
	}

	f := commandFile{Version: CommandFormatVersion,
		Command: Command{Command: command, UpdatedAt: now.UTC().Truncate(time.Second), UpdatedBy: by}}
	contents, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')

	c.mu.Lock()
	defer c.mu.Unlock()

	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".alerts-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	if err := os.Rename(name, c.path); err != nil {
		return err
	}
	c.modTime = time.Time{}
	return c.reloadLocked()
}
