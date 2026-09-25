package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// outputLimit is how much of the command's output is kept for the log
// and the admin UI: enough for curl's error, not a way to fill memory.
const outputLimit = 2048

// run hands an alert to the owner's command and says what came of it.
//
// The command runs with the node's own user, through sh -c, and gets the
// alert in ANTIBOT_ALERT_* variables and as JSON on stdin. Nothing of the
// alert is pasted into the command's text: the shell expands "$VAR" into
// one argument and never parses it again, so no string a visitor made up
// becomes a piece of the owner's shell.
func (w *Watcher) run(ctx context.Context, a Alert) string {
	command := ""
	if w.o.Command != nil {
		command = w.o.Command()
	}
	if strings.TrimSpace(command) == "" {
		return "not sent: no command is set"
	}

	ctx, cancel := context.WithTimeout(ctx, w.o.Timeout)
	defer cancel()

	stdin, err := json.Marshal(a)
	if err != nil {
		return "not sent: " + err.Error()
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.Env = append(os.Environ(),
		"ANTIBOT_ALERT_ID="+a.ID,
		"ANTIBOT_ALERT_KIND="+a.Kind,
		"ANTIBOT_ALERT_STATE="+a.State,
		"ANTIBOT_ALERT_TEXT="+a.Text,
		"ANTIBOT_ALERT_HOST="+a.Host,
		"ANTIBOT_ALERT_TIME="+a.Time.UTC().Format(time.RFC3339),
		"ANTIBOT_ALERT_LANGUAGE="+string(a.Language),
	)
	cmd.Stdin = bytes.NewReader(append(stdin, '\n'))
	out := &limited{max: outputLimit}
	cmd.Stdout, cmd.Stderr = out, out
	// A command that left a child holding the pipes must not hold the
	// delivery queue with it.
	cmd.WaitDelay = 2 * time.Second

	start := time.Now()
	err = cmd.Run()
	took := time.Since(start).Round(time.Millisecond)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("did not finish in %s", w.o.Timeout)
	}
	if err != nil {
		w.o.Log.Error("the alert command failed", "alert", a.ID, "state", a.State,
			"err", err, "output", out.String())
		result := "failed: " + err.Error()
		if text := strings.TrimSpace(out.String()); text != "" {
			result += ": " + text
		}
		return result
	}
	w.o.Log.Info("an alert was handed to the command", "alert", a.ID, "state", a.State, "took", took)
	return "handed to the command in " + took.String()
}

// limited keeps the first max bytes written to it and swallows the rest.
type limited struct {
	buf bytes.Buffer
	max int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func (l *limited) String() string { return l.buf.String() }
