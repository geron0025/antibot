package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
)

type fakeCore struct {
	answered [][2]bool
	reloaded []Reloadable
}

func (f *fakeCore) Health(context.Context) (Health, error) {
	return Health{Version: "v1.2.3", Started: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)}, nil
}
func (f *fakeCore) Stop(context.Context) error { return nil }
func (f *fakeCore) Alerts(context.Context) (Alerts, error) {
	return Alerts{Enabled: true,
		Triggers: []alerts.Trigger{{Kind: "site_down", Title: "the site does not answer"}},
		Firing:   []alerts.Status{{ID: "site_down", Kind: "site_down", Text: "502s"}},
	}, nil
}
func (f *fakeCore) TestAlert(context.Context) (string, error) { return "handed to the command", nil }
func (f *fakeCore) Cloud(context.Context) (CloudState, error) {
	return CloudState{Token: true, Tenant: "node-1"}, nil
}
func (f *fakeCore) CloudAnswer(_ context.Context, facts, aggregates bool) error {
	f.answered = append(f.answered, [2]bool{facts, aggregates})
	return nil
}
func (f *fakeCore) CloudRegister(context.Context, bool, bool) error {
	return Refuse("this installation already took a token once")
}
func (f *fakeCore) CloudForget(context.Context) error {
	return errors.New("the link file is read-only")
}
func (f *fakeCore) Certificates(context.Context) ([]Certificate, error) {
	return []Certificate{{Path: "/certs/a/fullchain.pem", Names: []string{"a.example"}}}, nil
}
func (f *fakeCore) Routes(context.Context) (map[string]string, error) {
	return map[string]string{"a.example": "http://127.0.0.1:3000"}, nil
}
func (f *fakeCore) Reload(_ context.Context, what Reloadable) error {
	f.reloaded = append(f.reloaded, what)
	return nil
}

// Every question goes over a real socket and comes back as asked, and a
// refusal meant for a human stays one on the other side.
func TestTheClientAsksOverTheSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "core.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	core := &fakeCore{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, ln, core, slog.New(slog.NewTextHandler(io.Discard, nil)))

	c := NewClient(path)
	h, err := c.Health(ctx)
	if err != nil || h.Version != "v1.2.3" || h.Started.IsZero() {
		t.Fatalf("health: %+v %v", h, err)
	}
	a, err := c.Alerts(ctx)
	if err != nil || !a.Enabled || len(a.Firing) != 1 || a.Triggers[0].Title != "the site does not answer" {
		t.Fatalf("alerts: %+v %v", a, err)
	}
	if r, err := c.TestAlert(ctx); err != nil || r != "handed to the command" {
		t.Fatalf("test: %q %v", r, err)
	}
	if s, err := c.Cloud(ctx); err != nil || s.Tenant != "node-1" {
		t.Fatalf("cloud: %+v %v", s, err)
	}
	if err := c.CloudAnswer(ctx, true, false); err != nil || len(core.answered) != 1 || core.answered[0] != [2]bool{true, false} {
		t.Fatalf("answer: %v %v", core.answered, err)
	}

	var refusal *Refusal
	if err := c.CloudRegister(ctx, true, true); !errors.As(err, &refusal) || refusal.Text != "this installation already took a token once" {
		t.Fatalf("register: %v", err)
	}
	if err := c.CloudForget(ctx); err == nil || errors.As(err, &refusal) || err.Error() != "the link file is read-only" {
		t.Fatalf("forget: %v", err)
	}

	if list, err := c.Certificates(ctx); err != nil || len(list) != 1 || list[0].Names[0] != "a.example" {
		t.Fatalf("certificates: %+v %v", list, err)
	}
	if routes, err := c.Routes(ctx); err != nil || routes["a.example"] == "" {
		t.Fatalf("routes: %v %v", routes, err)
	}
	if err := c.Reload(ctx, ReloadRules); err != nil || len(core.reloaded) != 1 || core.reloaded[0] != ReloadRules {
		t.Fatalf("reload: %v %v", core.reloaded, err)
	}
}

// A core that is not there is said to be so, and quickly: the admin UI
// asks on every page.
func TestAMissingCoreIsUnreachable(t *testing.T) {
	c := NewClient(filepath.Join(shortDir(t), "core.sock"))
	start := time.Now()
	if _, err := c.Health(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("it took too long to find out")
	}
}

// A stale socket left by a core that died is taken over; a live one and a
// file that is not a socket are never removed.
func TestListenTakesOverOnlyASocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "core.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	// Closing a unix listener removes its file; a crash does not.
	ln.(interface{ SetUnlinkOnClose(bool) }).SetUnlinkOnClose(false)
	ln.Close()
	if ln, err = Listen(path); err != nil {
		t.Fatalf("a stale socket: %v", err)
	}
	// A socket somebody answers on is never taken over.
	if _, err := Listen(path); err == nil {
		t.Fatal("a live socket was taken over")
	}
	ln.Close()

	other := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(other, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(other); err == nil {
		t.Fatal("a regular file was taken over")
	}
}

// shortDir is a temporary directory with a short path: a unix socket's
// path is limited to about a hundred bytes, and t.TempDir on macOS nearly
// uses that up by itself.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ab")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
