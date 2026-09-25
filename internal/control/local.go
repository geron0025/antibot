package control

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/edgetls"
)

// CloudLink is what the core does about the link to the cloud when the
// owner answers the two questions.
type CloudLink interface {
	// Answer records the two checkboxes and applies them at once.
	Answer(facts, aggregates bool) error

	// Register asks the cloud for a token for this installation and
	// keeps it, then records the checkboxes.
	Register(ctx context.Context, facts, aggregates bool) error

	// Forget drops the token and clears both answers.
	Forget() error
}

// Local is Core over the core's own objects: what the core serves on its
// socket. Nil fields are what the core does not have — alerts turned off,
// no link to the cloud — and are answered as such rather than failing.
type Local struct {
	Version string
	Started time.Time

	// Watcher is nil when the core's settings turn the alerts off.
	Watcher        *alerts.Watcher
	ConfigCommand  string
	ConfigLanguage string

	// CloudState reports the link; Link changes it. A nil Link is a
	// token written into the settings file by hand: nothing asked over
	// the socket may override it.
	CloudState func() CloudState
	Link       CloudLink

	Certs       *edgetls.Set
	ConfigRoute map[string]string

	// Reloaders take a changed file up now, one per what.
	Reloaders map[Reloadable]func() error

	// Shutdown makes the core finish cleanly. Called at most once.
	Shutdown func()
	stopOnce sync.Once
}

var _ Core = (*Local)(nil)

func (l *Local) Health(context.Context) (Health, error) {
	return Health{Version: l.Version, Started: l.Started}, nil
}

func (l *Local) Stop(context.Context) error {
	if l.Shutdown == nil {
		return fmt.Errorf("this core cannot be stopped from outside")
	}
	// After the answer has had time to leave: the socket closes with
	// the core.
	l.stopOnce.Do(func() { time.AfterFunc(100*time.Millisecond, l.Shutdown) })
	return nil
}

func (l *Local) Alerts(context.Context) (Alerts, error) {
	if l.Watcher == nil {
		return Alerts{}, nil
	}
	return Alerts{
		Enabled:        true,
		Triggers:       l.Watcher.Triggers(),
		Firing:         l.Watcher.Firing(),
		History:        l.Watcher.History(),
		ConfigCommand:  l.ConfigCommand,
		ConfigLanguage: l.ConfigLanguage,
	}, nil
}

func (l *Local) TestAlert(ctx context.Context) (string, error) {
	if l.Watcher == nil {
		return "", Refuse("the alerts are off: alerts.enabled is false in the core's settings")
	}
	return l.Watcher.Test(ctx), nil
}

func (l *Local) Cloud(context.Context) (CloudState, error) {
	if l.CloudState == nil {
		return CloudState{}, fmt.Errorf("this core has no link to the cloud")
	}
	return l.CloudState(), nil
}

func (l *Local) CloudAnswer(_ context.Context, facts, aggregates bool) error {
	if l.Link == nil {
		return Refuse("this node's link to the cloud is set in config.yaml")
	}
	return l.Link.Answer(facts, aggregates)
}

func (l *Local) CloudRegister(ctx context.Context, facts, aggregates bool) error {
	if l.Link == nil {
		return Refuse("this node's link to the cloud is set in config.yaml")
	}
	return l.Link.Register(ctx, facts, aggregates)
}

func (l *Local) CloudForget(context.Context) error {
	if l.Link == nil {
		return Refuse("this node's link to the cloud is set in config.yaml")
	}
	return l.Link.Forget()
}

func (l *Local) Certificates(context.Context) ([]Certificate, error) {
	if l.Certs == nil {
		return nil, nil
	}
	var out []Certificate
	for _, info := range l.Certs.List() {
		out = append(out, Certificate{Path: info.Path, Names: info.Names, NotAfter: info.NotAfter})
	}
	return out, nil
}

func (l *Local) Routes(context.Context) (map[string]string, error) {
	return l.ConfigRoute, nil
}

func (l *Local) Reload(_ context.Context, what Reloadable) error {
	reload, ok := l.Reloaders[what]
	if !ok {
		return fmt.Errorf("nothing to reload by the name %q", what)
	}
	return reload()
}
