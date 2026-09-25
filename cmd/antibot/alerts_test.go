package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/config"
	"github.com/geron0025/antibot/internal/i18n"
)

// The language of the messages: config.yaml when it names one, then the
// file the admin UI writes, then English. The file is read at every
// message, so a change there takes effect without a restart.
func TestTheDeliveryLanguage(t *testing.T) {
	file, err := alerts.OpenCommand(filepath.Join(t.TempDir(), "alerts.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	lang := deliveryLanguage(config.Alerts{}, file)
	if got := lang(); got != i18n.EN {
		t.Fatalf("nothing said: %q", got)
	}
	if err := file.Save("true", "ru", "owner", now); err != nil {
		t.Fatal(err)
	}
	if got := lang(); got != i18n.RU {
		t.Fatalf("the file: %q", got)
	}
	if got := deliveryLanguage(config.Alerts{Language: "en"}, file)(); got != i18n.EN {
		t.Fatalf("config.yaml does not win: %q", got)
	}
	if got := deliveryLanguage(config.Alerts{Command: "logger antibot"}, file)(); got != i18n.EN {
		t.Fatalf("a command in config.yaml leaves the file out, its language too: %q", got)
	}
	if got := deliveryLanguage(config.Alerts{}, nil)(); got != i18n.EN {
		t.Fatalf("no file: %q", got)
	}
}
