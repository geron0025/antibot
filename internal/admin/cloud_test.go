package admin

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A node without a token says in so many words that nothing leaves it;
// with one, the overview shows how both directions fare.
func TestOverviewSaysWhatTheCloudGets(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	s.o.Cloud = func() CloudState { return CloudState{} }
	page, _ := io.ReadAll(get(t, s, "/", cookies).Body)
	if !strings.Contains(string(page), "This node talks to nobody") {
		t.Fatal("a node without a token does not say that nothing leaves it")
	}

	s.o.Cloud = func() CloudState {
		return CloudState{Token: true, Fetching: true, FactsVersion: 12, FactsBuilt: time.Now(),
			Outbox: 3, LastProblem: "the cloud did not accept the token (401); sending sleeps for an hour"}
	}
	page, _ = io.ReadAll(get(t, s, "/", cookies).Body)
	for _, want := range []string{"version 12", "3 waiting to be sent", "none accepted since the start",
		"did not accept the token (401)"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("the overview does not say %q", want)
		}
	}
}

// The admin UI's own certificate is reread when its files change, and a
// pair that does not load keeps the previous one in force.
func TestAdminCertificateIsReread(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
	write := func(name string, at time.Time) {
		chain, key := pemPair(t, time.Now().Add(90*24*time.Hour), name)
		os.WriteFile(certFile, chain, 0o600)
		os.WriteFile(keyFile, key, 0o600)
		os.Chtimes(certFile, at, at)
		os.Chtimes(keyFile, at, at)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	write("admin-one.example.ru", time.Now())
	c, err := loadCertificate(certFile, keyFile, log)
	if err != nil {
		t.Fatal(err)
	}
	c.every = 0
	first, _ := c.get(nil)

	write("admin-two.example.ru", time.Now().Add(time.Minute))
	second, _ := c.get(nil)
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("the renewed certificate was not taken up")
	}

	os.WriteFile(certFile, []byte("not a certificate"), 0o600)
	later := time.Now().Add(2 * time.Minute)
	os.Chtimes(certFile, later, later)
	third, _ := c.get(nil)
	if !bytes.Equal(third.Certificate[0], second.Certificate[0]) {
		t.Fatal("a broken pair replaced a working one")
	}

	// A pair that does not load stops the start, before any port is taken.
	users, _ := OpenUsers(filepath.Join(dir, "admin.json"))
	users.Set("owner", password)
	_, err = New(Options{Addr: "0.0.0.0:0", Cert: certFile, Key: keyFile, Users: users, Log: log})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a broken pair at the start: %v", err)
	}
}
