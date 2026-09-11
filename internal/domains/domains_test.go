package domains

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	good := map[string]string{
		"shop.example.ru":   "shop.example.ru",
		"Shop.Example.RU":   "shop.example.ru",
		"*.example.ru":      "*.example.ru",
		"*.ПрИмЕр.рф":       "*.xn--e1afmkfd.xn--p1ai",
		"пример.рф":         "xn--e1afmkfd.xn--p1ai",
		" shop.example.ru ": "shop.example.ru",
	}
	for in, want := range good {
		got, err := NormalizeHost(in)
		if err != nil {
			t.Errorf("NormalizeHost(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}

	bad := []string{"", "*", "*.", "a b.ru", "a/b.ru", "*.*.ru"}
	for _, in := range bad {
		if got, err := NormalizeHost(in); err == nil {
			t.Errorf("NormalizeHost(%q) = %q, want a refusal", in, got)
		}
	}
}

func TestValidate(t *testing.T) {
	bad := []struct {
		list []Domain
		why  string
	}{
		{[]Domain{{Host: "a.ru", To: "ftp://1.2.3.4"}}, "a scheme that is not http/https"},
		{[]Domain{{Host: "a.ru", To: "http://"}}, "no server"},
		{[]Domain{{Host: "a.ru", To: "http://user:pw@1.2.3.4"}}, "credentials"},
		{[]Domain{{Host: "a.ru", To: "http://1.2.3.4/path"}}, "a path"},
		{[]Domain{{Host: "a.ru", To: "http://1.2.3.4?x=1"}}, "a query"},
		{[]Domain{{Host: "A.ru", To: "http://1.2.3.4"}}, "a non-normalized host"},
		{[]Domain{
			{Host: "a.ru", To: "http://1.2.3.4"},
			{Host: "a.ru", To: "http://1.2.3.5"},
		}, "a duplicate"},
	}
	for _, c := range bad {
		if err := Validate(c.list); err == nil {
			t.Errorf("Validate accepted %s: %+v", c.why, c.list)
		}
	}

	if err := Validate([]Domain{
		{Host: "a.ru", To: "http://127.0.0.1:8080"},
		{Host: "*.a.ru", To: "https://[2001:db8::1]:8443"},
		{Host: "b.ru", To: "http://backend"},
	}); err != nil {
		t.Errorf("a valid list was refused: %v", err)
	}
}

func TestAddRemoveAndReread(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.json")
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}

	changes := 0
	s.OnChange(func() { changes++ })

	added, err := s.Add("Shop.Example.RU", "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if added.Host != "shop.example.ru" {
		t.Errorf("the host was not normalized: %q", added.Host)
	}
	if changes == 0 {
		t.Error("the change did not reach the listener")
	}
	if to, ok := s.Routes()["shop.example.ru"]; !ok || to != "http://127.0.0.1:8080" {
		t.Errorf("the route did not appear: %v", s.Routes())
	}

	// A second copy is a refusal, in any spelling.
	if _, err := s.Add("SHOP.example.ru", "http://127.0.0.1:9090"); err == nil {
		t.Error("a duplicate was accepted")
	}

	if err := s.Remove("shop.example.ru"); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Errorf("the domain stayed after removal: %v", s.List())
	}
	if err := s.Remove("shop.example.ru"); err == nil {
		t.Error("removing a non-existent domain did not say so")
	}
}

// A broken file keeps the previous list in force: half a list looks
// working and is therefore worse than a refusal.
func TestABrokenFileKeepsThePreviousList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.json")
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("a.ru", "http://127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(`{"version":1,"domains":[{"host":"broken`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reload(); err == nil {
		t.Error("the broken file was not reported")
	}
	if len(s.List()) != 1 || s.List()[0].Host != "a.ru" {
		t.Errorf("the previous list did not stay in force: %v", s.List())
	}
}

// A typo in a field name is an error, not a silently skipped intention.
func TestATypoInAFieldNameIsAnError(t *testing.T) {
	if _, err := Parse([]byte(`{"version":1,"domains":[{"hosts":"a.ru","to":"http://1.2.3.4"}]}`)); err == nil ||
		!strings.Contains(err.Error(), "hosts") {
		t.Errorf("the typo went unnoticed: %v", err)
	}
}
