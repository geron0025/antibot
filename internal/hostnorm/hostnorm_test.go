package hostnorm

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"shop.example.ru":      "shop.example.ru",
		"Shop.Example.RU":      "shop.example.ru",
		"shop.example.ru:8443": "shop.example.ru",
		"shop.example.ru.":     "shop.example.ru",
		"  shop.example.ru  ":  "shop.example.ru",
		"пример.рф":            "xn--e1afmkfd.xn--p1ai",
		"ПРИМЕР.РФ":            "xn--e1afmkfd.xn--p1ai",
		"[2001:db8::1]:443":    "2001:db8::1",
		"[2001:db8::1]":        "2001:db8::1",
		"127.0.0.1:80":         "127.0.0.1",
		"":                     "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// A Unicode name and its punycode form must agree: otherwise a rule
// written by a human in Russian will not match an event written by the
// machine.
func TestUnicodeAndPunycodeAgree(t *testing.T) {
	if Normalize("пример.рф") != Normalize("xn--e1afmkfd.xn--p1ai") {
		t.Error("the same name normalized differently")
	}
}
