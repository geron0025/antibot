package proxy

import "testing"

func testRouter() *Router {
	return NewRouter(map[string]string{
		"shop.example.ru": "exact",
		"*.example.ru":    "subdomains",
		"*.b.example.ru":  "deeper",
		"пример.рф":       "unicode",
		"*":               "fallback",
	})
}

func TestRouteSelection(t *testing.T) {
	r := testRouter()
	cases := map[string]string{
		"shop.example.ru":       "exact",
		"shop.example.ru:8443":  "exact",
		"SHOP.EXAMPLE.RU":       "exact",
		"api.example.ru":        "subdomains",
		"a.b.example.ru":        "deeper",
		"example.ru":            "fallback", // *.example.ru does not cover the domain itself
		"пример.рф":             "unicode",
		"xn--e1afmkfd.xn--p1ai": "unicode",
		"foreign.site":          "fallback",
	}
	for host, want := range cases {
		to, ok := r.To(host)
		if !ok || to != want {
			t.Errorf("To(%q) = %q,%v — want %q", host, to, ok, want)
		}
	}
}

// The order in which the routes made it into the configuration must not
// affect anything: otherwise swapping two lines in the config changes the
// site's behaviour.
func TestOrderDoesNotMatter(t *testing.T) {
	forward := NewRouter(map[string]string{"*.example.ru": "wide", "*.b.example.ru": "narrow"})
	backward := NewRouter(map[string]string{"*.b.example.ru": "narrow", "*.example.ru": "wide"})

	for _, host := range []string{"a.b.example.ru", "c.example.ru"} {
		a, _ := forward.To(host)
		b, _ := backward.To(host)
		if a != b {
			t.Errorf("%s: %q against %q", host, a, b)
		}
	}
}

func TestWithoutAFallbackThereIsNoRoute(t *testing.T) {
	r := NewRouter(map[string]string{"shop.example.ru": "exact"})
	if _, ok := r.To("foreign.site"); ok {
		t.Error("a route was found where none was configured")
	}
}
