package proxy

import (
	"net/http"
	"net/netip"
	"testing"
)

func request(peer string, xff ...string) *http.Request {
	r := &http.Request{RemoteAddr: peer, Header: http.Header{}}
	for _, h := range xff {
		r.Header.Add("X-Forwarded-For", h)
	}
	return r
}

func prefixes(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(s))
	for _, p := range s {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, prefix)
	}
	return out
}

func TestClientAddr(t *testing.T) {
	trusted := prefixes(t, "10.0.0.0/8", "192.168.0.0/16")

	cases := []struct {
		name    string
		r       *http.Request
		trusted []netip.Prefix
		want    string
	}{
		{
			"without trusted networks the header is ignored",
			request("203.0.113.5:1234", "1.2.3.4"),
			nil, "203.0.113.5",
		},
		{
			"the peer is not trusted — the header is ignored",
			request("203.0.113.5:1234", "1.2.3.4"),
			trusted, "203.0.113.5",
		},
		{
			"one trusted intermediary",
			request("10.0.0.1:1234", "198.51.100.7"),
			trusted, "198.51.100.7",
		},
		{
			"a chain of intermediaries: take the first untrusted from the right",
			request("10.0.0.1:1234", "198.51.100.7, 10.0.0.9, 192.168.1.1"),
			trusted, "198.51.100.7",
		},
		{
			"the client forged the header — its entry is to the left of our chain",
			request("10.0.0.1:1234", "1.1.1.1, 198.51.100.7"),
			trusted, "198.51.100.7",
		},
		{
			"garbage in the chain — we trust only the TCP peer",
			request("10.0.0.1:1234", "not-an-address"),
			trusted, "10.0.0.1",
		},
		{
			"there is no header at all",
			request("10.0.0.1:1234"),
			trusted, "10.0.0.1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClientAddr(c.r, c.trusted)
			if got.String() != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}
