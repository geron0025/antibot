package h2fp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func certificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The fingerprint is taken from a live HTTP/2 connection rather than from
// prepared bytes: the whole point of the sniffer is that it sits in the
// stream and spoils nothing in it, and that has to be checked as a whole.
func TestFingerprintFromLiveConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	captured := make(chan Fingerprint, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{certificate(t)},
			NextProtos:   []string{"h2"},
		})
		if err := tlsConn.Handshake(); err != nil {
			return
		}

		sniffer := Sniff(tlsConn)
		(&http2.Server{}).ServeConn(sniffer, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "done")
				captured <- sniffer.Fingerprint()
			}),
		})
	}()

	client := &http.Client{Transport: &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + listener.Addr().String() + "/check")
	if err != nil {
		t.Fatalf("the request did not go through: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "done" {
		t.Fatalf("response body: %q — the sniffer spoiled the stream", body)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("the connection turned out to be HTTP/%d", resp.ProtoMajor)
	}

	select {
	case fp := <-captured:
		if !fp.Complete {
			t.Errorf("the fingerprint was not captured completely: %+v", fp)
		}
		if len(fp.Settings) == 0 {
			t.Error("SETTINGS were not captured")
		}
		s := fp.String()
		if strings.Count(s, "|") != 3 {
			t.Errorf("fingerprint format: %q", s)
		}
		// The pseudo-header order is what this was all started for.
		for _, letter := range []string{"m", "a", "s", "p"} {
			if !strings.Contains(fp.Pseudo, letter) {
				t.Errorf("the pseudo-header order lacks %q: %q", letter, fp.Pseudo)
			}
		}
		t.Logf("captured fingerprint: %s", s)
	case <-time.After(5 * time.Second):
		t.Fatal("the fingerprint was never captured")
	}
}
