package tlsfp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
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
		DNSNames:     []string{"shop.example.ru"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The main property of interception: the handshake still completes after
// it. Should this break, the node stops serving absolutely everyone —
// people and bots alike.
func TestInterceptDoesNotBreakHandshake(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	interceptor := Intercept(serverSide)
	server := tls.Server(interceptor, &tls.Config{
		Certificates: []tls.Certificate{certificate(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	})

	done := make(chan error, 1)
	go func() {
		defer server.Close()
		if err := server.Handshake(); err != nil {
			done <- err
			return
		}
		if _, err := server.Write([]byte("hello")); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	client := tls.Client(clientSide, &tls.Config{
		ServerName:         "shop.example.ru",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("the client could not negotiate: %v", err)
	}

	buf := make([]byte, len("hello"))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("the data did not arrive: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("received %q", buf)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}

	h, err := interceptor.Hello()
	if err != nil {
		t.Fatalf("parsing the intercepted message failed: %v", err)
	}
	if h.SNI != "shop.example.ru" {
		t.Errorf("SNI: %q", h.SNI)
	}
	if !strings.HasPrefix(h.JA4(), "t13d") {
		t.Errorf("JA4 does not look like TLS 1.3 with a domain name: %s", h.JA4())
	}
}

// A connection torn down in the middle of the first record must neither
// panic nor eat bytes: scanners break handshakes all the time.
func TestTornConnection(t *testing.T) {
	clientSide, serverSide := net.Pipe()

	go func() {
		clientSide.Write([]byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01, 0x02})
		clientSide.Close()
	}()

	interceptor := Intercept(serverSide)
	rest, err := io.ReadAll(interceptor)
	if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("unexpected read error: %v", err)
	}

	// Everything read went back into the stream: crypto/tls will see the
	// same bytes.
	if len(rest) != 5 {
		t.Errorf("%d bytes in the stream, want the 5 read from the header", len(rest))
	}
	if _, err := interceptor.Hello(); err == nil {
		t.Error("a torn record parsed without an error")
	}
}
