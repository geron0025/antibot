package main

import (
	"net"
	"strings"
	"testing"

	"github.com/geron0025/antibot/internal/config"
)

// A port somebody else holds is a refusal to start that names the key,
// and the ports taken before it are given back.
func TestATakenPortStopsTheStart(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	var cfg config.Config
	cfg.Listen.HTTP = "127.0.0.1:0"
	cfg.Listen.Admin = held.Addr().String()

	_, err = takePorts(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "listen.admin "+held.Addr().String()) {
		t.Fatalf("err = %v", err)
	}

	// Everything free: every port is taken and none is left out.
	cfg.Listen.Admin = "127.0.0.1:0"
	p, err := takePorts(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.http.Close()
	defer p.service.Close()
	if p.http == nil || p.service == nil || p.https != nil {
		t.Fatalf("%+v", p)
	}
}
