// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/nettest"
	"tailscale.com/types/appctype"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestPortForwardingArguments(t *testing.T) {
	tests := []struct {
		in      string
		wanterr string
		want    *portForward
	}{
		{"", "", nil},
		{"bad port specifier", "cannot parse", nil},
		{"tcp/xyz/example.com", "bad forwarding port", nil},
		{"tcp//example.com", "bad forwarding port", nil},
		{"tcp/2112/", "bad destination", nil},
		{"udp/53/example.com", "unsupported forwarding protocol", nil},
		{"tcp/22/github.com", "", &portForward{Proto: "tcp", Port: 22, Destination: "github.com"}},
	}
	for _, tt := range tests {
		got, goterr := parseForward(tt.in)
		if tt.wanterr != "" {
			if !strings.Contains(goterr.Error(), tt.wanterr) {
				t.Errorf("f(%q).err = %v; want %v", tt.in, goterr, tt.wanterr)
			}
		} else if diff := cmp.Diff(got, tt.want); diff != "" {
			t.Errorf("Parsed forward (-got, +want):\n%s", diff)
		}
	}
}

var verboseDERP = flag.Bool("verbose-derp", false, "if set, print DERP and STUN logs")
var verboseNodes = flag.Bool("verbose-nodes", false, "if set, print tsnet.Server logs")

func startControl(t *testing.T) (control *testcontrol.Server, controlURL string) {
	// Corp#4520: don't use netns for tests.
	netns.SetEnabled(false)
	t.Cleanup(func() {
		netns.SetEnabled(true)
	})

	derpLogf := logger.Discard
	if *verboseDERP {
		derpLogf = t.Logf
	}
	derpMap := integration.RunDERPAndSTUN(t, derpLogf, "127.0.0.1")
	control = &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL = control.HTTPTestServer.URL
	t.Logf("testcontrol listening on %s", controlURL)
	return control, controlURL
}

func startNode(t *testing.T, ctx context.Context, controlURL, hostname string) (*tsnet.Server, key.NodePublic, netip.Addr) {
	t.Helper()

	tmp := filepath.Join(t.TempDir(), hostname)
	os.MkdirAll(tmp, 0755)
	s := &tsnet.Server{
		Dir:        tmp,
		ControlURL: controlURL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	if *verboseNodes {
		s.Logf = log.Printf
	}
	t.Cleanup(func() { s.Close() })

	status, err := s.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s, status.Self.PublicKey, status.TailscaleIPs[0]
}

func TestSNIProxyWithNetmapConfig(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	c, controlURL := startControl(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a listener to proxy connections to.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Start sniproxy
	sni, nodeKey, ip := startNode(t, ctx, controlURL, "snitest")
	go run(ctx, sni, 0, sni.Hostname, false, 0, "", "")

	// Configure the mock coordination server to send down app connector config.
	config := &appctype.AppConnectorConfig{
		DNAT: map[appctype.ConfigID]appctype.DNATConfig{
			"nic_test": {
				Addrs: []netip.Addr{ip},
				To:    []string{"127.0.0.1"},
				IP: []tailcfg.ProtoPortRange{
					{
						Proto: int(ipproto.TCP),
						Ports: tailcfg.PortRange{First: uint16(ln.Addr().(*net.TCPAddr).Port), Last: uint16(ln.Addr().(*net.TCPAddr).Port)},
					},
				},
			},
		},
	}
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	c.SetNodeCapMap(nodeKey, tailcfg.NodeCapMap{
		configCapKey: []tailcfg.RawMessage{tailcfg.RawMessage(b)},
	})

	// Let's spin up a second node (to represent the client).
	client, _, _ := startNode(t, ctx, controlURL, "client")

	// Make sure that the sni node has received its config.
	lc, err := sni.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	gotConfigured := false
	for range 100 {
		s, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Self.CapMap) > 0 {
			gotConfigured = true
			break // we got it
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !gotConfigured {
		t.Error("sni node never received its configuration from the coordination server!")
	}

	// Let's make the client open a connection to the sniproxy node, and
	// make sure it results in a connection to our test listener.
	w, err := client.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", ip, ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	r, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}

func TestSNIProxyWithFlagConfig(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	_, controlURL := startControl(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a listener to proxy connections to.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Start sniproxy
	sni, _, ip := startNode(t, ctx, controlURL, "snitest")
	go run(ctx, sni, 0, sni.Hostname, false, 0, "", fmt.Sprintf("tcp/%d/localhost", ln.Addr().(*net.TCPAddr).Port))

	// Let's spin up a second node (to represent the client).
	client, _, _ := startNode(t, ctx, controlURL, "client")

	// Let's make the client open a connection to the sniproxy node, and
	// make sure it results in a connection to our test listener.
	w, err := client.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", ip, ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	r, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}
