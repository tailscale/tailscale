// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgcfg

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"go4.org/mem"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"inet.af/netaddr"
	"tailscale.com/types/key"
)

func TestDeviceConfig(t *testing.T) {
	newK := func() (key.NodePublic, key.NodePrivate) {
		t.Helper()
		k := key.NewNode()
		return k.Public(), k
	}
	k1, pk1 := newK()
	ip1 := netaddr.MustParseIPPrefix("10.0.0.1/32")

	k2, pk2 := newK()
	ip2 := netaddr.MustParseIPPrefix("10.0.0.2/32")

	k3, _ := newK()
	ip3 := netaddr.MustParseIPPrefix("10.0.0.3/32")

	cfg1 := &Config{
		PrivateKey: pk1,
		Peers: []Peer{{
			PublicKey:  k2,
			AllowedIPs: []netaddr.IPPrefix{ip2},
		}},
	}

	cfg2 := &Config{
		PrivateKey: pk2,
		Peers: []Peer{{
			PublicKey:           k1,
			AllowedIPs:          []netaddr.IPPrefix{ip1},
			PersistentKeepalive: 5,
		}},
	}

	device1 := NewDevice(newNilTun(), new(noopBind), device.NewLogger(device.LogLevelError, "device1"))
	device2 := NewDevice(newNilTun(), new(noopBind), device.NewLogger(device.LogLevelError, "device2"))
	defer device1.Close()
	defer device2.Close()

	cmp := func(t *testing.T, d *device.Device, want *Config) {
		t.Helper()
		got, err := DeviceConfig(d)
		if err != nil {
			t.Fatal(err)
		}
		prev := new(Config)
		gotbuf := new(strings.Builder)
		err = got.ToUAPI(gotbuf, prev)
		gotStr := gotbuf.String()
		if err != nil {
			t.Errorf("got.ToUAPI(): error: %v", err)
			return
		}
		wantbuf := new(strings.Builder)
		err = want.ToUAPI(wantbuf, prev)
		wantStr := wantbuf.String()
		if err != nil {
			t.Errorf("want.ToUAPI(): error: %v", err)
			return
		}
		if gotStr != wantStr {
			buf := new(bytes.Buffer)
			w := bufio.NewWriter(buf)
			if err := d.IpcGetOperation(w); err != nil {
				t.Errorf("on error, could not IpcGetOperation: %v", err)
			}
			w.Flush()
			t.Errorf("config mismatch:\n---- got:\n%s\n---- want:\n%s\n---- uapi:\n%s", gotStr, wantStr, buf.String())
		}
	}

	t.Run("device1 config", func(t *testing.T) {
		if err := ReconfigDevice(device1, cfg1, t.Logf); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)
	})

	t.Run("device2 config", func(t *testing.T) {
		if err := ReconfigDevice(device2, cfg2, t.Logf); err != nil {
			t.Fatal(err)
		}
		cmp(t, device2, cfg2)
	})

	// This is only to test that Config and Reconfig are properly synchronized.
	t.Run("device2 config/reconfig", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			ReconfigDevice(device2, cfg2, t.Logf)
			wg.Done()
		}()

		go func() {
			DeviceConfig(device2)
			wg.Done()
		}()

		wg.Wait()
	})

	t.Run("device1 modify peer", func(t *testing.T) {
		cfg1.Peers[0].DiscoKey = key.DiscoPublicFromRaw32(mem.B([]byte{0: 1, 31: 0}))
		if err := ReconfigDevice(device1, cfg1, t.Logf); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)
	})

	t.Run("device1 replace endpoint", func(t *testing.T) {
		cfg1.Peers[0].DiscoKey = key.DiscoPublicFromRaw32(mem.B([]byte{0: 2, 31: 0}))
		if err := ReconfigDevice(device1, cfg1, t.Logf); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)
	})

	t.Run("device1 add new peer", func(t *testing.T) {
		cfg1.Peers = append(cfg1.Peers, Peer{
			PublicKey:  k3,
			AllowedIPs: []netaddr.IPPrefix{ip3},
		})
		sort.Slice(cfg1.Peers, func(i, j int) bool {
			return cfg1.Peers[i].PublicKey.Less(cfg1.Peers[j].PublicKey)
		})

		origCfg, err := DeviceConfig(device1)
		if err != nil {
			t.Fatal(err)
		}

		if err := ReconfigDevice(device1, cfg1, t.Logf); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)

		newCfg, err := DeviceConfig(device1)
		if err != nil {
			t.Fatal(err)
		}

		peer0 := func(cfg *Config) Peer {
			p, ok := cfg.PeerWithKey(k2)
			if !ok {
				t.Helper()
				t.Fatal("failed to look up peer 2")
			}
			return p
		}
		peersEqual := func(p, q Peer) bool {
			return p.PublicKey == q.PublicKey && p.DiscoKey == q.DiscoKey && p.PersistentKeepalive == q.PersistentKeepalive && cidrsEqual(p.AllowedIPs, q.AllowedIPs)
		}
		if !peersEqual(peer0(origCfg), peer0(newCfg)) {
			t.Error("reconfig modified old peer")
		}
	})

	t.Run("device1 remove peer", func(t *testing.T) {
		removeKey := cfg1.Peers[len(cfg1.Peers)-1].PublicKey
		cfg1.Peers = cfg1.Peers[:len(cfg1.Peers)-1]

		if err := ReconfigDevice(device1, cfg1, t.Logf); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)

		newCfg, err := DeviceConfig(device1)
		if err != nil {
			t.Fatal(err)
		}

		_, ok := newCfg.PeerWithKey(removeKey)
		if ok {
			t.Error("reconfig failed to remove peer")
		}
	})
}

// TODO: replace with a loopback tunnel
type nilTun struct {
	events chan tun.Event
	closed chan struct{}
}

func newNilTun() tun.Device {
	return &nilTun{
		events: make(chan tun.Event),
		closed: make(chan struct{}),
	}
}

func (t *nilTun) File() *os.File         { return nil }
func (t *nilTun) Flush() error           { return nil }
func (t *nilTun) MTU() (int, error)      { return 1420, nil }
func (t *nilTun) Name() (string, error)  { return "niltun", nil }
func (t *nilTun) Events() chan tun.Event { return t.events }

func (t *nilTun) Read(data []byte, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Write(data []byte, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Close() error {
	close(t.events)
	close(t.closed)
	return nil
}

// A noopBind is a conn.Bind that does no actual binding work.
type noopBind struct{}

func (noopBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return nil, 1, nil
}
func (noopBind) Close() error                          { return nil }
func (noopBind) SetMark(mark uint32) error             { return nil }
func (noopBind) Send(b []byte, ep conn.Endpoint) error { return nil }
func (noopBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return dummyEndpoint(s), nil
}

// A dummyEndpoint is a string holding the endpoint destination.
type dummyEndpoint string

func (e dummyEndpoint) ClearSrc()           {}
func (e dummyEndpoint) SrcToString() string { return "" }
func (e dummyEndpoint) DstToString() string { return string(e) }
func (e dummyEndpoint) DstToBytes() []byte  { return nil }
func (e dummyEndpoint) DstIP() net.IP       { return nil }
func (dummyEndpoint) SrcIP() net.IP         { return nil }
