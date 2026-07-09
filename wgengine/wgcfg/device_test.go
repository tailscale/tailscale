// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/key"
)

func TestNewPeerLookupFunc(t *testing.T) {
	k1, _ := newK()

	k2, _ := newK()
	ip2 := netip.MustParsePrefix("10.0.0.2/32")

	k3, _ := newK()

	dev := NewDevice(newNilTun(), new(noopBind), device.NewLogger(device.LogLevelError, "test"))
	defer dev.Close()

	// peers is the live per-peer config source, standing in for what
	// LocalBackend provides via wgengine.Engine.SetPeerConfigFunc.
	peers := map[device.NoisePublicKey][]netip.Prefix{
		k2.Raw32(): {ip2},
	}
	dev.SetPeerLookupFunc(NewPeerLookupFunc(dev.Bind(), t.Logf, func(pubk device.NoisePublicKey) ([]netip.Prefix, bool) {
		ips, ok := peers[pubk]
		return ips, ok
	}))

	t.Run("lazy-creation", func(t *testing.T) {
		// A peer known to the config source should be creatable on
		// demand via LookupPeer.
		if p := dev.LookupPeer(k2.Raw32()); p == nil {
			t.Fatal("expected peer k2 to exist via LookupPeer")
		}
		// An unknown peer should not be found.
		if p := dev.LookupPeer(k3.Raw32()); p != nil {
			t.Fatal("expected unknown peer k3 to not exist")
		}
	})

	t.Run("remove-peer", func(t *testing.T) {
		delete(peers, k2.Raw32())
		dev.RemoveMatchingPeers(func(pk device.NoisePublicKey) bool {
			_, ok := peers[pk]
			return !ok
		})
		if p := dev.LookupPeer(k2.Raw32()); p != nil {
			t.Fatal("expected peer k2 to not exist after removal")
		}
	})

	t.Run("self-key-not-peer", func(t *testing.T) {
		// The device's own key should not be a peer.
		if p := dev.LookupPeer(k1.Raw32()); p != nil {
			t.Fatal("expected own key to not be a peer")
		}
	})
}

func newK() (key.NodePublic, key.NodePrivate) {
	k := key.NewNode()
	return k.Public(), k
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

func (t *nilTun) File() *os.File           { return nil }
func (t *nilTun) Flush() error             { return nil }
func (t *nilTun) MTU() (int, error)        { return 1420, nil }
func (t *nilTun) Name() (string, error)    { return "niltun", nil }
func (t *nilTun) Events() <-chan tun.Event { return t.events }

func (t *nilTun) Read(data [][]byte, sizes []int, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Write(data [][]byte, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Close() error {
	close(t.events)
	close(t.closed)
	return nil
}

func (t *nilTun) BatchSize() int { return 1 }

// A noopBind is a conn.Bind that does no actual binding work.
type noopBind struct{}

func (noopBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return nil, 1, nil
}
func (noopBind) Close() error                                        { return nil }
func (noopBind) SetMark(mark uint32) error                           { return nil }
func (noopBind) Send(b [][]byte, ep conn.Endpoint, offset int) error { return nil }
func (noopBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return dummyEndpoint(s), nil
}
func (noopBind) BatchSize() int { return 1 }

// A dummyEndpoint is a string holding the endpoint destination.
type dummyEndpoint string

func (e dummyEndpoint) ClearSrc()           {}
func (e dummyEndpoint) SrcToString() string { return "" }
func (e dummyEndpoint) DstToString() string { return string(e) }
func (e dummyEndpoint) DstToBytes() []byte  { return nil }
func (e dummyEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (dummyEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }
