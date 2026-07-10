// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package bird

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/feature"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine"
)

// fakeBIRD is a fake BIRD server listening on a unix socket. It speaks
// enough of the BIRD CLI wire protocol to satisfy chirp and records the
// commands it receives so tests can assert on them.
type fakeBIRD struct {
	ln   net.Listener
	sock string

	mu       sync.Mutex
	calls    []string // commands received, e.g. "enable tailscale"
	enabled  bool     // whether the "tailscale" protocol is enabled
	failNext bool     // whether to reply to the next command with a runtime error
}

func newFakeBIRD(t *testing.T) *fakeBIRD {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "bird.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBIRD{ln: ln, sock: sock}
	t.Cleanup(func() { ln.Close() })
	go fb.listen()
	return fb
}

func (fb *fakeBIRD) listen() {
	for {
		c, err := fb.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			panic(err)
		}
		go fb.handle(c)
	}
}

func (fb *fakeBIRD) handle(c net.Conn) {
	fmt.Fprintln(c, "0001 BIRD 2.0.8 ready.")
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		cmd := sc.Text()
		var proto string
		var wantEnabled bool
		switch {
		case strings.HasPrefix(cmd, "enable "):
			proto, wantEnabled = strings.TrimPrefix(cmd, "enable "), true
		case strings.HasPrefix(cmd, "disable "):
			proto, wantEnabled = strings.TrimPrefix(cmd, "disable "), false
		}

		fb.mu.Lock()
		fb.calls = append(fb.calls, cmd)
		fail := fb.failNext
		fb.failNext = false
		switch {
		case proto != protocolName:
			fmt.Fprintln(c, "9001 syntax error, unexpected CF_SYM_UNDEFINED, expecting CF_SYM_KNOWN or TEXT or ALL")
		case fail:
			fmt.Fprintln(c, "8001 fake runtime error")
		case wantEnabled == fb.enabled:
			fmt.Fprintf(c, "0010-%s: already %s\n0000 \n", proto, verb(wantEnabled))
		default:
			fb.enabled = wantEnabled
			fmt.Fprintf(c, "0011-%s: %s\n0000 \n", proto, verb(wantEnabled))
		}
		fb.mu.Unlock()
	}
	if err := sc.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		panic(err)
	}
}

func verb(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

// takeCalls returns the commands received since the last call and
// resets the record. It is safe to call once the chirp request that
// caused them has returned, as chirp waits for each response.
func (fb *fakeBIRD) takeCalls() []string {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	calls := fb.calls
	fb.calls = nil
	return calls
}

func (fb *fakeBIRD) checkCalls(t *testing.T, want ...string) {
	t.Helper()
	if diff := cmp.Diff(fb.takeCalls(), want, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("BIRD calls mismatch (-got +want):\n%s", diff)
	}
}

func node(primaryRoutes, routableIPs []netip.Prefix) tailcfg.NodeView {
	return (&tailcfg.Node{
		PrimaryRoutes: primaryRoutes,
		Hostinfo:      (&tailcfg.Hostinfo{RoutableIPs: routableIPs}).View(),
	}).View()
}

func TestBird(t *testing.T) {
	if !feature.IsRegistered("bird") {
		t.Fatal("bird feature not registered")
	}

	fb := newFakeBIRD(t)
	newBird, ok := wgengine.HookNewBird.GetOk()
	if !ok {
		t.Fatal("HookNewBird not set")
	}
	b, err := newBird(t.Logf, fb.sock)
	if err != nil {
		t.Fatal(err)
	}
	// Construction disables the protocol.
	fb.checkCalls(t, "disable tailscale")

	pfx := netip.MustParsePrefix
	subnetRouter := node(
		[]netip.Prefix{pfx("192.168.1.0/24")},
		[]netip.Prefix{pfx("192.168.1.0/24"), pfx("10.0.0.0/8")},
	)
	notSubnetRouter := node(
		[]netip.Prefix{pfx("192.168.2.0/24")},
		[]netip.Prefix{pfx("192.168.1.0/24")},
	)

	// An invalid self node is not a subnet router; no state change, no calls.
	if changed := b.Reconfig(tailcfg.NodeView{}); changed {
		t.Error("Reconfig(invalid) reported change")
	}
	b.ReconfigDone()
	fb.checkCalls(t)

	// Becoming a primary subnet router enables the protocol.
	if changed := b.Reconfig(subnetRouter); !changed {
		t.Error("Reconfig(subnetRouter) reported no change")
	}
	b.ReconfigDone()
	fb.checkCalls(t, "enable tailscale")

	// Reconfig with the same state is a no-op.
	if changed := b.Reconfig(subnetRouter); changed {
		t.Error("Reconfig(subnetRouter) again reported change")
	}
	b.ReconfigDone()
	fb.checkCalls(t)

	// A BIRD failure leaves the state unapplied, so the next Reconfig
	// still reports a change and retries.
	fb.mu.Lock()
	fb.failNext = true
	fb.mu.Unlock()
	if changed := b.Reconfig(notSubnetRouter); !changed {
		t.Error("Reconfig(notSubnetRouter) reported no change")
	}
	b.ReconfigDone()
	fb.checkCalls(t, "disable tailscale")
	if changed := b.Reconfig(notSubnetRouter); !changed {
		t.Error("Reconfig(notSubnetRouter) retry reported no change")
	}
	b.ReconfigDone()
	fb.checkCalls(t, "disable tailscale")

	// And becoming a subnet router again enables it again.
	if changed := b.Reconfig(subnetRouter); !changed {
		t.Error("Reconfig(subnetRouter) reported no change")
	}
	b.ReconfigDone()
	fb.checkCalls(t, "enable tailscale")

	// Close disables the protocol on the way out.
	b.Close()
	fb.checkCalls(t, "disable tailscale")
}
