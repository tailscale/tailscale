// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestTSWGTailscaledKeyRotation checks that when a peer rotates its node
// key, the kernel data plane changes the kernel peer's key in place (an
// atomic rename, keeping its allowed IPs and so its traffic), rather than
// removing the old peer and adding a new one, and that the tunnel works
// with the new key.
func TestTSWGTailscaledKeyRotation(t *testing.T) {
	f := newTSWGTailscaled(t, vnet.EasyNAT)
	n1, n2 := f.nodes[0], f.nodes[1]
	f.env.LANPing(n1, f.ip(n2))
	oldKey := f.env.Status(n2).Self.PublicKey

	// While n2 rotates, watch n1's kernel peers: there must always be
	// exactly one.
	var bad atomic.Value
	stop := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			d, err := f.show(n1)
			if err == nil && len(d.Peers) != 1 {
				bad.Store(fmt.Sprintf("%d kernel peers", len(d.Peers)))
			}
		}
	}()

	prefsJSON, err := f.env.Tailscale(n2, "debug", "prefs")
	if err != nil {
		t.Fatalf("debug prefs: %v", err)
	}
	var prefs struct{ ControlURL string }
	if err := json.Unmarshal([]byte(prefsJSON), &prefs); err != nil {
		t.Fatalf("parsing prefs %q: %v", prefsJSON, err)
	}
	if out, err := f.env.Tailscale(n2, "up", "--force-reauth", "--login-server="+prefs.ControlURL, "--accept-routes"); err != nil {
		t.Fatalf("up --force-reauth: %v: %s", err, out)
	}
	var newKey string
	if err := tstest.WaitFor(30*time.Second, func() error {
		k := f.env.Status(n2).Self.PublicKey
		if k == oldKey {
			return fmt.Errorf("n2's node key hasn't changed")
		}
		newKey = k.String()
		d, err := f.show(n1)
		if err != nil {
			return err
		}
		if len(d.Peers) != 1 || d.Peers[0].PublicKey != k {
			var have []string
			for _, p := range d.Peers {
				have = append(have, p.PublicKey.ShortString())
			}
			return fmt.Errorf("n1's kernel peers are %v; want n2's new key %v (old %v)", have, k.ShortString(), oldKey.ShortString())
		}
		return nil
	}); err != nil {
		for _, line := range strings.Split(f.env.NodeLogs(n1), "\n") {
			if strings.Contains(line, "tswg:") {
				t.Logf("n1: %s", line)
			}
		}
		t.Fatal(err)
	}
	close(stop)
	<-watched
	t.Logf("n2 rotated its key from %v to %v", oldKey.ShortString(), newKey)
	if v := bad.Load(); v != nil {
		t.Errorf("n1's kernel had %v during the rotation, want always 1", v)
	}
	// Logs arrive late.
	if err := tstest.WaitFor(20*time.Second, func() error {
		if !strings.Contains(f.env.NodeLogs(n1), "rotated its key") {
			return fmt.Errorf("n1's logs don't mention the rotation")
		}
		return nil
	}); err != nil {
		for _, line := range strings.Split(f.env.NodeLogs(n1), "\n") {
			if strings.Contains(line, "tswg:") {
				t.Logf("n1: %s", line)
			}
		}
		t.Errorf("n1 didn't rename the kernel peer: %v", err)
	}

	f.env.LANPing(n1, f.ip(n2))
	f.env.LANPing(n2, f.ip(n1))
}
