// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/logtail"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestSetDiscoPublicKey(t *testing.T) {
	initialKey := key.NewDisco().Public()

	c := &Direct{
		discoPubKey: initialKey,
	}

	c.mu.Lock()
	if c.discoPubKey != initialKey {
		t.Fatalf("initial disco key mismatch: got %v, want %v", c.discoPubKey, initialKey)
	}
	c.mu.Unlock()

	newKey := key.NewDisco().Public()
	c.SetDiscoPublicKey(newKey)

	c.mu.Lock()
	if c.discoPubKey != newKey {
		t.Fatalf("disco key not updated: got %v, want %v", c.discoPubKey, newKey)
	}
	if c.discoPubKey == initialKey {
		t.Fatal("disco key should have changed")
	}
	c.mu.Unlock()
}

func TestNewDirect(t *testing.T) {
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni
	bus := eventbustest.NewBus(t)

	k := key.NewMachine()
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	opts := Options{
		ServerURL: "https://example.com",
		Hostinfo:  hi,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		Dialer: dialer,
		Bus:    bus,
	}
	c, err := NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}

	if c.serverURL != opts.ServerURL {
		t.Errorf("c.serverURL got %v want %v", c.serverURL, opts.ServerURL)
	}

	// hi is stored without its NetInfo field.
	hiWithoutNi := *hi
	hiWithoutNi.NetInfo = nil
	if !hiWithoutNi.Equal(c.hostinfo) {
		t.Errorf("c.hostinfo got %v want %v", c.hostinfo, hi)
	}

	changed := c.SetNetInfo(&ni)
	if changed {
		t.Errorf("c.SetNetInfo(ni) want false got %v", changed)
	}
	ni = tailcfg.NetInfo{LinkType: "wifi"}
	changed = c.SetNetInfo(&ni)
	if !changed {
		t.Errorf("c.SetNetInfo(ni) want true got %v", changed)
	}

	changed = c.SetHostinfo(hi)
	if changed {
		t.Errorf("c.SetHostinfo(hi) want false got %v", changed)
	}
	hi = hostinfo.New()
	hi.Hostname = "different host name"
	changed = c.SetHostinfo(hi)
	if !changed {
		t.Errorf("c.SetHostinfo(hi) want true got %v", changed)
	}

	endpoints := fakeEndpoints(1, 2, 3)
	changed = c.newEndpoints(endpoints)
	if !changed {
		t.Errorf("c.newEndpoints want true got %v", changed)
	}
	changed = c.newEndpoints(endpoints)
	if changed {
		t.Errorf("c.newEndpoints want false got %v", changed)
	}
	endpoints = fakeEndpoints(4, 5, 6)
	changed = c.newEndpoints(endpoints)
	if !changed {
		t.Errorf("c.newEndpoints want true got %v", changed)
	}
}

func fakeEndpoints(ports ...uint16) (ret []tailcfg.Endpoint) {
	for _, port := range ports {
		ret = append(ret, tailcfg.Endpoint{
			Addr: netip.AddrPortFrom(netip.Addr{}, port),
		})
	}
	return
}

func TestTsmpPing(t *testing.T) {
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni
	bus := eventbustest.NewBus(t)

	k := key.NewMachine()
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	opts := Options{
		ServerURL: "https://example.com",
		Hostinfo:  hi,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		Dialer: dialer,
		Bus:    bus,
	}

	c, err := NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}

	pingRes := &tailcfg.PingResponse{
		Type:     "TSMP",
		IP:       "123.456.7890",
		Err:      "",
		NodeName: "testnode",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body := new(ipnstate.PingResult)
		if err := json.NewDecoder(r.Body).Decode(body); err != nil {
			t.Fatal(err)
		}
		if pingRes.IP != body.IP {
			t.Fatalf("PingResult did not have the correct IP : got %v, expected : %v", body.IP, pingRes.IP)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	now := time.Now()

	pr := &tailcfg.PingRequest{
		URL: ts.URL,
	}

	err = postPingResult(now, t.Logf, c.httpc, pr, pingRes)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHandleDebugMessageDisableLogTail(t *testing.T) {
	// This test mutates package-level logtail state and must not run in
	// parallel with tests that depend on logtail being enabled.
	t.Cleanup(func() { logtail.Enable() })

	t.Run("callback_fires", func(t *testing.T) {
		logtail.Enable() // reset from any prior subtest

		var called atomic.Bool
		c := &Direct{
			logf:             t.Logf,
			onDisableLogTail: func() { called.Store(true) },
		}

		err := c.handleDebugMessage(context.Background(), &tailcfg.Debug{DisableLogTail: true})
		if err != nil {
			t.Fatalf("handleDebugMessage: %v", err)
		}

		if !called.Load() {
			t.Error("onDisableLogTail callback was not called")
		}
	})

	t.Run("envknob_not_set", func(t *testing.T) {
		logtail.Enable() // reset
		t.Setenv("TS_NO_LOGS_NO_SUPPORT", "")

		c := &Direct{
			logf:             t.Logf,
			onDisableLogTail: func() {},
		}

		err := c.handleDebugMessage(context.Background(), &tailcfg.Debug{DisableLogTail: true})
		if err != nil {
			t.Fatalf("handleDebugMessage: %v", err)
		}

		if envknob.NoLogsNoSupport() {
			t.Error("envknob.NoLogsNoSupport() should be false; handleDebugMessage must not call envknob.SetNoLogsNoSupport()")
		}
	})

	t.Run("nil_callback_no_panic", func(t *testing.T) {
		logtail.Enable() // reset

		c := &Direct{
			logf:             t.Logf,
			onDisableLogTail: nil,
		}

		err := c.handleDebugMessage(context.Background(), &tailcfg.Debug{DisableLogTail: true})
		if err != nil {
			t.Fatalf("handleDebugMessage: %v", err)
		}
		// No panic means success.
	})

	t.Run("false_does_not_fire", func(t *testing.T) {
		logtail.Enable() // reset

		var called atomic.Bool
		c := &Direct{
			logf:             t.Logf,
			onDisableLogTail: func() { called.Store(true) },
		}

		err := c.handleDebugMessage(context.Background(), &tailcfg.Debug{DisableLogTail: false})
		if err != nil {
			t.Fatalf("handleDebugMessage: %v", err)
		}

		if called.Load() {
			t.Error("onDisableLogTail should not be called when DisableLogTail is false")
		}
	})
}
