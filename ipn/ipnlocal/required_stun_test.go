// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/ipn/conffile"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/stun"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
)

func TestNewLocalBackendRequiredSTUNServersError(t *testing.T) {
	tstest.ResourceCheck(t)
	sys := tsd.NewSystem()
	t.Cleanup(sys.Bus.Get().Close)
	e, err := wgengine.NewFakeUserspaceEngine(t.Logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.Close()
		sys.Dialer.Get().Close()
	})
	sys.Set(e)
	sys.StateStore.Set(new(mem.Store))
	before := sys.Bus.Get().Debugger().Clients()
	sys.InitialConfig = &conffile.Config{Parsed: ipn.ConfigVAlpha{
		Version:             "alpha0",
		RequiredSTUNServers: []string{"missing-port"},
	}}
	b, err := NewLocalBackend(t.Logf, logid.PublicID{}, sys, 0)
	if b != nil {
		t.Cleanup(b.Shutdown)
	}
	if b != nil || err == nil || !strings.Contains(err.Error(), "requiredSTUNServers[0]") {
		t.Fatalf("NewLocalBackend() = %v, %v, want an indexed STUN target error", b, err)
	}
	for _, c := range sys.Bus.Get().Debugger().Clients() {
		if slices.Contains(before, c) {
			continue
		}
		select {
		case <-c.Done():
		default:
			t.Errorf("failed config left an active event bus client: %s", c.Name())
		}
	}
}

func TestLocalBackendInitPrefsFromConfigRequiredSTUNServers(t *testing.T) {
	tstest.ResourceCheck(t)
	for _, tt := range []struct {
		name    string
		static  []netip.AddrPort
		invalid bool
	}{
		{name: "InvalidTarget", invalid: true},
		{name: "WithoutStaticEndpoints"},
		{name: "EmptyStaticEndpoints", static: []netip.AddrPort{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestLocalBackend(t)
			t.Cleanup(func() {
				b.Shutdown()
				b.Dialer().Close()
			})
			prefs := b.Prefs().AsStruct()
			conf := &conffile.Config{Parsed: ipn.ConfigVAlpha{
				Hostname:            new("changed-host"),
				RequiredSTUNServers: []string{"192.0.2.1:3478"},
				StaticEndpoints:     tt.static,
			}}
			if tt.invalid {
				conf.Parsed.RequiredSTUNServers = append(conf.Parsed.RequiredSTUNServers, "missing-port")
			}
			err := b.initPrefsFromConfig(conf)
			if tt.invalid {
				if err == nil || !strings.Contains(err.Error(), "requiredSTUNServers[1]") {
					t.Fatalf("initPrefsFromConfig() error = %v, want an indexed STUN target error", err)
				}
				if b.conf != nil || !reflect.DeepEqual(b.Prefs().AsStruct(), prefs) {
					t.Error("invalid initial config changed config or preferences")
				}
			} else if err != nil || b.conf != conf {
				t.Fatalf("initPrefsFromConfig() error = %v, active config = %p, want nil, %p", err, b.conf, conf)
			}
		})
	}
}

func TestLocalBackendReloadConfigRequiredSTUNServers(t *testing.T) {
	if !buildfeatures.HasNATTraversal || !buildfeatures.HasUDPTransport {
		t.Skip("requires NAT traversal and UDP transport")
	}
	tstest.ResourceCheck(t)
	type server struct {
		addr        string
		mapping     netip.AddrPort
		source      syncs.MutexValue[netip.AddrPort]
		beforeReply syncs.MutexValue[func()]
	}
	serve := func(mapping string) *server {
		t.Helper()
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		s := &server{addr: pc.LocalAddr().String(), mapping: netip.MustParseAddrPort(mapping)}
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 1500)
			for {
				n, src, err := pc.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				tx, err := stun.ParseBindingRequest(buf[:n])
				if err != nil {
					t.Error(err)
					return
				}
				s.source.Store(src)
				if f := s.beforeReply.Load(); f != nil {
					f()
				}
				if _, err := pc.WriteToUDPAddrPort(stun.Response(tx, s.mapping), src); err != nil {
					t.Logf("STUN response: %v", err)
				}
			}
		}()
		t.Cleanup(func() {
			pc.Close()
			<-done
		})
		return s
	}
	first := serve("198.51.100.20:45678")
	second := serve("198.51.100.30:56789")
	static := netip.MustParseAddrPort("198.51.100.40:41641")
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig := func(t *testing.T, hostname string, targets any, omit, invalidPrefs bool) {
		t.Helper()
		data := map[string]any{
			"version":         "alpha0",
			"locked":          true,
			"enabled":         false,
			"hostname":        hostname,
			"staticEndpoints": []string{static.String()},
		}
		if !omit {
			data["requiredSTUNServers"] = targets
		}
		if invalidPrefs {
			data["netfilterMode"] = "invalid"
		}
		encoded, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, "initial-host", []string{first.addr, second.addr}, false, false)
	initial, err := conffile.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	sys := tsd.NewSystem()
	t.Cleanup(sys.Bus.Get().Close)
	sys.InitialConfig = initial
	b := newTestLocalBackendWithSys(t, sys)
	t.Cleanup(func() {
		b.Shutdown()
		b.Dialer().Close()
	})
	ms := b.MagicConn()
	ordinary, cleanup := stuntest.Serve(t)
	t.Cleanup(cleanup)
	ms.SetDERPMap(stuntest.DERPMapOf(ordinary.String()))
	checkReport := func(t *testing.T, want []netip.AddrPort) {
		t.Helper()
		previous := ms.GetLastNetcheckReport(t.Context())
		ms.ReSTUN("required-stun-config-test")
		if err := tstest.WaitFor(5*time.Second, func() error {
			r := ms.GetLastNetcheckReport(t.Context())
			if r == nil || r == previous {
				return fmt.Errorf("waiting for a new report")
			}
			got := slices.Clone(r.RequiredSTUNEndpoints)
			slices.SortFunc(got, netip.AddrPort.Compare)
			if !slices.Equal(got, want) {
				return fmt.Errorf("required mappings = %v, want %v", got, want)
			}
			v4, _ := r.GetGlobalAddrs()
			if !slices.Contains(v4, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ms.LocalPort())) {
				return fmt.Errorf("ordinary STUN mapping is missing")
			}
			for _, s := range []*server{first, second} {
				if slices.Contains(want, s.mapping) && s.source.Load().Port() != ms.LocalPort() {
					return fmt.Errorf("STUN source port differs from live magicsock port")
				}
			}
			b.mu.Lock()
			hasStatic := slices.Contains(b.endpoints, tailcfg.Endpoint{Addr: static, Type: tailcfg.EndpointExplicitConf})
			b.mu.Unlock()
			if !hasStatic {
				return fmt.Errorf("static endpoint is missing")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	checkReport(t, []netip.AddrPort{first.mapping, second.mapping})
	for _, tt := range []struct {
		name         string
		targets      any
		omit         bool
		invalidPrefs bool
		want         []netip.AddrPort
		wantErr      bool
	}{
		{name: "Replace", targets: []string{second.addr}, want: []netip.AddrPort{second.mapping}},
		{name: "Add", targets: []string{first.addr, second.addr}, want: []netip.AddrPort{first.mapping, second.mapping}},
		{name: "Unchanged", targets: []string{first.addr, second.addr}, want: []netip.AddrPort{first.mapping, second.mapping}},
		{name: "Reorder", targets: []string{second.addr, first.addr}, want: []netip.AddrPort{first.mapping, second.mapping}},
		{name: "Empty", targets: []string{}},
		{name: "Omitted", omit: true},
		{name: "Null"},
		{name: "Restore", targets: []string{first.addr}, want: []netip.AddrPort{first.mapping}},
		{name: "InvalidTarget", targets: []string{second.addr, "missing-port"}, want: []netip.AddrPort{first.mapping}, wantErr: true},
		{name: "InvalidType", targets: "not-a-list", want: []netip.AddrPort{first.mapping}, wantErr: true},
		{name: "InvalidPrefs", targets: []string{second.addr}, invalidPrefs: true, want: []netip.AddrPort{first.mapping}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b.mu.Lock()
			previous := b.conf
			b.mu.Unlock()
			prefs := b.Prefs().AsStruct()
			writeConfig(t, "host-"+strings.ToLower(tt.name), tt.targets, tt.omit, tt.invalidPrefs)
			ok, err := b.ReloadConfig()
			if tt.wantErr {
				if ok || err == nil {
					t.Fatalf("ReloadConfig() = %v, %v, want an error", ok, err)
				}
				b.mu.Lock()
				unchanged := b.conf == previous
				b.mu.Unlock()
				if !unchanged || !reflect.DeepEqual(b.Prefs().AsStruct(), prefs) {
					t.Error("rejected reload changed the active config or preferences")
				}
			} else if !ok || err != nil {
				t.Fatalf("ReloadConfig() = %v, %v, want true, nil", ok, err)
			} else if got := b.Prefs().Hostname(); got != "host-"+strings.ToLower(tt.name) {
				t.Errorf("hostname = %q, want the reloaded value", got)
			}
			checkReport(t, tt.want)
		})
	}

	t.Run("DuringProbe", func(t *testing.T) {
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		first.beforeReply.Store(func() {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		})
		defer first.beforeReply.Store(nil)
		previous := ms.GetLastNetcheckReport(t.Context())
		ms.ReSTUN("required-stun-inflight-config-test")
		select {
		case <-t.Context().Done():
			t.Fatal("test canceled")
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("probe did not reach the previous target")
		}
		writeConfig(t, "inflight-host", []string{second.addr}, false, false)
		if ok, err := b.ReloadConfig(); !ok || err != nil {
			t.Fatalf("ReloadConfig() = %v, %v, want true, nil", ok, err)
		}
		first.beforeReply.Store(nil)
		unblock()
		// Do not request another ReSTUN here. Reloading during an active
		// report must itself queue discovery using the new target list.
		if err := tstest.WaitFor(5*time.Second, func() error {
			r := ms.GetLastNetcheckReport(t.Context())
			if r == nil || r == previous || !slices.Equal(r.RequiredSTUNEndpoints, []netip.AddrPort{second.mapping}) {
				return fmt.Errorf("waiting for the reloaded target's report")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
