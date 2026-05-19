// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet2

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
)

// TestSmoke is a compile-smoke test for the public API surface of
// tsnet2. It verifies that the Server type has the fields and methods
// PLAN.tsnet2.md commits to (v1) and that they have the expected
// signatures. Every method is exercised to confirm it does not panic
// for callers who only need to type-check against the surface; methods
// that need a running daemon return errNotImplemented at runtime, which
// is fine for the skeleton phase.
func TestSmoke(t *testing.T) {
	s := &Server{}

	// --- field presence and types ---
	st := reflect.TypeOf(*s)

	wantFields := map[string]reflect.Kind{
		"Dir":            reflect.String,
		"Hostname":       reflect.String,
		"Ephemeral":      reflect.Bool,
		"AuthKey":        reflect.String,
		"ControlURL":     reflect.String,
		"Port":           reflect.Uint16,
		"SocketPath":     reflect.String,
		"TrafficLogPath": reflect.String,
	}
	for name, kind := range wantFields {
		f, ok := st.FieldByName(name)
		if !ok {
			t.Errorf("Server.%s: missing", name)
			continue
		}
		if f.Type.Kind() != kind {
			t.Errorf("Server.%s: kind %v, want %v", name, f.Type.Kind(), kind)
		}
	}

	// Slice/interface fields are checked by name only — they are not
	// scalar Kinds so the loop above can't validate them.
	for _, name := range []string{
		"Store",         // ipn.StateStore (interface)
		"UserLogf",      // logger.Logf (func)
		"Logf",          // logger.Logf (func)
		"Tun",           // tun.Device (interface)
		"AdvertiseTags", // []string
	} {
		if _, ok := st.FieldByName(name); !ok {
			t.Errorf("Server.%s: missing", name)
		}
	}

	// --- method presence and signatures ---
	// We use reflect rather than just calling methods so that this test
	// remains a compile-time signature check even after the bodies are
	// filled in.
	checkMethod := func(name string, wantIn, wantOut []reflect.Type) {
		t.Helper()
		m, ok := reflect.TypeOf(s).MethodByName(name)
		if !ok {
			t.Errorf("Server.%s: method missing", name)
			return
		}
		// m.Type.In(0) is the receiver, so skip it.
		var gotIn []reflect.Type
		for i := 1; i < m.Type.NumIn(); i++ {
			gotIn = append(gotIn, m.Type.In(i))
		}
		if !reflect.DeepEqual(gotIn, wantIn) {
			t.Errorf("Server.%s: inputs = %v, want %v", name, gotIn, wantIn)
		}
		var gotOut []reflect.Type
		for i := 0; i < m.Type.NumOut(); i++ {
			gotOut = append(gotOut, m.Type.Out(i))
		}
		if !reflect.DeepEqual(gotOut, wantOut) {
			t.Errorf("Server.%s: outputs = %v, want %v", name, gotOut, wantOut)
		}
	}

	ctxT := reflect.TypeOf((*context.Context)(nil)).Elem()
	netConnT := reflect.TypeOf((*net.Conn)(nil)).Elem()
	netListenerT := reflect.TypeOf((*net.Listener)(nil)).Elem()
	errT := reflect.TypeOf((*error)(nil)).Elem()
	stringT := reflect.TypeOf("")
	stringSliceT := reflect.TypeOf([]string(nil))
	addrT := reflect.TypeOf(netip.Addr{})
	statusT := reflect.TypeOf((*ipnstate.Status)(nil))
	localClientT := reflect.TypeOf((*local.Client)(nil))
	fallbackT := reflect.TypeOf(FallbackTCPHandler(nil))
	funcVoidT := reflect.TypeOf(func() {})

	checkMethod("Start", nil, []reflect.Type{errT})
	checkMethod("Up", []reflect.Type{ctxT}, []reflect.Type{statusT, errT})
	checkMethod("Close", nil, []reflect.Type{errT})
	checkMethod("Listen", []reflect.Type{stringT, stringT}, []reflect.Type{netListenerT, errT})
	checkMethod("ListenTLS", []reflect.Type{stringT, stringT}, []reflect.Type{netListenerT, errT})
	checkMethod("Dial", []reflect.Type{ctxT, stringT, stringT}, []reflect.Type{netConnT, errT})
	checkMethod("TailscaleIPs", nil, []reflect.Type{addrT, addrT})
	checkMethod("GetRootPath", nil, []reflect.Type{stringT})
	checkMethod("LocalClient", nil, []reflect.Type{localClientT, errT})
	checkMethod("RegisterFallbackTCPHandler", []reflect.Type{fallbackT}, []reflect.Type{funcVoidT})
	checkMethod("CertDomains", nil, []reflect.Type{stringSliceT})

	// --- behavioural smoke checks (no daemon) ---
	if err := s.Start(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Start() = %v, want errors.Is ErrNotImplemented", err)
	}
	if _, err := s.LocalClient(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("LocalClient() err = %v, want errors.Is ErrNotImplemented", err)
	}
	if _, err := s.Listen("tcp", ":0"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Listen() err = %v, want errors.Is ErrNotImplemented", err)
	}
	if _, err := s.Dial(t.Context(), "tcp", "100.64.0.1:1"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Dial() err = %v, want errors.Is ErrNotImplemented", err)
	}
	if got := s.GetRootPath(); got != "" {
		t.Errorf("GetRootPath() on empty server = %q, want \"\"", got)
	}
	if ip4, ip6 := s.TailscaleIPs(); ip4.IsValid() || ip6.IsValid() {
		t.Errorf("TailscaleIPs() on un-started server = (%v, %v), want both invalid", ip4, ip6)
	}
	if got := s.CertDomains(); got != nil {
		t.Errorf("CertDomains() on un-started server = %v, want nil", got)
	}
	// Deregister callback should be safe to call.
	dereg := s.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		return nil, false
	})
	dereg()
}
