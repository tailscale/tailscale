// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstat

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetListeners(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	wantModule := filepath.Base(exe)

	ln4, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln4.Close()
	// Connect to it too, so there are ESTABLISHED rows to leave out.
	c, err := net.Dial("tcp", ln4.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Listener address => seen.
	want := map[netip.AddrPort]bool{ln4.Addr().(*net.TCPAddr).AddrPort(): false}
	if ln6, err := net.Listen("tcp", "[::1]:0"); err == nil {
		defer ln6.Close()
		want[ln6.Addr().(*net.TCPAddr).AddrPort()] = false
		if c6, err := net.Dial("tcp", ln6.Addr().String()); err == nil {
			defer c6.Close()
		} else {
			t.Logf("no IPv6 connection: %v", err)
		}
	} else {
		t.Logf("no IPv6 listener: %v", err)
	}

	tab, err := GetListeners()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range tab.Entries {
		if e.State != "LISTEN" {
			t.Errorf("got non-listener entry: %+v", e)
		}
		if _, ok := want[e.Local]; !ok {
			continue
		}
		want[e.Local] = true
		if e.Pid != os.Getpid() {
			t.Errorf("%v: pid = %d; want %d", e.Local, e.Pid, os.Getpid())
		}
		mod, err := e.OSMetadata.GetModule()
		if err != nil || !strings.EqualFold(mod, wantModule) {
			t.Errorf("%v: GetModule = %q, %v; want %q", e.Local, mod, err, wantModule)
		}
	}
	for ap, seen := range want {
		if !seen {
			t.Errorf("listener %v not returned", ap)
		}
	}
}
