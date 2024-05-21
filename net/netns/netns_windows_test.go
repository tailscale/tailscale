// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/tsconst"
)

func TestGetInterfaceIndex(t *testing.T) {
	oldVal := bindToInterfaceByRoute.Load()
	t.Cleanup(func() { bindToInterfaceByRoute.Store(oldVal) })
	bindToInterfaceByRoute.Store(true)

	defIfaceIdxV4, err := defaultInterfaceIndex(windows.AF_INET)
	if err != nil {
		t.Fatalf("defaultInterfaceIndex(AF_INET) failed: %v", err)
	}

	tests := []struct {
		name string
		addr string
		err  string
	}{
		{
			name: "IP_and_port",
			addr: "8.8.8.8:53",
		},
		{
			name: "bare_ip",
			addr: "8.8.8.8",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := parseAddress(tc.addr)
			if err != nil {
				t.Fatal(err)
			}

			idx, err := getInterfaceIndex(t.Logf, addr, defIfaceIdxV4)
			if err != nil {
				if tc.err == "" {
					t.Fatalf("got unexpected error: %v", err)
				}
				if errstr := err.Error(); errstr != tc.err {
					t.Errorf("expected error %q, got %q", errstr, tc.err)
				}
			} else {
				t.Logf("getInterfaceIndex(%q) = %d", tc.addr, idx)
				if tc.err != "" {
					t.Fatalf("wanted error %q", tc.err)
				}
			}
		})
	}

	t.Run("NoTailscale", func(t *testing.T) {
		tsIdx, ok, err := tailscaleInterfaceIndex()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Skip("no tailscale interface on this machine")
		}

		defaultIdx, err := defaultInterfaceIndex(windows.AF_INET)
		if err != nil {
			t.Fatalf("defaultInterfaceIndex(AF_INET) failed: %v", err)
		}

		addr, err := parseAddress("100.100.100.100:53")
		if err != nil {
			t.Fatal(err)
		}

		idx, err := getInterfaceIndex(t.Logf, addr, defaultIdx)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("tailscaleIdx=%d defaultIdx=%d idx=%d", tsIdx, defaultIdx, idx)

		if idx == tsIdx {
			t.Fatalf("got idx=%d; wanted not Tailscale interface", idx)
		} else if idx != defaultIdx {
			t.Fatalf("got idx=%d, want %d", idx, defaultIdx)
		}
	})
}

func tailscaleInterfaceIndex() (idx uint32, found bool, err error) {
	ifs, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return idx, false, err
	}

	for _, iface := range ifs {
		if iface.IfType != winipcfg.IfTypePropVirtual {
			continue
		}
		if strings.Contains(iface.Description(), tsconst.WintunInterfaceDesc) {
			return iface.IfIndex, true, nil
		}
	}
	return idx, false, nil
}
