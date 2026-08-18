// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube_test

import (
	"fmt"
	"net/netip"
	"testing"

	kube "tailscale.com/k8s-operator"
	"tailscale.com/tailcfg"
)

// TestTailscaledConfigFileNameRoundTrip pins the config file naming contract. The operator writes these names into a
// Secret and containerboot parses them back out, so the two functions must stay inverses of each other and the format
// must not drift.
func TestTailscaledConfigFileNameRoundTrip(t *testing.T) {
	t.Parallel()

	for _, capVer := range []tailcfg.CapabilityVersion{0, 1, 95, 106, 32767} {
		name := kube.TailscaledConfigFileName(capVer)
		if want := fmt.Sprintf("cap-%d.hujson", capVer); name != want {
			t.Errorf("TailscaledConfigFileName(%d) = %q, want %q", capVer, name, want)
		}

		got, err := kube.CapVerFromFileName(name)
		if err != nil {
			t.Errorf("CapVerFromFileName(%q): %v", name, err)
			continue
		}
		if got != capVer {
			t.Errorf("round trip of %d gave %d", capVer, got)
		}
	}

	// Pre-config-file proxies wrote a file simply named "tailscaled"; it maps to capability version 0.
	got, err := kube.CapVerFromFileName("tailscaled")
	if err != nil {
		t.Errorf(`CapVerFromFileName("tailscaled"): %v`, err)
	}
	if got != 0 {
		t.Errorf(`CapVerFromFileName("tailscaled") = %d, want 0`, got)
	}

	if _, err := kube.CapVerFromFileName("not-a-config-file"); err == nil {
		t.Error("CapVerFromFileName(\"not-a-config-file\") succeeded, want error")
	}
}

func TestResolveViaDomain(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		name string
		want string // empty means expect ok == false
	}{
		"bare":                 {name: "10-1-2-3-via-7", want: "fd7a:115c:a1e0:b1a:0:7:a01:203"},
		"trailing-dot":         {name: "10-1-2-3-via-7.", want: "fd7a:115c:a1e0:b1a:0:7:a01:203"},
		"ts.net-domain":        {name: "10-1-2-3-via-7.foo.ts.net.", want: "fd7a:115c:a1e0:b1a:0:7:a01:203"},
		"tailscale.net-domain": {name: "10-1-2-3-via-7.foo.tailscale.net", want: "fd7a:115c:a1e0:b1a:0:7:a01:203"},
		"hex-site-id":          {name: "10-1-2-3-via-0x7", want: "fd7a:115c:a1e0:b1a:0:7:a01:203"},
		"too-short":            {name: "0-0-0-via"},
		"no-via":               {name: "10-1-2-3-7.foo.ts.net"},
		"foreign-domain":       {name: "10-1-2-3-via-7.example.com"},
		"not-an-ipv4":          {name: "10-1-2-via-7"},
		"site-id-not-a-number": {name: "10-1-2-3-via-abc"},
	}

	for tn, tc := range tests {
		t.Run(tn, func(t *testing.T) {
			t.Parallel()
			got, ok := kube.ResolveViaDomain(tc.name)
			if tc.want == "" {
				if ok {
					t.Fatalf("ResolveViaDomain(%q) = %v, true; want ok == false", tc.name, got)
				}
				return
			}
			if !ok {
				t.Fatalf("ResolveViaDomain(%q) returned ok == false, want %s", tc.name, tc.want)
			}
			if got != netip.MustParseAddr(tc.want) {
				t.Errorf("ResolveViaDomain(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
