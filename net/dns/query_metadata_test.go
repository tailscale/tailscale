// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"tailscale.com/net/dns/resolver"
	"tailscale.com/util/dnsname"
)

func TestQueryWithMetadataMapper(t *testing.T) {
	m, _, _ := newEmptyBaseConfigManager(t)
	if err := m.resolver.SetConfig(resolver.Config{
		LocalDomains: []dnsname.FQDN{"tailnet.ts.net."},
	}); err != nil {
		t.Fatal(err)
	}
	var original *resolver.Response
	mapped := []byte("mapped response")
	m.SetQueryResponseMapper(func(res *resolver.Response) []byte {
		original = res
		if !res.IsLocal {
			t.Error("mapper did not receive local response metadata")
		}
		return mapped
	})
	query := buildTestDNSQuery(t, "missing.tailnet.ts.net.")
	from := netip.MustParseAddrPort("127.0.0.1:12345")
	res, err := m.QueryWithMetadata(t.Context(), query, "udp", from)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsLocal || !bytes.Equal(res.Bs, mapped) {
		t.Errorf("mapped response = %+v, want local response with mapped bytes", res)
	}
	if original == nil || bytes.Equal(original.Bs, mapped) {
		t.Error("mapper's input response bytes were overwritten")
	}
	// The existing Query method must still apply the same mapper.
	out, err := m.Query(t.Context(), query, "udp", from)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, mapped) {
		t.Errorf("Query returned %q, want %q", out, mapped)
	}
}

func TestQueryWithMetadataErrors(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(*Manager)
		want  error
	}{
		{"closed_manager", func(m *Manager) { m.ctxCancel() }, net.ErrClosed},
		{"full_queue", func(m *Manager) { atomic.StoreInt32(&m.activeQueriesAtomic, maxActiveQueries) }, errFullQueue},
		{"closed_resolver", func(m *Manager) { m.resolver.Close() }, net.ErrClosed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, _, _ := newEmptyBaseConfigManager(t)
			tt.setup(m)
			query := buildTestDNSQuery(t, "example.com.")
			from := netip.MustParseAddrPort("127.0.0.1:12345")
			if res, err := m.QueryWithMetadata(t.Context(), query, "udp", from); res != nil || !errors.Is(err, tt.want) {
				t.Errorf("QueryWithMetadata = %v, %v; want nil, %v", res, err, tt.want)
			}
			if out, err := m.Query(t.Context(), query, "udp", from); out != nil || !errors.Is(err, tt.want) {
				t.Errorf("Query = %v, %v; want nil, %v", out, err, tt.want)
			}
		})
	}
}
