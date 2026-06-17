// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/mock"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// mustParsePorts parses ProtoPortRanges or fails the test.
func mustParsePorts(t *testing.T, ports ...string) []tailcfg.ProtoPortRange {
	t.Helper()
	ppr, err := tailcfg.ParseProtoPortRanges(ports)
	if err != nil {
		t.Fatalf("ParseProtoPortRanges(%q): %v", ports, err)
	}
	return ppr
}

// statusWithSuffix returns a Status carrying the given MagicDNS suffix.
func statusWithSuffix(suffix string) *ipnstate.Status {
	return &ipnstate.Status{
		CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: suffix},
	}
}

// runList runs the list command with the given client, capturing stdout.
func runList(t *testing.T, lc localClientI, jsonOut bool) string {
	t.Helper()
	var buf strings.Builder
	tstest.Replace[io.Writer](t, &Stdout, &buf)
	tstest.Replace(t, &serviceListArgs.json, jsonOut)

	ctx := withLocalClient(context.Background(), lc)
	if err := runServiceList(ctx, nil); err != nil {
		t.Fatalf("runServiceList: %v", err)
	}
	return buf.String()
}

func TestServiceListTable(t *testing.T) {
	services := map[tailcfg.ServiceName]tailcfg.ServiceDetails{
		// Intentionally out of order to exercise sorting.
		"svc:web": {
			Name:        "svc:web",
			DisplayName: "Web",
			Addrs:       []netip.Addr{netip.MustParseAddr("100.80.0.2"), netip.MustParseAddr("fd7a::2")},
			Ports:       mustParsePorts(t, "tcp:443"),
		},
		"svc:db": {
			Name:  "svc:db",
			Addrs: []netip.Addr{netip.MustParseAddr("100.80.0.1")},
			Ports: mustParsePorts(t, "tcp:5432"),
		},
	}

	lc := newMockLocalClient(t)
	lc.EXPECT().GetServices(mock.Anything).Return(services, nil).Once()
	lc.EXPECT().Status(mock.Anything).Return(statusWithSuffix("ts-tailnet.ts.net."), nil).Once()

	out := runList(t, lc, false)

	// Header.
	for _, h := range []string{"NAME", "DISPLAY NAME", "DNS NAME", "IP", "ENDPOINTS"} {
		if !strings.Contains(out, h) {
			t.Errorf("output missing header %q\n%s", h, out)
		}
	}

	// Services are sorted by name, so svc:db precedes svc:web.
	if i, j := strings.Index(out, "svc:db"), strings.Index(out, "svc:web"); i < 0 || j < 0 || i > j {
		t.Errorf("services not sorted by name (db=%d, web=%d)\n%s", i, j, out)
	}

	// DNS name is <bare name>.<suffix> with the suffix's dots trimmed.
	if !strings.Contains(out, "web.ts-tailnet.ts.net") {
		t.Errorf("output missing svc:web DNS name\n%s", out)
	}

	// IP is the first address only; the v6 address is not shown.
	if !strings.Contains(out, "100.80.0.2") {
		t.Errorf("output missing svc:web first IP\n%s", out)
	}
	if strings.Contains(out, "fd7a::2") {
		t.Errorf("output should show only the first IP, not the v6 address\n%s", out)
	}

	// Endpoints come from Ports.
	if !strings.Contains(out, "tcp:443") || !strings.Contains(out, "tcp:5432") {
		t.Errorf("output missing endpoints\n%s", out)
	}

	// svc:db has no DisplayName, so its cell renders as "-".
	if !strings.Contains(out, "-") {
		t.Errorf("expected %q for empty DisplayName\n%s", "-", out)
	}
}

// TestServiceListIPv6Only verifies that when a Service only has a v6 address
// (e.g. a tailnet with IPv4 disabled), the v6 address is shown as the IP.
func TestServiceListIPv6Only(t *testing.T) {
	services := map[tailcfg.ServiceName]tailcfg.ServiceDetails{
		"svc:v6": {
			Name:  "svc:v6",
			Addrs: []netip.Addr{netip.MustParseAddr("fd7a::9")},
			Ports: mustParsePorts(t, "tcp:80"),
		},
	}

	lc := newMockLocalClient(t)
	lc.EXPECT().GetServices(mock.Anything).Return(services, nil).Once()
	lc.EXPECT().Status(mock.Anything).Return(statusWithSuffix("ts-tailnet.ts.net"), nil).Once()

	out := runList(t, lc, false)
	if !strings.Contains(out, "fd7a::9") {
		t.Errorf("expected v6 address as IP\n%s", out)
	}
}

func TestServiceListJSON(t *testing.T) {
	services := map[tailcfg.ServiceName]tailcfg.ServiceDetails{
		// Intentionally out of order to exercise sorting, and svc:web has both
		// v4 and v6 addresses to confirm the JSON carries the full address
		// list (unlike the table, which shows only the first).
		"svc:web": {
			Name:        "svc:web",
			DisplayName: "Web",
			Addrs:       []netip.Addr{netip.MustParseAddr("100.80.0.2"), netip.MustParseAddr("fd7a::2")},
			Ports:       mustParsePorts(t, "tcp:443", "tcp:8443"),
		},
		"svc:db": {
			Name:  "svc:db",
			Addrs: []netip.Addr{netip.MustParseAddr("100.80.0.1")},
			Ports: mustParsePorts(t, "tcp:5432"),
		},
	}

	lc := newMockLocalClient(t)
	lc.EXPECT().GetServices(mock.Anything).Return(services, nil).Once()
	lc.EXPECT().Status(mock.Anything).Return(statusWithSuffix("ts-tailnet.ts.net"), nil).Once()

	out := runList(t, lc, true)

	var got []serviceListEntry
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal JSON output: %v\n%s", err, out)
	}

	// Entries are sorted by name and each embedded ServiceDetails (including
	// the full Addrs and Ports) round-trips, decorated with the DNS name.
	want := []serviceListEntry{
		{
			ServiceDetails: tailcfg.ServiceDetails{
				Name:  "svc:db",
				Addrs: []netip.Addr{netip.MustParseAddr("100.80.0.1")},
				Ports: mustParsePorts(t, "tcp:5432"),
			},
			DNSName: "db.ts-tailnet.ts.net",
		},
		{
			ServiceDetails: tailcfg.ServiceDetails{
				Name:        "svc:web",
				DisplayName: "Web",
				Addrs:       []netip.Addr{netip.MustParseAddr("100.80.0.2"), netip.MustParseAddr("fd7a::2")},
				Ports:       mustParsePorts(t, "tcp:443", "tcp:8443"),
			},
			DNSName: "web.ts-tailnet.ts.net",
		},
	}
	// netip.Addr has unexported fields but is comparable, so compare it by ==.
	if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("JSON output mismatch (-want +got):\n%s\nraw:\n%s", diff, out)
	}
}

func TestServiceListEmpty(t *testing.T) {
	lc := newMockLocalClient(t)
	lc.EXPECT().GetServices(mock.Anything).Return(map[tailcfg.ServiceName]tailcfg.ServiceDetails{}, nil).Once()
	lc.EXPECT().Status(mock.Anything).Return(statusWithSuffix("ts-tailnet.ts.net"), nil).Once()

	out := runList(t, lc, false)
	if !strings.Contains(out, "No Tailscale Services are available") {
		t.Errorf("expected empty message, got\n%s", out)
	}
}

func TestServiceListGetServicesError(t *testing.T) {
	wantErr := errors.New("boom")
	lc := newMockLocalClient(t)
	lc.EXPECT().GetServices(mock.Anything).Return(nil, wantErr).Once()

	ctx := withLocalClient(context.Background(), lc)
	err := runServiceList(ctx, nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

func TestServiceListRejectsArgs(t *testing.T) {
	// The args check happens before any LocalAPI call, so no expectations.
	ctx := withLocalClient(context.Background(), newMockLocalClient(t))
	if err := runServiceList(ctx, []string{"unexpected"}); err == nil {
		t.Error("expected error for extra args, got nil")
	}
}

func TestServiceDNSName(t *testing.T) {
	tests := []struct {
		name   tailcfg.ServiceName
		suffix string
		want   string
	}{
		{"svc:web", "ts-tailnet.ts.net", "web.ts-tailnet.ts.net"},
		{"svc:web", "ts-tailnet.ts.net.", "web.ts-tailnet.ts.net"}, // trailing dot trimmed
		{"svc:web", "", ""},                        // no suffix
		{"not-a-service", "ts-tailnet.ts.net", ""}, // invalid name (no svc: prefix)
	}
	for _, tt := range tests {
		if got := serviceDNSName(tt.name, tt.suffix); got != tt.want {
			t.Errorf("serviceDNSName(%q, %q) = %q, want %q", tt.name, tt.suffix, got, tt.want)
		}
	}
}

// TestLocalClientFromContextDefault verifies that without injection the
// real localClient is returned.
func TestLocalClientFromContextDefault(t *testing.T) {
	if got := localClientFromContext(context.Background()); got != &localClient {
		t.Errorf("localClientFromContext default = %v, want &localClient", got)
	}
}

// TestServiceCmdEnvKnob verifies the service command is only registered when
// the TS_DEBUG_ENABLE_SERVICE_COMMANDS knob is set. The knob is registered via
// envknob.RegisterBool, whose value is cached at init, so it must be mutated
// through envknob.Setenv (which updates the registry) rather than t.Setenv.
func TestServiceCmdEnvKnob(t *testing.T) {
	t.Cleanup(func() { envknob.Setenv("TS_DEBUG_ENABLE_SERVICE_COMMANDS", "") })

	envknob.Setenv("TS_DEBUG_ENABLE_SERVICE_COMMANDS", "")
	if cmd := serviceCmd(); cmd != nil {
		t.Errorf("serviceCmd() = %v, want nil when knob unset", cmd)
	}

	envknob.Setenv("TS_DEBUG_ENABLE_SERVICE_COMMANDS", "1")
	if cmd := serviceCmd(); cmd == nil {
		t.Error("serviceCmd() = nil, want non-nil when knob set")
	}
}
