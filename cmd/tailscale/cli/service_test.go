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
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// fakeServiceLister is a test-only [serviceLister] injected via
// [withServiceLister] in place of the real localClient.
type fakeServiceLister struct {
	services    map[tailcfg.ServiceName]tailcfg.ServiceDetails
	servicesErr error
	status      *ipnstate.Status
	statusErr   error
}

func (f fakeServiceLister) GetServices(context.Context) (map[tailcfg.ServiceName]tailcfg.ServiceDetails, error) {
	return f.services, f.servicesErr
}

func (f fakeServiceLister) Status(context.Context) (*ipnstate.Status, error) {
	return f.status, f.statusErr
}

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

// runList runs the list command with the given lister, capturing stdout.
func runList(t *testing.T, lc serviceLister, jsonOut bool) string {
	t.Helper()
	var buf strings.Builder
	tstest.Replace[io.Writer](t, &Stdout, &buf)
	tstest.Replace(t, &serviceListArgs.json, jsonOut)

	ctx := withServiceLister(context.Background(), lc)
	if err := runServiceList(ctx, nil); err != nil {
		t.Fatalf("runServiceList: %v", err)
	}
	return buf.String()
}

func TestServiceListTable(t *testing.T) {
	lc := fakeServiceLister{
		status: statusWithSuffix("ts-tailnet.ts.net."),
		services: map[tailcfg.ServiceName]tailcfg.ServiceDetails{
			// Intentionally out of order to exercise sorting.
			"svc:web": {
				Name:        "svc:web",
				DisplayName: "Web",
				Addrs:       []netip.Addr{netip.MustParseAddr("100.80.0.2"), netip.MustParseAddr("fd7a::2")},
				Ports:       mustParsePorts(t, "tcp:443"),
				// Two actions render comma-separated.
				Actions: []tailcfg.ServiceAction{
					{Type: tailcfg.ServiceActionTypeHTTP, Port: 443},
					{Type: tailcfg.ServiceActionTypeSSH, Port: 22},
				},
			},
			"svc:db": {
				Name:  "svc:db",
				Addrs: []netip.Addr{netip.MustParseAddr("100.80.0.1")},
				Ports: mustParsePorts(t, "tcp:5432"),
				// No explicit actions, but tcp:5432 infers "postgresql".
			},
		},
	}

	out := runList(t, lc, false)

	for _, h := range []string{"IP", "HOSTNAME", "DISPLAY NAME", "ENDPOINTS", "TYPE"} {
		if !strings.Contains(out, h) {
			t.Errorf("output missing header %q\n%s", h, out)
		}
	}

	// Services are sorted by name, so svc:db's row precedes svc:web's.
	if i, j := strings.Index(out, "db.ts-tailnet.ts.net"), strings.Index(out, "web.ts-tailnet.ts.net"); i < 0 || j < 0 || i > j {
		t.Errorf("services not sorted by name (db=%d, web=%d)\n%s", i, j, out)
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

	// svc:web has two explicit actions, rendered comma-separated.
	if !strings.Contains(out, "http, ssh") {
		t.Errorf("output missing svc:web actions %q\n%s", "http, ssh", out)
	}

	// svc:db has no explicit actions but a well-known port (5432), so its
	// type is inferred.
	if !strings.Contains(out, "postgresql") {
		t.Errorf("output missing svc:db inferred type %q\n%s", "postgresql", out)
	}
}

func TestServiceActionTypes(t *testing.T) {
	tests := []struct {
		name string
		svc  tailcfg.ServiceDetails
		want string
	}{
		{
			"explicit one",
			tailcfg.ServiceDetails{Actions: []tailcfg.ServiceAction{{Type: tailcfg.ServiceActionTypeSSH}}},
			"ssh",
		},
		{
			"explicit two",
			tailcfg.ServiceDetails{Actions: []tailcfg.ServiceAction{
				{Type: tailcfg.ServiceActionTypeHTTP},
				{Type: tailcfg.ServiceActionTypeSSH},
			}},
			"http, ssh",
		},
		{
			// More than maxNamedTypes: name two, summarize the rest.
			"explicit three summarizes one other",
			tailcfg.ServiceDetails{Actions: []tailcfg.ServiceAction{
				{Type: tailcfg.ServiceActionTypeHTTP},
				{Type: tailcfg.ServiceActionTypeSSH},
				{Type: tailcfg.ServiceActionTypeMySQL},
			}},
			"http, ssh, 1 other",
		},
		{
			"explicit four summarizes multiple others",
			tailcfg.ServiceDetails{Actions: []tailcfg.ServiceAction{
				{Type: tailcfg.ServiceActionTypeHTTP},
				{Type: tailcfg.ServiceActionTypeSSH},
				{Type: tailcfg.ServiceActionTypeMySQL},
				{Type: tailcfg.ServiceActionTypeRDP},
			}},
			"http, ssh, 2 others",
		},
		{
			// Duplicate types collapse before counting.
			"explicit dedupes by type",
			tailcfg.ServiceDetails{Actions: []tailcfg.ServiceAction{
				{Type: tailcfg.ServiceActionTypeHTTP, Port: 80},
				{Type: tailcfg.ServiceActionTypeHTTP, Port: 443},
				{Type: tailcfg.ServiceActionTypeSSH, Port: 22},
			}},
			"http, ssh",
		},
		{
			// Explicit actions win; ports are not consulted for inference.
			"explicit beats inference",
			tailcfg.ServiceDetails{
				Actions: []tailcfg.ServiceAction{{Type: tailcfg.ServiceActionTypeTCP}},
				Ports:   mustParsePorts(t, "tcp:22"),
			},
			"tcp",
		},
		{
			"inferred from well-known port",
			tailcfg.ServiceDetails{Ports: mustParsePorts(t, "tcp:22")},
			"ssh",
		},
		{
			"inferred from multiple well-known ports",
			tailcfg.ServiceDetails{Ports: mustParsePorts(t, "tcp:80", "tcp:5432")},
			"http, postgresql",
		},
		{
			// 443 and 80 both map to http; it is only listed once.
			"inferred dedupes by action type",
			tailcfg.ServiceDetails{Ports: mustParsePorts(t, "tcp:80", "tcp:443")},
			"http",
		},
		{
			"no actions and unknown port",
			tailcfg.ServiceDetails{Ports: mustParsePorts(t, "tcp:12345")},
			"-",
		},
		{
			// A port range is not a single well-known port, so nothing is inferred.
			"port range is not inferred",
			tailcfg.ServiceDetails{Ports: mustParsePorts(t, "tcp:20-30")},
			"-",
		},
		{"nothing at all", tailcfg.ServiceDetails{}, "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serviceActionTypes(tt.svc); got != tt.want {
				t.Errorf("serviceActionTypes() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestServiceListIPv6Only verifies that when a Service only has a v6 address
// (e.g. a tailnet with IPv4 disabled), the v6 address is shown as the IP.
func TestServiceListIPv6Only(t *testing.T) {
	lc := fakeServiceLister{
		status: statusWithSuffix("ts-tailnet.ts.net"),
		services: map[tailcfg.ServiceName]tailcfg.ServiceDetails{
			"svc:v6": {
				Name:  "svc:v6",
				Addrs: []netip.Addr{netip.MustParseAddr("fd7a::9")},
				Ports: mustParsePorts(t, "tcp:80"),
			},
		},
	}

	out := runList(t, lc, false)
	if !strings.Contains(out, "fd7a::9") {
		t.Errorf("expected v6 address as IP\n%s", out)
	}
}

func TestServiceListJSON(t *testing.T) {
	lc := fakeServiceLister{
		status: statusWithSuffix("ts-tailnet.ts.net"),
		services: map[tailcfg.ServiceName]tailcfg.ServiceDetails{
			// Intentionally out of order to exercise sorting, and svc:web has
			// both v4 and v6 addresses to confirm the JSON carries the full
			// address list (unlike the table, which shows only the first).
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
		},
	}

	out := runList(t, lc, true)

	var got []serviceListEntry
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal JSON output: %v\n%s", err, out)
	}

	// Entries are sorted by name and each embedded ServiceDetails (including
	// the full Addrs and Ports) round-trips, decorated with the hostname.
	want := []serviceListEntry{
		{
			ServiceDetails: tailcfg.ServiceDetails{
				Name:  "svc:db",
				Addrs: []netip.Addr{netip.MustParseAddr("100.80.0.1")},
				Ports: mustParsePorts(t, "tcp:5432"),
			},
			Hostname: "db.ts-tailnet.ts.net",
		},
		{
			ServiceDetails: tailcfg.ServiceDetails{
				Name:        "svc:web",
				DisplayName: "Web",
				Addrs:       []netip.Addr{netip.MustParseAddr("100.80.0.2"), netip.MustParseAddr("fd7a::2")},
				Ports:       mustParsePorts(t, "tcp:443", "tcp:8443"),
			},
			Hostname: "web.ts-tailnet.ts.net",
		},
	}
	// netip.Addr has unexported fields but is comparable, so compare it by ==.
	if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("JSON output mismatch (-want +got):\n%s\nraw:\n%s", diff, out)
	}
}

func TestServiceListEmpty(t *testing.T) {
	lc := fakeServiceLister{
		status:   statusWithSuffix("ts-tailnet.ts.net"),
		services: map[tailcfg.ServiceName]tailcfg.ServiceDetails{},
	}
	out := runList(t, lc, false)
	if !strings.Contains(out, "No Tailscale Services are available") {
		t.Errorf("expected empty message, got\n%s", out)
	}
}

func TestServiceListGetServicesError(t *testing.T) {
	wantErr := errors.New("boom")
	lc := fakeServiceLister{servicesErr: wantErr}

	ctx := withServiceLister(context.Background(), lc)
	err := runServiceList(ctx, nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

func TestServiceListRejectsArgs(t *testing.T) {
	ctx := withServiceLister(context.Background(), fakeServiceLister{})
	if err := runServiceList(ctx, []string{"unexpected"}); err == nil {
		t.Error("expected error for extra args, got nil")
	}
}

func TestServiceHostname(t *testing.T) {
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
		if got := serviceHostname(tt.name, tt.suffix); got != tt.want {
			t.Errorf("serviceHostname(%q, %q) = %q, want %q", tt.name, tt.suffix, got, tt.want)
		}
	}
}

// TestServiceListerFromContextDefault verifies that without injection the
// real localClient is returned.
func TestServiceListerFromContextDefault(t *testing.T) {
	if got := serviceListerFromContext(context.Background()); got != &localClient {
		t.Errorf("serviceListerFromContext default = %v, want &localClient", got)
	}
}

// TestServiceCmdWIPGate verifies the service command is only registered when
// work-in-progress code is enabled.
func TestServiceCmdWIPGate(t *testing.T) {
	t.Setenv("TAILSCALE_USE_WIP_CODE", "")
	if cmd := serviceCmd(); cmd != nil {
		t.Errorf("serviceCmd() = %v, want nil when WIP code is disabled", cmd)
	}

	t.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	if cmd := serviceCmd(); cmd == nil {
		t.Error("serviceCmd() = nil, want non-nil when WIP code is enabled")
	}
}
