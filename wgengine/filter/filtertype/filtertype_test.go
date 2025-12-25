// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package filtertype

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
)

func TestPortRange_String(t *testing.T) {
	tests := []struct {
		name string
		pr   PortRange
		want string
	}{
		{
			name: "all_ports",
			pr:   PortRange{0, 65535},
			want: "*",
		},
		{
			name: "single_port",
			pr:   PortRange{80, 80},
			want: "80",
		},
		{
			name: "range",
			pr:   PortRange{8000, 8999},
			want: "8000-8999",
		},
		{
			name: "ssh",
			pr:   PortRange{22, 22},
			want: "22",
		},
		{
			name: "http_to_https",
			pr:   PortRange{80, 443},
			want: "80-443",
		},
		{
			name: "first_port",
			pr:   PortRange{0, 0},
			want: "0",
		},
		{
			name: "last_port",
			pr:   PortRange{65535, 65535},
			want: "65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pr.String()
			if got != tt.want {
				t.Errorf("PortRange.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPortRange_Contains(t *testing.T) {
	tests := []struct {
		name string
		pr   PortRange
		port uint16
		want bool
	}{
		{
			name: "in_range_start",
			pr:   PortRange{80, 90},
			port: 80,
			want: true,
		},
		{
			name: "in_range_end",
			pr:   PortRange{80, 90},
			port: 90,
			want: true,
		},
		{
			name: "in_range_middle",
			pr:   PortRange{80, 90},
			port: 85,
			want: true,
		},
		{
			name: "before_range",
			pr:   PortRange{80, 90},
			port: 79,
			want: false,
		},
		{
			name: "after_range",
			pr:   PortRange{80, 90},
			port: 91,
			want: false,
		},
		{
			name: "all_ports_zero",
			pr:   AllPorts,
			port: 0,
			want: true,
		},
		{
			name: "all_ports_max",
			pr:   AllPorts,
			port: 65535,
			want: true,
		},
		{
			name: "all_ports_middle",
			pr:   AllPorts,
			port: 8080,
			want: true,
		},
		{
			name: "single_port_match",
			pr:   PortRange{443, 443},
			port: 443,
			want: true,
		},
		{
			name: "single_port_no_match",
			pr:   PortRange{443, 443},
			port: 444,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pr.Contains(tt.port)
			if got != tt.want {
				t.Errorf("PortRange(%d,%d).Contains(%d) = %v, want %v",
					tt.pr.First, tt.pr.Last, tt.port, got, tt.want)
			}
		})
	}
}

func TestAllPorts(t *testing.T) {
	if AllPorts.First != 0 || AllPorts.Last != 0xffff {
		t.Errorf("AllPorts = %+v, want {0, 65535}", AllPorts)
	}

	// Test that AllPorts contains various ports
	testPorts := []uint16{0, 1, 80, 443, 8080, 32768, 65534, 65535}
	for _, port := range testPorts {
		if !AllPorts.Contains(port) {
			t.Errorf("AllPorts.Contains(%d) = false, want true", port)
		}
	}
}

func TestNetPortRange_String(t *testing.T) {
	tests := []struct {
		name string
		npr  NetPortRange
		want string
	}{
		{
			name: "ipv4_single_port",
			npr: NetPortRange{
				Net:   netip.MustParsePrefix("192.168.1.0/24"),
				Ports: PortRange{80, 80},
			},
			want: "192.168.1.0/24:80",
		},
		{
			name: "ipv4_port_range",
			npr: NetPortRange{
				Net:   netip.MustParsePrefix("10.0.0.0/8"),
				Ports: PortRange{8000, 9000},
			},
			want: "10.0.0.0/8:8000-9000",
		},
		{
			name: "ipv4_all_ports",
			npr: NetPortRange{
				Net:   netip.MustParsePrefix("172.16.0.0/12"),
				Ports: AllPorts,
			},
			want: "172.16.0.0/12:*",
		},
		{
			name: "ipv6_single_port",
			npr: NetPortRange{
				Net:   netip.MustParsePrefix("2001:db8::/32"),
				Ports: PortRange{443, 443},
			},
			want: "2001:db8::/32:443",
		},
		{
			name: "ipv6_port_range",
			npr: NetPortRange{
				Net:   netip.MustParsePrefix("fd00::/8"),
				Ports: PortRange{3000, 4000},
			},
			want: "fd00::/8:3000-4000",
		},
		{
			name: "single_host",
			npr: NetPortRange{
				Net:   netip.MustParsePrefix("192.168.1.100/32"),
				Ports: PortRange{22, 22},
			},
			want: "192.168.1.100/32:22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.npr.String()
			if got != tt.want {
				t.Errorf("NetPortRange.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatch_String(t *testing.T) {
	tcp := ipproto.TCP
	udp := ipproto.UDP

	tests := []struct {
		name     string
		m        Match
		wantHave []string // substrings that should be in the output
	}{
		{
			name: "simple_tcp",
			m: Match{
				IPProto: views.SliceOf([]ipproto.Proto{tcp}),
				Srcs:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
				Dsts: []NetPortRange{
					{
						Net:   netip.MustParsePrefix("192.168.1.0/24"),
						Ports: PortRange{80, 80},
					},
				},
			},
			wantHave: []string{"10.0.0.1/32", "192.168.1.0/24:80", "=>"},
		},
		{
			name: "multiple_sources",
			m: Match{
				IPProto: views.SliceOf([]ipproto.Proto{tcp}),
				Srcs: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.1/32"),
					netip.MustParsePrefix("10.0.0.2/32"),
				},
				Dsts: []NetPortRange{
					{
						Net:   netip.MustParsePrefix("192.168.1.0/24"),
						Ports: PortRange{443, 443},
					},
				},
			},
			wantHave: []string{"10.0.0.1/32", "10.0.0.2/32", "192.168.1.0/24:443"},
		},
		{
			name: "multiple_destinations",
			m: Match{
				IPProto: views.SliceOf([]ipproto.Proto{udp}),
				Srcs:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
				Dsts: []NetPortRange{
					{
						Net:   netip.MustParsePrefix("192.168.1.0/24"),
						Ports: PortRange{53, 53},
					},
					{
						Net:   netip.MustParsePrefix("192.168.2.0/24"),
						Ports: PortRange{53, 53},
					},
				},
			},
			wantHave: []string{"10.0.0.1/32", "192.168.1.0/24:53", "192.168.2.0/24:53"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.m.String()
			for _, want := range tt.wantHave {
				if !strings.Contains(got, want) {
					t.Errorf("Match.String() = %q, should contain %q", got, want)
				}
			}
		})
	}
}

func TestCapMatch_Clone(t *testing.T) {
	original := &CapMatch{
		Dst: netip.MustParsePrefix("192.168.1.0/24"),
		Cap: "cap:test",
		Values: []tailcfg.RawMessage{
			tailcfg.RawMessage(`{"key":"value1"}`),
			tailcfg.RawMessage(`{"key":"value2"}`),
		},
	}

	cloned := original.Clone()

	// Verify it's not nil
	if cloned == nil {
		t.Fatal("Clone() returned nil")
	}

	// Verify it's a different pointer
	if cloned == original {
		t.Error("Clone() returned same pointer")
	}

	// Verify values are equal
	if cloned.Dst != original.Dst {
		t.Errorf("Clone().Dst = %v, want %v", cloned.Dst, original.Dst)
	}
	if cloned.Cap != original.Cap {
		t.Errorf("Clone().Cap = %v, want %v", cloned.Cap, original.Cap)
	}
	if len(cloned.Values) != len(original.Values) {
		t.Fatalf("Clone().Values length = %d, want %d", len(cloned.Values), len(original.Values))
	}

	// Verify modifying clone doesn't affect original
	cloned.Values[0] = tailcfg.RawMessage(`{"modified":"value"}`)
	if string(original.Values[0]) == `{"modified":"value"}` {
		t.Error("modifying clone affected original")
	}
}

func TestCapMatch_CloneNil(t *testing.T) {
	var cm *CapMatch
	cloned := cm.Clone()
	if cloned != nil {
		t.Errorf("Clone() of nil = %v, want nil", cloned)
	}
}

func TestMatch_Clone(t *testing.T) {
	tcp := ipproto.TCP
	original := &Match{
		IPProto: views.SliceOf([]ipproto.Proto{tcp}),
		Srcs: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.1/32"),
			netip.MustParsePrefix("10.0.0.2/32"),
		},
		SrcCaps: []tailcfg.NodeCapability{"cap:test1", "cap:test2"},
		Dsts: []NetPortRange{
			{
				Net:   netip.MustParsePrefix("192.168.1.0/24"),
				Ports: PortRange{80, 80},
			},
		},
		Caps: []CapMatch{
			{
				Dst:    netip.MustParsePrefix("192.168.2.0/24"),
				Cap:    "cap:admin",
				Values: []tailcfg.RawMessage{tailcfg.RawMessage(`{"admin":true}`)},
			},
		},
	}

	cloned := original.Clone()

	// Verify it's not nil
	if cloned == nil {
		t.Fatal("Clone() returned nil")
	}

	// Verify it's a different pointer
	if cloned == original {
		t.Error("Clone() returned same pointer")
	}

	// Verify slices are independent
	if len(cloned.Srcs) != len(original.Srcs) {
		t.Errorf("Clone().Srcs length = %d, want %d", len(cloned.Srcs), len(original.Srcs))
	}

	// Modify clone and verify original is unchanged
	cloned.Srcs = append(cloned.Srcs, netip.MustParsePrefix("10.0.0.3/32"))
	if len(original.Srcs) == len(cloned.Srcs) {
		t.Error("modifying clone's Srcs affected original")
	}

	cloned.SrcCaps = append(cloned.SrcCaps, "cap:test3")
	if len(original.SrcCaps) == len(cloned.SrcCaps) {
		t.Error("modifying clone's SrcCaps affected original")
	}

	cloned.Dsts = append(cloned.Dsts, NetPortRange{
		Net:   netip.MustParsePrefix("172.16.0.0/12"),
		Ports: PortRange{443, 443},
	})
	if len(original.Dsts) == len(cloned.Dsts) {
		t.Error("modifying clone's Dsts affected original")
	}
}

func TestMatch_CloneNil(t *testing.T) {
	var m *Match
	cloned := m.Clone()
	if cloned != nil {
		t.Errorf("Clone() of nil = %v, want nil", cloned)
	}
}

func TestMatch_CloneWithNilCaps(t *testing.T) {
	tcp := ipproto.TCP
	m := &Match{
		IPProto: views.SliceOf([]ipproto.Proto{tcp}),
		Srcs:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
		Caps:    nil,
	}

	cloned := m.Clone()
	if cloned == nil {
		t.Fatal("Clone() returned nil")
	}

	if cloned.Caps != nil {
		t.Errorf("Clone().Caps = %v, want nil", cloned.Caps)
	}
}

// Test that SrcsContains function field is not serialized but clone copies it
func TestMatch_SrcsContains(t *testing.T) {
	containsFunc := func(addr netip.Addr) bool {
		return addr.String() == "10.0.0.1"
	}

	m := &Match{
		SrcsContains: containsFunc,
	}

	// Test the function works
	if !m.SrcsContains(netip.MustParseAddr("10.0.0.1")) {
		t.Error("SrcsContains(10.0.0.1) = false, want true")
	}
	if m.SrcsContains(netip.MustParseAddr("10.0.0.2")) {
		t.Error("SrcsContains(10.0.0.2) = true, want false")
	}
}

// Benchmark port range operations
func BenchmarkPortRange_Contains(b *testing.B) {
	pr := PortRange{8000, 9000}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pr.Contains(8500)
	}
}

func BenchmarkPortRange_String(b *testing.B) {
	pr := PortRange{8000, 9000}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pr.String()
	}
}

func BenchmarkMatch_String(b *testing.B) {
	tcp := ipproto.TCP
	m := Match{
		IPProto: views.SliceOf([]ipproto.Proto{tcp}),
		Srcs: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.1/32"),
			netip.MustParsePrefix("10.0.0.2/32"),
		},
		Dsts: []NetPortRange{
			{
				Net:   netip.MustParsePrefix("192.168.1.0/24"),
				Ports: PortRange{80, 80},
			},
			{
				Net:   netip.MustParsePrefix("192.168.2.0/24"),
				Ports: PortRange{443, 443},
			},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.String()
	}
}

func BenchmarkMatch_Clone(b *testing.B) {
	tcp := ipproto.TCP
	m := &Match{
		IPProto: views.SliceOf([]ipproto.Proto{tcp}),
		Srcs:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
		SrcCaps: []tailcfg.NodeCapability{"cap:test"},
		Dsts: []NetPortRange{
			{Net: netip.MustParsePrefix("192.168.1.0/24"), Ports: PortRange{80, 80}},
		},
		Caps: []CapMatch{
			{Dst: netip.MustParsePrefix("192.168.2.0/24"), Cap: "cap:admin"},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Clone()
	}
}
