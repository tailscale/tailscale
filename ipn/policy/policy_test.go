// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestIsInterestingService(t *testing.T) {
	tests := []struct {
		name string
		svc  tailcfg.Service
		os   string
		want bool
	}{
		// PeerAPI protocols - always interesting
		{
			name: "peerapi4",
			svc:  tailcfg.Service{Proto: tailcfg.PeerAPI4, Port: 12345},
			os:   "linux",
			want: true,
		},
		{
			name: "peerapi6",
			svc:  tailcfg.Service{Proto: tailcfg.PeerAPI6, Port: 12345},
			os:   "windows",
			want: true,
		},
		{
			name: "peerapidns",
			svc:  tailcfg.Service{Proto: tailcfg.PeerAPIDNS, Port: 12345},
			os:   "darwin",
			want: true,
		},

		// Non-TCP protocols on non-Windows (should be false)
		{
			name: "udp_linux",
			svc:  tailcfg.Service{Proto: tailcfg.UDP, Port: 53},
			os:   "linux",
			want: false,
		},
		{
			name: "udp_darwin",
			svc:  tailcfg.Service{Proto: tailcfg.UDP, Port: 80},
			os:   "darwin",
			want: false,
		},

		// TCP on Linux - all ports interesting
		{
			name: "tcp_linux_ssh",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 22},
			os:   "linux",
			want: true,
		},
		{
			name: "tcp_linux_random",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 9999},
			os:   "linux",
			want: true,
		},
		{
			name: "tcp_linux_http",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 80},
			os:   "linux",
			want: true,
		},

		// TCP on Darwin - all ports interesting
		{
			name: "tcp_darwin_vnc",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 5900},
			os:   "darwin",
			want: true,
		},
		{
			name: "tcp_darwin_custom",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 12345},
			os:   "darwin",
			want: true,
		},

		// TCP on Windows - only allowlisted ports
		{
			name: "tcp_windows_ssh",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 22},
			os:   "windows",
			want: true,
		},
		{
			name: "tcp_windows_http",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 80},
			os:   "windows",
			want: true,
		},
		{
			name: "tcp_windows_https",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 443},
			os:   "windows",
			want: true,
		},
		{
			name: "tcp_windows_rdp",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 3389},
			os:   "windows",
			want: true,
		},
		{
			name: "tcp_windows_vnc",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 5900},
			os:   "windows",
			want: true,
		},
		{
			name: "tcp_windows_plex",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 32400},
			os:   "windows",
			want: true,
		},
		{
			name: "tcp_windows_dev_8000",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 8000},
			os:   "windows",
			want: true,
		},
		{
			name: "tcp_windows_dev_8080",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 8080},
			os:   "windows",
			want: true,
		},
		{
			name: "tcp_windows_dev_8443",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 8443},
			os:   "windows",
			want: true,
		},
		{
			name: "tcp_windows_dev_8888",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 8888},
			os:   "windows",
			want: true,
		},

		// TCP on Windows - non-allowlisted ports (should be false)
		{
			name: "tcp_windows_random_low",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 135},
			os:   "windows",
			want: false,
		},
		{
			name: "tcp_windows_random_mid",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 9999},
			os:   "windows",
			want: false,
		},
		{
			name: "tcp_windows_random_high",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 49152},
			os:   "windows",
			want: false,
		},
		{
			name: "tcp_windows_smb",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 445},
			os:   "windows",
			want: false,
		},

		// Edge cases
		{
			name: "tcp_port_zero",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 0},
			os:   "linux",
			want: true, // Linux accepts all TCP ports
		},
		{
			name: "tcp_port_max",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 65535},
			os:   "linux",
			want: true,
		},
		{
			name: "empty_os_tcp",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 80},
			os:   "",
			want: true, // Empty OS is treated as non-Windows
		},
		{
			name: "openbsd_tcp",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 8080},
			os:   "openbsd",
			want: true, // Non-Windows OS
		},
		{
			name: "freebsd_tcp",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 3000},
			os:   "freebsd",
			want: true, // Non-Windows OS
		},
		{
			name: "android_tcp",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 8080},
			os:   "android",
			want: true, // Non-Windows OS
		},
		{
			name: "ios_tcp",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 8080},
			os:   "ios",
			want: true, // Non-Windows OS
		},

		// Case sensitivity check for Windows
		{
			name: "windows_uppercase",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 9999},
			os:   "Windows",
			want: true, // Should NOT match "windows" - case sensitive
		},
		{
			name: "windows_mixed_case",
			svc:  tailcfg.Service{Proto: tailcfg.TCP, Port: 9999},
			os:   "WINDOWS",
			want: true, // Should NOT match "windows" - case sensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsInterestingService(tt.svc, tt.os)
			if got != tt.want {
				t.Errorf("IsInterestingService(%+v, %q) = %v, want %v",
					tt.svc, tt.os, got, tt.want)
			}
		})
	}
}

func TestIsInterestingService_AllWindowsPorts(t *testing.T) {
	// Exhaustively test all allowlisted Windows ports
	allowlistedPorts := []uint16{22, 80, 443, 3389, 5900, 32400, 8000, 8080, 8443, 8888}

	for _, port := range allowlistedPorts {
		svc := tailcfg.Service{Proto: tailcfg.TCP, Port: port}
		if !IsInterestingService(svc, "windows") {
			t.Errorf("IsInterestingService(TCP:%d, windows) = false, want true", port)
		}
	}
}

func TestIsInterestingService_AllPeerAPIProtocols(t *testing.T) {
	// Test all PeerAPI protocols on various OS
	peerAPIProtocols := []tailcfg.ServiceProto{
		tailcfg.PeerAPI4,
		tailcfg.PeerAPI6,
		tailcfg.PeerAPIDNS,
	}

	operatingSystems := []string{"linux", "darwin", "windows", "freebsd", "openbsd", "android", "ios"}

	for _, proto := range peerAPIProtocols {
		for _, os := range operatingSystems {
			svc := tailcfg.Service{Proto: proto, Port: 12345}
			if !IsInterestingService(svc, os) {
				t.Errorf("IsInterestingService(%v, %s) = false, want true (PeerAPI always interesting)",
					proto, os)
			}
		}
	}
}

func TestIsInterestingService_NonWindowsAcceptsAllTCP(t *testing.T) {
	// Verify that non-Windows OSes accept all TCP ports
	nonWindowsOSes := []string{"linux", "darwin", "freebsd", "openbsd", "android", "ios", ""}
	testPorts := []uint16{1, 22, 80, 135, 445, 1234, 8080, 9999, 32768, 65535}

	for _, os := range nonWindowsOSes {
		for _, port := range testPorts {
			svc := tailcfg.Service{Proto: tailcfg.TCP, Port: port}
			if !IsInterestingService(svc, os) {
				t.Errorf("IsInterestingService(TCP:%d, %s) = false, want true (non-Windows accepts all TCP)",
					port, os)
			}
		}
	}
}

func TestIsInterestingService_WindowsRejectsNonAllowlisted(t *testing.T) {
	// Test that Windows rejects TCP ports not in the allowlist
	rejectedPorts := []uint16{1, 21, 23, 25, 110, 135, 139, 445, 1433, 3306, 5432, 9999, 49152, 65535}

	for _, port := range rejectedPorts {
		svc := tailcfg.Service{Proto: tailcfg.TCP, Port: port}
		if IsInterestingService(svc, "windows") {
			t.Errorf("IsInterestingService(TCP:%d, windows) = true, want false (not in allowlist)",
				port)
		}
	}
}

// Benchmark the function to ensure it's fast
func BenchmarkIsInterestingService(b *testing.B) {
	svc := tailcfg.Service{Proto: tailcfg.TCP, Port: 8080}

	b.Run("windows", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			IsInterestingService(svc, "windows")
		}
	})

	b.Run("linux", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			IsInterestingService(svc, "linux")
		}
	})

	b.Run("peerapi", func(b *testing.B) {
		peerSvc := tailcfg.Service{Proto: tailcfg.PeerAPI4, Port: 12345}
		for i := 0; i < b.N; i++ {
			IsInterestingService(peerSvc, "linux")
		}
	})
}
