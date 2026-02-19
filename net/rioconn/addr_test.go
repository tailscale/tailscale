// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/util/must"
)

func TestRawSockaddrLayout(t *testing.T) {
	t.Parallel()
	if unsafe.Alignof(rawSockaddr{}) != unsafe.Alignof(windows.RawSockaddrInet{}) {
		t.Errorf("rawSockaddr has incorrect alignment: %d != %d",
			unsafe.Alignof(rawSockaddr{}), unsafe.Alignof(windows.RawSockaddrInet{}))
	}
	if unsafe.Sizeof(rawSockaddr{}) < unsafe.Sizeof(windows.RawSockaddrInet4{}) {
		t.Errorf("rawSockaddr is too small to hold RawSockaddrInet4: %d < %d",
			unsafe.Sizeof(rawSockaddr{}), unsafe.Sizeof(windows.RawSockaddrInet4{}))
	}
	if unsafe.Sizeof(rawSockaddr{}) < unsafe.Sizeof(windows.RawSockaddrInet6{}) {
		t.Errorf("rawSockaddr is too small to hold RawSockaddrInet6: %d < %d",
			unsafe.Sizeof(rawSockaddr{}), unsafe.Sizeof(windows.RawSockaddrInet6{}))
	}
}

func TestRawSockaddrFromAddrPort(t *testing.T) {
	t.Parallel()
	iface := firstInterface(t)
	tests := []struct {
		name      string
		ap        netip.AddrPort
		wantBytes []byte
		wantErr   bool
	}{
		{
			name:    "invalid-address",
			ap:      netip.AddrPort{},
			wantErr: true,
		},
		{
			name: "IPv4",
			ap:   netip.MustParseAddrPort("1.2.3.4:5678"),
			wantBytes: []byte{
				0x02, 0x00, // Family = AF_INET
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x01, 0x02, 0x03, 0x04, // Addr = 1.2.3.4
			},
		},
		{
			name: "IPv4/unspecified",
			ap:   netip.AddrPortFrom(netip.IPv4Unspecified(), 1234),
			wantBytes: []byte{
				0x02, 0x00, // Family = AF_INET
				0x04, 0xd2, // Port = 1234 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Addr = 0.0.0.0
			},
		},
		{
			name: "IPv6",
			ap:   netip.MustParseAddrPort("[2001:db8::1]:5678"),
			wantBytes: []byte{
				0x17, 0x00, // Family = AF_INET6
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, // Scope_id = 0
			},
		},
		{
			name: "IPv6/unspecified",
			ap:   netip.AddrPortFrom(netip.IPv6Unspecified(), 1234),
			wantBytes: []byte{
				0x17, 0x00, // Family = AF_INET6
				0x04, 0xd2, // Port = 1234 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = :: (all zeros)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, // Scope_id = 0
			},
		},
		{
			name: "IPv6/with-zone",
			ap:   netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1").WithZone(iface.Name), 5678),
			wantBytes: append([]byte{
				0x17, 0x00, // Family = AF_INET6
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				// Scope_id = interface index (host byte order)
				binary.LittleEndian.AppendUint32(nil, uint32(iface.Index))...,
			),
		},
		{
			name:    "IPv6/invalid-zone",
			ap:      netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1").WithZone("nonexistent"), 5678),
			wantErr: true,
		},
		{
			name: "zero-port",
			ap:   netip.MustParseAddrPort("[2001:db8::1]:0"),
			wantBytes: []byte{
				0x17, 0x00, // Family = AF_INET6
				0x00, 0x00, // Port = 0
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, // Scope_id = 0
			},
		},
		{
			name: "max-port",
			ap:   netip.MustParseAddrPort("[2001:db8::1]:65535"),
			wantBytes: []byte{
				0x17, 0x00, // Family = AF_INET6
				0xff, 0xff, // Port = 65535 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, // Scope_id = 0
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sa, err := rawSockaddrFromAddrPort(tt.ap)
			if (err != nil) != tt.wantErr {
				t.Fatalf("rawSockaddrFromAddrPort(%v) error: got %v; want %v", tt.ap, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			gotBytes := unsafe.Slice((*byte)(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
			gotBytes = gotBytes[:len(tt.wantBytes)] // only compare the relevant bytes
			if !bytes.Equal(gotBytes, tt.wantBytes) {
				t.Errorf("rawSockaddrFromAddrPort(%v): got %v; want %v", tt.ap, gotBytes, tt.wantBytes)
			}
		})
	}
}

func TestInterfaceIndexFromZone(t *testing.T) {
	t.Parallel()

	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}

	t.Run("by-name", func(t *testing.T) {
		t.Parallel()
		for _, iface := range interfaces {
			index, err := interfaceIndexFromZone(iface.Name)
			if err != nil {
				t.Fatalf("interfaceIndexFromZone(%q) error: %v", iface.Name, err)
			}
			if index != uint32(iface.Index) {
				t.Errorf("interfaceIndexFromZone(%q): got %d; want %d", iface.Name, index, iface.Index)
			}
		}
	})

	t.Run("by-index", func(t *testing.T) {
		t.Parallel()
		for _, iface := range interfaces {
			indexStr := strconv.Itoa(iface.Index)
			index, err := interfaceIndexFromZone(indexStr)
			if err != nil {
				t.Fatalf("interfaceIndexFromZone(%q) error: %v", indexStr, err)
			}
			if index != uint32(iface.Index) {
				t.Errorf("interfaceIndexFromZone(%q): got %d; want %d", indexStr, index, iface.Index)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		_, err := interfaceIndexFromZone("nonexistent-interface-name")
		if err == nil {
			t.Errorf("interfaceIndexFromZone: expected error; got nil")
		}
	})
}

func TestRawSockaddrToAddrPort(t *testing.T) {
	t.Parallel()
	iface := firstInterface(t)
	tests := []struct {
		name    string
		bytes   []byte
		want    netip.AddrPort
		wantErr bool
	}{
		{
			name:    "invalid/unspecified",
			bytes:   []byte{0x00, 0x00}, // Family = 0 (AF_UNSPEC)
			wantErr: true,
		},
		{
			name: "invalid/netbios",
			bytes: []byte{
				0x11, 0x00, // Family = AF_NETBIOS (0x11)
				0x00, 0x00, // Type = NETBIOS_UNIQUE_NAME
				0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20,
				0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			},
			wantErr: true,
		},
		{
			name: "IPv4",
			bytes: []byte{
				0x02, 0x00, // Family = AF_INET
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x01, 0x02, 0x03, 0x04, // Addr = 1.2.3.4
			},
			want: netip.MustParseAddrPort("1.2.3.4:5678"),
		},
		{
			name: "IPv6",
			bytes: []byte{
				0x17, 0x00, // Family = AF_INET6
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, // Scope_id = 0
			},
			want: netip.MustParseAddrPort("[2001:db8::1]:5678"),
		},
		{
			name: "IPv6/with-zone",
			bytes: append([]byte{
				0x17, 0x00, // Family = AF_INET6
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				// Scope_id = interface index (host byte order)
				binary.LittleEndian.AppendUint32(nil, uint32(iface.Index))...,
			),
			want: netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1").WithZone(iface.Name), 5678),
		},
		{
			name: "IPv6/invalid-zone",
			bytes: []byte{
				0x17, 0x00, // Family = AF_INET6
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Scope_id = 0xDEADBEEF (nonexistent interface index)
				0xDE, 0xAD, 0xBE, 0xEF,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sa rawSockaddr
			if len(tt.bytes) > int(unsafe.Sizeof(sa)) {
				t.Fatalf("test bytes too large: %d > %d", len(tt.bytes), unsafe.Sizeof(sa))
			}
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)), tt.bytes)
			ap, err := sa.ToAddrPort()
			if (err != nil) != tt.wantErr {
				t.Fatalf("rawSockaddr.ToAddrPort() error: got %v; want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if ap != tt.want {
				t.Errorf("rawSockaddr.ToAddrPort(): got %v; want %v", ap, tt.want)
			}
		})
	}
}

func TestRawSockaddrToSockaddr(t *testing.T) {
	t.Parallel()
	iface := firstInterface(t)
	tests := []struct {
		name    string
		bytes   []byte
		want    windows.Sockaddr
		wantErr bool
	}{
		{
			name: "invalid/unspecified-family",
			bytes: []byte{
				0x00, 0x00, // Family = 0 (AF_UNSPEC)
			},
			wantErr: true,
		},
		{
			name: "invalid/netbios-family",
			bytes: []byte{
				0x11, 0x00, // Family = AF_NETBIOS (0x11)
				0x00, 0x00, // Type = NETBIOS_UNIQUE_NAME
				0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20,
				0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
			},
			wantErr: true,
		},
		{
			name: "IPv4",
			bytes: []byte{
				0x02, 0x00, // Family = AF_INET
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x01, 0x02, 0x03, 0x04, // Addr = 1.2.3.4
			},
			want: &windows.SockaddrInet4{
				Port: 5678,
				Addr: [4]byte{1, 2, 3, 4},
			},
		},
		{
			name: "IPv6",
			bytes: []byte{
				0x17, 0x00, // Family = AF_INET6
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, // Scope_id = 0
			},
			want: &windows.SockaddrInet6{
				Port: 5678,
				Addr: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				ZoneId: 0,
			},
		},
		{
			name: "IPv6/with-zone",
			bytes: append([]byte{
				0x17, 0x00, // Family = AF_INET6
				0x16, 0x2e, // Port = 5678 (network byte order)
				0x00, 0x00, 0x00, 0x00, // Flowinfo = 0
				// Addr = 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				// Scope_id = interface index (host byte order)
				binary.LittleEndian.AppendUint32(nil, uint32(iface.Index))...,
			),
			want: &windows.SockaddrInet6{
				Port: 5678,
				Addr: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				ZoneId: uint32(iface.Index),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sa rawSockaddr
			if len(tt.bytes) > int(unsafe.Sizeof(sa)) {
				t.Fatalf("test bytes too large: %d > %d", len(tt.bytes), unsafe.Sizeof(sa))
			}
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)), tt.bytes)
			got, err := sa.Sockaddr()
			if (err != nil) != tt.wantErr {
				t.Fatalf("rawSockaddr.Sockaddr() error: got %v; want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			checkSockaddrEqual(t, got, tt.want)
		})
	}
}

func TestRawSockaddrFamily(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		rsa         rawSockaddr
		wantFamily  uint16
		wantIPv4In6 bool
	}{
		{
			name:       "IPv4",
			rsa:        must.Get(rawSockaddrFromAddrPort(netip.MustParseAddrPort("192.0.2.0:50000"))),
			wantFamily: windows.AF_INET,
		},
		{
			name:       "IPv6",
			rsa:        must.Get(rawSockaddrFromAddrPort(netip.MustParseAddrPort("[2001:db8::1]:50000"))),
			wantFamily: windows.AF_INET6,
		},
		{
			name: "IPv4-mapped-IPv6",
			rsa: must.Get(
				rawSockaddrFromAddrPort(
					netip.AddrPortFrom(
						netip.AddrFrom16(netip.MustParseAddr("192.0.2.0").As16()),
						50000,
					),
				),
			),
			wantFamily:  windows.AF_INET6,
			wantIPv4In6: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if gotFamily := tt.rsa.Family(); gotFamily != tt.wantFamily {
				t.Errorf("rawSockaddr.Family(): got %d; want %d", gotFamily, tt.wantFamily)
			}
			if gotIPv4In6 := tt.rsa.Is4In6(); gotIPv4In6 != tt.wantIPv4In6 {
				t.Errorf("rawSockaddr.Is4In6(): got %v; want %v", gotIPv4In6, tt.wantIPv4In6)
			}
		})
	}
}

func TestAddrPortFromSockaddr(t *testing.T) {
	t.Parallel()
	iface := firstInterface(t)
	tests := []struct {
		name    string
		sa      windows.Sockaddr
		want    netip.AddrPort
		wantErr bool
	}{
		{
			name: "IPv4",
			sa: &windows.SockaddrInet4{
				Port: 50000,
				Addr: [4]byte{192, 0, 2, 1},
			},
			want: netip.MustParseAddrPort("192.0.2.1:50000"),
		},
		{
			name: "IPv4/invalid-port",
			sa: &windows.SockaddrInet4{
				Port: 0xFFFF + 1,
				Addr: [4]byte{192, 0, 2, 1},
			},
			wantErr: true,
		},
		{
			name: "IPv6",
			sa: &windows.SockaddrInet6{
				Port: 50000,
				Addr: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				ZoneId: 0,
			},
			want: netip.MustParseAddrPort("[2001:db8::1]:50000"),
		},
		{
			name: "IPv6/invalid-port",
			sa: &windows.SockaddrInet6{
				Port: 0xFFFF + 1,
				Addr: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				ZoneId: 0,
			},
			wantErr: true,
		},
		{
			name: "IPv6/IPv4-mapped",
			sa: &windows.SockaddrInet6{
				Port: 50000,
				Addr: [16]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0xff, 0xff, 192, 0, 2, 1,
				},
				ZoneId: 0,
			},
			want: netip.MustParseAddrPort("[::ffff:192.0.2.1]:50000"),
		},
		{
			name: "IPv6/with-zone",
			sa: &windows.SockaddrInet6{
				Port: 50000,
				Addr: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				ZoneId: uint32(iface.Index),
			},
			want: netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1").WithZone(iface.Name), 50000),
		},
		{
			name: "IPv6/invalid-zone",
			sa: &windows.SockaddrInet6{
				Port: 50000,
				Addr: [16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				ZoneId: uint32(0xDEADBEEF), // some nonexistent zone
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := addrPortFromSockaddr(tt.sa)
			if (err != nil) != tt.wantErr {
				t.Fatalf("addrPortFromSockaddr() error: got %v; want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("addrPortFromSockaddr() got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestNetAddrFromAddrPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ap       netip.AddrPort
		sotype   int32
		wantNet  string
		wantAddr string
		wantErr  bool
	}{
		{
			name:    "invalid-address",
			sotype:  windows.SOCK_DGRAM,
			ap:      netip.AddrPort{},
			wantErr: true,
		},
		{
			name:     "IPv4/UDP",
			sotype:   windows.SOCK_DGRAM,
			ap:       netip.MustParseAddrPort("192.0.2.1:1234"),
			wantNet:  "udp",
			wantAddr: "192.0.2.1:1234",
		},
		{
			name:     "IPv6/UDP",
			sotype:   windows.SOCK_DGRAM,
			ap:       netip.MustParseAddrPort("[2001:db8::1]:1234"),
			wantNet:  "udp",
			wantAddr: "[2001:db8::1]:1234",
		},
		{
			name:     "IPv4/TCP",
			sotype:   windows.SOCK_STREAM,
			ap:       netip.MustParseAddrPort("192.0.2.1:1234"),
			wantNet:  "tcp",
			wantAddr: "192.0.2.1:1234",
		},
		{
			name:     "IPv6/TCP",
			sotype:   windows.SOCK_STREAM,
			ap:       netip.MustParseAddrPort("[2001:db8::1]:1234"),
			wantNet:  "tcp",
			wantAddr: "[2001:db8::1]:1234",
		},
		{
			name:    "IPv4/unsupported-socket-type",
			sotype:  windows.SOCK_RAW,
			ap:      netip.MustParseAddrPort("192.0.2.1:1234"),
			wantErr: true,
		},
		{
			name:    "IPv6/unsupported-socket-type",
			sotype:  windows.SOCK_RAW,
			ap:      netip.MustParseAddrPort("[2001:db8::1]:1234"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotAddr, err := netAddrFromAddrPort(tt.ap, tt.sotype)
			if (err != nil) != tt.wantErr {
				t.Fatalf("netAddrFromAddrPort error: got %v; want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if gotAddr.Network() != tt.wantNet {
				t.Errorf("netAddrFromAddrPort network: got  %q; want %q", gotAddr.Network(), tt.wantNet)
			}
			if gotAddr.String() != tt.wantAddr {
				t.Errorf("netAddrFromAddrPort address: got %q; want %q", gotAddr.String(), tt.wantAddr)
			}
		})
	}
}

func TestNetworkName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		sotype    int32
		proto     int32
		family    int32
		dualStack bool
		wantNet   string
		wantErr   bool
	}{
		{
			name:    "dgram/UDP/invalid-family",
			sotype:  windows.SOCK_DGRAM,
			proto:   windows.IPPROTO_UDP,
			family:  0,
			wantErr: true,
		},
		{
			name:    "dgram/UDP/IPv4",
			sotype:  windows.SOCK_DGRAM,
			proto:   windows.IPPROTO_UDP,
			family:  windows.AF_INET,
			wantNet: "udp4",
		},
		{
			name:    "dgram/UDP/IPv6",
			sotype:  windows.SOCK_DGRAM,
			proto:   windows.IPPROTO_UDP,
			family:  windows.AF_INET6,
			wantNet: "udp6",
		},
		{
			name:      "dgram/UDP/IPv6/dual-stack",
			sotype:    windows.SOCK_DGRAM,
			proto:     windows.IPPROTO_UDP,
			family:    windows.AF_INET6,
			dualStack: true,
			wantNet:   "udp",
		},
		{
			name:    "stream/TCP/invalid-family",
			sotype:  windows.SOCK_STREAM,
			proto:   windows.IPPROTO_TCP,
			family:  0,
			wantErr: true,
		},
		{
			name:    "stream/TCP/IPv4",
			sotype:  windows.SOCK_STREAM,
			proto:   windows.IPPROTO_TCP,
			family:  windows.AF_INET,
			wantNet: "tcp4",
		},
		{
			name:    "stream/TCP/IPv6",
			sotype:  windows.SOCK_STREAM,
			proto:   windows.IPPROTO_TCP,
			family:  windows.AF_INET6,
			wantNet: "tcp6",
		},
		{
			name:      "stream/TCP/IPv6/dual-stack",
			sotype:    windows.SOCK_STREAM,
			proto:     windows.IPPROTO_TCP,
			family:    windows.AF_INET6,
			dualStack: true,
			wantNet:   "tcp",
		},
		{
			name:    "unsupported-socket-type",
			sotype:  windows.SOCK_RAW,
			proto:   windows.IPPROTO_IP,
			family:  windows.AF_INET,
			wantErr: true,
		},
		{
			name:    "unsupported-protocol",
			sotype:  windows.SOCK_DGRAM,
			proto:   windows.IPPROTO_ICMP,
			family:  windows.AF_INET,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotNet, err := networkName(tt.sotype, tt.proto, tt.family, tt.dualStack)
			if (err != nil) != tt.wantErr {
				t.Fatalf("networkName error: got %v; want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if gotNet != tt.wantNet {
				t.Errorf("networkName: got %q; want %q", gotNet, tt.wantNet)
			}
		})
	}
}

func firstInterface(t *testing.T) net.Interface {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		t.Fatal("no network interfaces found")
	}
	return interfaces[0]
}

func checkSockaddrEqual(t *testing.T, sa1, sa2 windows.Sockaddr) {
	t.Helper()
	switch sa1 := sa1.(type) {
	case *windows.SockaddrInet4:
		sa2, ok := sa2.(*windows.SockaddrInet4)
		if !ok {
			t.Fatalf("sockaddr types do not match: got %T and %T", sa1, sa2)
		}
		if sa1.Port != sa2.Port {
			t.Errorf("sockaddr ports do not match: got %d and %d", sa1.Port, sa2.Port)
		}
		if !bytes.Equal(sa1.Addr[:], sa2.Addr[:]) {
			t.Errorf("sockaddr addresses do not match: got %v and %v", sa1.Addr, sa2.Addr)
		}
	case *windows.SockaddrInet6:
		sa2, ok := sa2.(*windows.SockaddrInet6)
		if !ok {
			t.Fatalf("sockaddr types do not match: got %T and %T", sa1, sa2)
		}
		if sa1.Port != sa2.Port {
			t.Errorf("sockaddr ports do not match: got %d and %d", sa1.Port, sa2.Port)
		}
		if sa1.ZoneId != sa2.ZoneId {
			t.Errorf("sockaddr zone IDs do not match: got %d and %d", sa1.ZoneId, sa2.ZoneId)
		}
		if !bytes.Equal(sa1.Addr[:], sa2.Addr[:]) {
			t.Errorf("sockaddr addresses do not match: got %v and %v", sa1.Addr, sa2.Addr)
		}
	default:
		t.Fatalf("unsupported sockaddr types: got %T and %T", sa1, sa2)
	}
}
