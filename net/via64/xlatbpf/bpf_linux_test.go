// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlatbpf

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/via64/xlat"
	"tailscale.com/tstest"
)

const (
	tcActOK   = 0
	tcActShot = 2
)

var (
	cfg     = xlat.Xlat{X4: netip.MustParseAddr("192.0.0.6")}
	lanHost = netip.MustParseAddr("10.1.0.174")
)

// canon returns a's address inside the canonical prefix, as it looks after the DNAT.
func canon(a netip.Addr) netip.Addr {
	c := xlat.Canonical.Addr().As16()
	b := a.As4()
	copy(c[12:], b[:])
	return netip.AddrFrom16(c)
}

func newTestBackend(t *testing.T) *backend {
	tstest.RequireRoot(t)
	bi, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b := bi.(*backend)
	t.Cleanup(func() { b.Close() })
	if err := b.setConfig(cfg); err != nil {
		t.Fatal(err)
	}
	return b
}

func run(t *testing.T, prog *ebpf.Program, pkt []byte) (uint32, []byte) {
	t.Helper()
	opts := ebpf.RunOptions{Data: pkt, DataOut: make([]byte, len(pkt)+64)}
	ret, err := prog.Run(&opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return ret, opts.DataOut
}

func counters(t *testing.T, b *backend) map[string]uint64 {
	t.Helper()
	c, err := b.Counters()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestXlat6to4(t *testing.T) {
	b := newTestBackend(t)
	tests := []struct {
		name      string
		proto     uint8
		l4        []byte
		wantProto uint8
	}{
		{"tcp", 6, tcpSeg(40000, 5201, []byte("hello")), 6},
		{"udp", 17, udpDgram(40000, 53, []byte("query")), 17},
		{"echo-request", 58, icmpMsg(128, 7, 1, []byte("ping")), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, out := run(t, b.objs.Xlat6to4, packet6(cfg.X6(), canon(lanHost), tt.proto, tt.l4))
			if ret != tcActOK {
				t.Fatalf("verdict %d; want TC_ACT_OK; counters %v", ret, counters(t, b))
			}
			src, dst, proto, ttl, l4 := parse4(t, out)
			if src != cfg.X4 || dst != lanHost || proto != tt.wantProto || ttl != 64 {
				t.Errorf("got %v -> %v proto %d ttl %d; want %v -> %v proto %d ttl 64", src, dst, proto, ttl, cfg.X4, lanHost, tt.wantProto)
			}
			if tt.proto == 58 {
				if l4[0] != 8 || binary.BigEndian.Uint16(l4[4:]) != 7 || binary.BigEndian.Uint16(l4[6:]) != 1 {
					t.Errorf("echo request: type %d id %d seq %d; want 8, 7, 1", l4[0], binary.BigEndian.Uint16(l4[4:]), binary.BigEndian.Uint16(l4[6:]))
				}
			} else if !bytes.Equal(l4[:4], tt.l4[:4]) {
				t.Errorf("ports changed: % x; want % x", l4[:4], tt.l4[:4])
			}
		})
	}
}

func TestXlat4to6(t *testing.T) {
	b := newTestBackend(t)
	tests := []struct {
		name      string
		proto     uint8
		l4        []byte
		wantProto uint8
	}{
		{"tcp", 6, tcpSeg(5201, 40000, []byte("hello")), 6},
		{"udp", 17, udpDgram(53, 40000, []byte("answer")), 17},
		{"echo-reply", 1, icmpMsg(0, 7, 1, []byte("pong")), 58},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, out := run(t, b.objs.Xlat4to6, packet4(lanHost, cfg.X4, tt.proto, tt.l4))
			if ret != tcActOK {
				t.Fatalf("verdict %d; want TC_ACT_OK; counters %v", ret, counters(t, b))
			}
			src, dst, proto, hlim, l4 := parse6(t, out)
			if src != canon(lanHost) || dst != cfg.X6() || proto != tt.wantProto || hlim != 64 {
				t.Errorf("got %v -> %v proto %d hlim %d; want %v -> %v proto %d hlim 64", src, dst, proto, hlim, canon(lanHost), cfg.X6(), tt.wantProto)
			}
			if tt.proto == 1 && l4[0] != 129 {
				t.Errorf("echo reply type %d; want 129", l4[0])
			}
		})
	}
}

func TestXlatDrops(t *testing.T) {
	b := newTestBackend(t)
	client := netip.MustParseAddr("fd7a:115c:a1e0::2")
	siteAddr, _ := tsaddr.MapVia(0x1790, netip.PrefixFrom(lanHost, 32)) // a via address the DNAT has not rewritten

	zeroUDP6 := packet6(cfg.X6(), canon(lanHost), 17, udpDgram(1, 2, []byte("x")))
	zeroUDP6[14+40+6], zeroUDP6[14+40+7] = 0, 0
	zeroUDP4 := packet4(lanHost, cfg.X4, 17, udpDgram(2, 1, []byte("x")))
	zeroUDP4[14+20+6], zeroUDP4[14+20+7] = 0, 0
	mf := packet4(lanHost, cfg.X4, 1, icmpMsg(0, 7, 1, []byte("pong"))) // fragmented ICMP cannot be translated statelessly
	binary.BigEndian.PutUint16(mf[14+6:], 0x2000)                       // More Fragments
	mf[14+10], mf[14+11] = 0, 0
	binary.BigEndian.PutUint16(mf[14+10:], fold(csum(mf[14:14+20], 0)))
	opts := packet4(lanHost, cfg.X4, 6, tcpSeg(2, 1, nil))
	opts[14] = 0x46

	tests := []struct {
		name    string
		prog    *ebpf.Program
		pkt     []byte
		counter string
	}{
		{"6to4-not-dnated", b.objs.Xlat6to4, packet6(cfg.X6(), siteAddr.Addr(), 6, tcpSeg(1, 2, nil)), "drop_not_ours"},
		{"6to4-source-not-nat66", b.objs.Xlat6to4, packet6(client, canon(lanHost), 6, tcpSeg(1, 2, nil)), "drop_bad_src"},
		{"6to4-to-x4", b.objs.Xlat6to4, packet6(cfg.X6(), cfg.X6(), 6, tcpSeg(1, 2, nil)), "drop_x4_dst"},
		{"6to4-icmp-fragment", b.objs.Xlat6to4, fragments6(packet6(cfg.X6(), canon(lanHost), 58, icmpMsg(128, 7, 1, make([]byte, 64))), 32, 1)[0], "drop_frag"},
		{"6to4-icmp-error", b.objs.Xlat6to4, packet6(cfg.X6(), canon(lanHost), 58, icmpMsg(1, 0, 0, nil)), "drop_icmp_unsupported"},
		{"6to4-udp-zero-checksum", b.objs.Xlat6to4, zeroUDP6, "drop_udp_zero_csum"},
		{"4to6-not-x4", b.objs.Xlat4to6, packet4(lanHost, netip.MustParseAddr("192.0.0.2"), 6, tcpSeg(2, 1, nil)), "drop_not_ours"},
		{"4to6-fragment", b.objs.Xlat4to6, mf, "drop_frag"},
		{"4to6-options", b.objs.Xlat4to6, opts, "drop_options"},
		{"4to6-icmp-error-without-quote", b.objs.Xlat4to6, packet4(lanHost, cfg.X4, 1, icmpMsg(3, 0, 0, nil)), "drop_short"},
		{"4to6-udp-zero-checksum", b.objs.Xlat4to6, zeroUDP4, "drop_udp_zero_csum"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := counters(t, b)[tt.counter]
			if ret, _ := run(t, tt.prog, tt.pkt); ret != tcActShot {
				t.Fatalf("verdict %d; want TC_ACT_SHOT", ret)
			}
			if after := counters(t, b)[tt.counter]; after != before+1 {
				t.Errorf("%s went %d -> %d; want +1 (all counters: %v)", tt.counter, before, after, counters(t, b))
			}
		})
	}
}

// TestXlatFragments translates both fragments of a TCP segment and of a UDP datagram each way, checking the checksum over the reassembled packet.
func TestXlatFragments(t *testing.T) {
	b := newTestBackend(t)
	payload := make([]byte, 2000)
	for i := range payload {
		payload[i] = byte(i)
	}
	for _, tc := range []struct {
		name  string
		proto uint8
		hlen  int
		seg   func(sport, dport uint16, payload []byte) []byte
	}{
		{"udp", 17, 8, udpDgram},
		{"tcp", 6, 20, tcpSeg},
	} {
		t.Run(tc.name+"-6to4", func(t *testing.T) {
			whole := packet6(cfg.X6(), canon(lanHost), tc.proto, tc.seg(40000, 53, payload))
			var l4 []byte
			for i, f := range fragments6(whole, 1232, 0x12345678) {
				ret, out := run(t, b.objs.Xlat6to4, f)
				if ret != tcActOK {
					t.Fatalf("fragment %d: verdict %d; counters %v", i, ret, counters(t, b))
				}
				ip := out[14:]
				n := int(binary.BigEndian.Uint16(ip[2:])) - 20
				if binary.BigEndian.Uint16(out[12:]) != 0x0800 || ip[0] != 0x45 || ip[9] != tc.proto || fold(csum(ip[:20], 0)) != 0 {
					t.Fatalf("fragment %d: not a valid IPv4 header: % x", i, ip[:20])
				}
				if id := binary.BigEndian.Uint16(ip[4:]); id != 0x5678 {
					t.Errorf("fragment %d: ID %#x; want 0x5678, the low bits of the IPv6 identification", i, id)
				}
				frag := binary.BigEndian.Uint16(ip[6:])
				wantMF := i == 0
				if frag&0x4000 != 0 || (frag&0x2000 != 0) != wantMF || int(frag&0x1fff)*8 != len(l4) {
					t.Errorf("fragment %d: flags/offset %#x; want MF %v, offset %d, no DF", i, frag, wantMF, len(l4))
				}
				if netip.AddrFrom4([4]byte(ip[12:16])) != cfg.X4 || netip.AddrFrom4([4]byte(ip[16:20])) != lanHost {
					t.Errorf("fragment %d: addresses % x", i, ip[12:20])
				}
				l4 = append(l4, ip[20:20+n]...)
			}
			if len(l4) != tc.hlen+len(payload) || fold(csum(l4, pseudo4(cfg.X4, lanHost, tc.proto, len(l4)))) != 0 {
				t.Errorf("reassembled packet: %d bytes, bad L4 checksum or length", len(l4))
			}
		})
		t.Run(tc.name+"-4to6", func(t *testing.T) {
			whole := packet4(lanHost, cfg.X4, tc.proto, tc.seg(53, 40000, payload))
			var l4 []byte
			for i, f := range fragments4(whole, 1232, 0xabcd) {
				ret, out := run(t, b.objs.Xlat4to6, f)
				if ret != tcActOK {
					t.Fatalf("fragment %d: verdict %d; counters %v", i, ret, counters(t, b))
				}
				ip := out[14:]
				plen := int(binary.BigEndian.Uint16(ip[4:]))
				if binary.BigEndian.Uint16(out[12:]) != 0x86dd || ip[0]>>4 != 6 || ip[6] != 44 {
					t.Fatalf("fragment %d: not an IPv6 fragment: % x", i, ip[:8])
				}
				if netip.AddrFrom16([16]byte(ip[8:24])) != canon(lanHost) || netip.AddrFrom16([16]byte(ip[24:40])) != cfg.X6() {
					t.Errorf("fragment %d: addresses % x", i, ip[8:40])
				}
				fh := ip[40:48]
				offlg := binary.BigEndian.Uint16(fh[2:])
				wantM := i == 0
				if fh[0] != tc.proto || (offlg&1 != 0) != wantM || int(offlg&^7) != len(l4) || binary.BigEndian.Uint32(fh[4:]) != 0xabcd {
					t.Errorf("fragment %d: fragment header % x; want next header %d, M %v, offset %d, ID 0xabcd", i, fh, tc.proto, wantM, len(l4))
				}
				l4 = append(l4, ip[48:40+plen]...)
			}
			if len(l4) != tc.hlen+len(payload) || fold(csum(l4, pseudo6(canon(lanHost), cfg.X6(), tc.proto, len(l4)))) != 0 {
				t.Errorf("reassembled packet: %d bytes, bad L4 checksum or length", len(l4))
			}
		})
	}
	t.Run("tcp-first-fragment-too-short", func(t *testing.T) {
		// A first fragment that ends inside the TCP header leaves no checksum to update: dropped, never read past the end.
		f := fragments6(packet6(cfg.X6(), canon(lanHost), 6, tcpSeg(40000, 5201, payload)), 8, 1)[0]
		if ret, _ := run(t, b.objs.Xlat6to4, f); ret != tcActShot {
			t.Errorf("verdict %d; want TC_ACT_SHOT", ret)
		}
	})
}

// TestXlatICMPErrors covers xlat_icmp4_error.
func TestXlatICMPErrors(t *testing.T) {
	b := newTestBackend(t)
	router := netip.MustParseAddr("10.1.0.1")
	syn := packet4(cfg.X4, lanHost, 6, tcpSeg(40000, 5201, nil))
	dgram := packet4(cfg.X4, lanHost, 17, udpDgram(40000, 53, []byte("query")))
	tests := []struct {
		name               string
		typ, code          uint8
		mtu                uint16
		quoted             []byte
		wantType, wantCode uint8
		wantMTU            uint32
	}{
		{"host-unreachable", 3, 1, 0, syn, 1, 0, 0},
		{"net-unreachable", 3, 0, 0, syn, 1, 0, 0},
		{"port-unreachable", 3, 3, 0, dgram, 1, 4, 0},
		{"admin-prohibited", 3, 13, 0, syn, 1, 1, 0},
		{"fragmentation-needed", 3, 4, 1400, syn, 2, 0, 1420},
		{"fragmentation-needed-small-mtu", 3, 4, 576, syn, 2, 0, 1280},
		{"time-exceeded", 11, 0, 0, dgram, 3, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := counters(t, b)["icmp_err_ok"]
			ret, out := run(t, b.objs.Xlat4to6, packet4(router, cfg.X4, 1, icmp4Error(tt.typ, tt.code, tt.mtu, tt.quoted)))
			if ret != tcActOK {
				t.Fatalf("verdict %d; counters %v", ret, counters(t, b))
			}
			src, dst, proto, _, l4 := parse6(t, out) // checks the ICMPv6 checksum
			if src != canon(router) || dst != cfg.X6() || proto != 58 {
				t.Errorf("outer %v -> %v proto %d; want %v -> %v proto 58", src, dst, proto, canon(router), cfg.X6())
			}
			if l4[0] != tt.wantType || l4[1] != tt.wantCode || binary.BigEndian.Uint32(l4[4:]) != tt.wantMTU {
				t.Errorf("type %d code %d mtu %d; want %d, %d, %d", l4[0], l4[1], binary.BigEndian.Uint32(l4[4:]), tt.wantType, tt.wantCode, tt.wantMTU)
			}
			inner := l4[8:]
			qproto := tt.quoted[14+9]
			isrc, idst := netip.AddrFrom16([16]byte(inner[8:24])), netip.AddrFrom16([16]byte(inner[24:40]))
			if inner[0]>>4 != 6 || inner[6] != qproto || isrc != cfg.X6() || idst != canon(lanHost) {
				t.Fatalf("quoted header % x; want IPv6 %v -> %v proto %d", inner[:40], cfg.X6(), canon(lanHost), qproto)
			}
			qpay := inner[40:]
			if n := int(binary.BigEndian.Uint16(inner[4:])); n != len(qpay) {
				t.Errorf("quoted payload length %d; want %d", n, len(qpay))
			}
			if fold(csum(qpay, pseudo6(isrc, idst, qproto, len(qpay)))) != 0 {
				t.Error("bad checksum in the quoted packet")
			}
			if !bytes.Equal(qpay[:4], tt.quoted[14+20:14+24]) {
				t.Errorf("quoted ports % x; want % x", qpay[:4], tt.quoted[14+20:14+24])
			}
			if after := counters(t, b)["icmp_err_ok"]; after != before+1 {
				t.Errorf("icmp_err_ok went %d -> %d", before, after)
			}
		})
	}
	for _, tt := range []struct {
		name    string
		pkt     []byte
		counter string
	}{
		{"protocol-unreachable", packet4(router, cfg.X4, 1, icmp4Error(3, 2, 0, syn)), "drop_icmp_unsupported"},
		{"about-a-ping", packet4(router, cfg.X4, 1, icmp4Error(3, 1, 0, packet4(cfg.X4, lanHost, 1, icmpMsg(8, 7, 1, nil)))), "drop_icmp_unsupported"},
		{"about-someone-else", packet4(router, cfg.X4, 1, icmp4Error(3, 1, 0, packet4(router, lanHost, 6, tcpSeg(1, 2, nil)))), "drop_not_ours"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := counters(t, b)[tt.counter]
			if ret, _ := run(t, b.objs.Xlat4to6, tt.pkt); ret != tcActShot {
				t.Fatalf("verdict %d; want TC_ACT_SHOT", ret)
			}
			if after := counters(t, b)[tt.counter]; after != before+1 {
				t.Errorf("%s went %d -> %d; want +1 (all counters: %v)", tt.counter, before, after, counters(t, b))
			}
		})
	}
}

// TestXlatICMPErrorSizeLimit checks that ICMPv4 errors up to 1240 bytes, which fill 1280 bytes as ICMPv6 (RFC 4443 2.4(c)), are translated.
func TestXlatICMPErrorSizeLimit(t *testing.T) {
	b := newTestBackend(t)
	router := netip.MustParseAddr("10.1.0.1")
	for _, tc := range []struct {
		tot  int
		want uint32
	}{{1240, tcActOK}, {1241, tcActShot}} {
		quoted := packet4(cfg.X4, lanHost, 17, udpDgram(40000, 53, make([]byte, tc.tot-56)))
		pkt := packet4(router, cfg.X4, 1, icmp4Error(3, 1, 0, quoted))
		if got := len(pkt) - 14; got != tc.tot {
			t.Fatalf("built a %d-byte error; want %d", got, tc.tot)
		}
		if ret, _ := run(t, b.objs.Xlat4to6, pkt); ret != tc.want {
			t.Errorf("%d-byte ICMPv4 error: verdict %d; want %d", tc.tot, ret, tc.want)
		}
	}
}

// counterNames must match enum counter in xlat.c, in order.
var counterNames = []string{
	"6to4_ok", "4to6_ok", "drop_not_ip", "drop_short", "drop_not_ours", "drop_bad_src", "drop_x4_dst",
	"drop_proto", "drop_icmp_unsupported", "drop_udp_zero_csum", "drop_options", "drop_frag", "drop_helper",
	"icmp_err_ok",
}

// Counters returns the translator's packet counters, summed over CPUs.
func (b *backend) Counters() (map[string]uint64, error) {
	out := make(map[string]uint64, len(counterNames))
	for i, name := range counterNames {
		var perCPU []uint64
		if err := b.objs.Counters.Lookup(uint32(i), &perCPU); err != nil {
			return nil, err
		}
		var sum uint64
		for _, n := range perCPU {
			sum += n
		}
		out[name] = sum
	}
	return out, nil
}
