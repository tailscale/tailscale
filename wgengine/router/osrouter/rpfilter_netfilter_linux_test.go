// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package osrouter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/net/netmon"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/router"
)

// netfilterChildEnv marks a re-executed TestUnderlaySrcRulesNetfilter*
// process running inside a private network namespace.
const netfilterChildEnv = "TS_TEST_RPFILTER_NETFILTER_CHILD"

// runNetfilterTest runs child in a private network namespace, as root, with
// the nft command available, re-executing the test binary for it.
func runNetfilterTest(t *testing.T, child func(*testing.T)) {
	if os.Getenv(netfilterChildEnv) == "" {
		tstest.RequireRoot(t)
		if _, err := exec.LookPath("nft"); err != nil {
			t.Skip("no nft command")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
		cmd.Env = append(os.Environ(), netfilterChildEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		out, err := cmd.CombinedOutput()
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skipf("can't create network namespace: %v", err)
			}
			t.Fatalf("netns child failed: %v\n%s", err, out)
		}
		t.Logf("netns child output:\n%s", out)
		return
	}
	child(t)
}

// TestUnderlaySrcRulesNetfilterV6 checks, with real packets against the real
// kernel, that the IPv6 underlay rules let replies to an underlay address
// through a netfilter reverse path filter while an exit node's ::/0 is in
// table 52.
//
// IPv6 has no kernel rp_filter, so IPv6's reverse path checks are netfilter
// ones, like firewalld's default IPv6_rpfilter: nftables "fib saddr . iif oif
// missing drop". That lookup runs through the ip rules as uid 0, so without
// our rules it finds table 52's ::/0 via the Tailscale interface, not the
// interface the reply came in on, and drops it. TestUnderlaySrcRulesKernel
// checks the IPv6 rules' routing decisions but stubs netfilter out; this is
// the end-to-end check for IPv6 that its replyPasses is for IPv4.
func TestUnderlaySrcRulesNetfilterV6(t *testing.T) {
	runNetfilterTest(t, func(t *testing.T) {
		e := newNetfilterRPFEnv(t, v6)
		defer e.close()

		// The filter itself works: with only main's default route, a
		// reply from the Internet arriving on ul0 is fine.
		if !e.sendReply() {
			t.Fatal("before using an exit node: reply dropped; the rpfilter rule is broken")
		}

		// Exit node on, address source disabled so there are no underlay
		// rules: the filter's lookup finds ::/0 via the Tailscale
		// interface and the reply is dropped. This is the bug, for IPv6.
		setTestUnderlayAddrs(e.lr, nil)
		e.set(e.cfg)
		if got := kernelUnderlayRules(t, e.lr); len(got) != 0 {
			t.Fatalf("unexpected rules with address source disabled: %v", got)
		}
		if e.sendReply() {
			t.Fatal("exit node on, no underlay rules: reply passed; the topology doesn't reproduce the bug for IPv6")
		}

		// With the rules, the same reply passes.
		e.useNetMonAddrs()
		if !e.sendReply() {
			t.Fatal("exit node on, with underlay rules: reply dropped")
		}

		e.checkExitNodeOff()
	})
}

// TestUnderlaySrcRulesNetfilterV4 is TestUnderlaySrcRulesNetfilterV6 for
// IPv4: the same netfilter reverse path check, with IPv4 replies.
//
// Unlike the IPv6 rules, the IPv4 rules are only installed while the
// kernel's IPv4 rp_filter is strict, so with a netfilter check alone (kernel
// rp_filter loose) the reply is still dropped. That is pinned here as a known
// limitation, so that a change to it is deliberate. Once rp_filter is strict
// the rules are installed (by the router's periodic recheck, with no Set or
// network change), and they satisfy the netfilter check and the kernel's
// strict rp_filter together.
func TestUnderlaySrcRulesNetfilterV4(t *testing.T) {
	runNetfilterTest(t, func(t *testing.T) {
		e := newNetfilterRPFEnv(t, v4)
		defer e.close()
		rpFilter := func(mode string) {
			t.Helper()
			for _, k := range []string{"all", "default", "ul0"} {
				e.sysctl("net.ipv4.conf."+k+".rp_filter", mode)
			}
		}

		rpFilter("2") // loose: only the netfilter check is strict
		if !e.sendReply() {
			t.Fatal("before using an exit node: reply dropped; the rpfilter rule is broken")
		}

		// Exit node on with a loose kernel rp_filter: no IPv4 rules, and
		// the netfilter check drops the reply.
		e.useNetMonAddrs()
		e.set(e.cfg)
		if got := kernelUnderlayRules(t, e.lr); slices.ContainsFunc(got, netip.Addr.Is4) {
			t.Fatalf("IPv4 rules %v with loose rp_filter; want none", got)
		}
		if e.sendReply() {
			t.Fatal("loose rp_filter, netfilter check: reply passed without IPv4 rules; " +
				"if the IPv4 rules are now installed regardless of rp_filter, turn this into a pass and update the commit message")
		}

		// Strict: the recheck installs the rules, and the reply passes
		// both the netfilter check and the kernel's rp_filter.
		rpFilter("1")
		waitForTimers(t, &e.timers, "IPv4 rules after rp_filter went strict", func() bool {
			return slices.Contains(kernelUnderlayRules(t, e.lr), e.local)
		})
		if !e.sendReply() {
			t.Fatal("strict rp_filter, with underlay rules: reply dropped")
		}

		e.checkExitNodeOff()
	})
}

// netfilterRPFEnv is a network namespace set up for the netfilter reverse
// path tests: an underlay NIC ul0 with one address of a family and a
// default route, an nftables reverse path filter on it, a socket on that
// address, and a router on a real TUN. Replies are injected with AF_PACKET
// on ulp, the other end of ul0's veth pair, so they arrive on ul0 as if from
// the network, and go through netfilter and the input path.
type netfilterRPFEnv struct {
	t             *testing.T
	fam           addrFamily
	local, remote netip.Addr
	lr            *linuxRouter
	timers        routerTimers
	cfg, noExit   *router.Config

	pc      *net.UDPConn
	inj     *ethInjector
	seq     int
	closers []func()
}

const (
	nfListenPort = 41641 // the reply's destination: one of our sockets
	nfRemotePort = 3478
)

func newNetfilterRPFEnv(t *testing.T, fam addrFamily) *netfilterRPFEnv {
	e := &netfilterRPFEnv{t: t, fam: fam}
	var prefix netip.Prefix
	var gw netip.Addr
	if fam == v4 {
		prefix = netip.MustParsePrefix("172.31.0.44/20")
		gw = netip.MustParseAddr("172.31.0.1")
		e.remote = netip.MustParseAddr("1.2.3.4") // exit node / DERP underlay
	} else {
		prefix = netip.MustParsePrefix("2001:db8:1::44/64")
		gw = netip.MustParseAddr("2001:db8:1::1")
		e.remote = netip.MustParseAddr("2001:db8:ffff::1234")
	}
	e.local = prefix.Addr()

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "ul0"}, PeerName: "ulp"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("can't create veth pair (no veth module?): %v", err)
	}
	ul, err := netlink.LinkByName("ul0")
	if err != nil {
		t.Fatal(err)
	}
	ulp, err := netlink.LinkByName("ulp")
	if err != nil {
		t.Fatal(err)
	}
	// ulp is only a wire: keep it out of IPv6 (and so out of netmon's
	// underlay addresses and the routing table). It never gets an IPv4
	// address.
	e.sysctl("net.ipv6.conf.ulp.disable_ipv6", "1")
	e.sysctl("net.ipv6.conf.ul0.disable_ipv6", "0")
	e.sysctl("net.ipv6.conf.ul0.accept_dad", "0")
	for _, l := range []netlink.Link{ul, ulp} {
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
	}
	if err := netlink.AddrAdd(ul, &netlink.Addr{IPNet: netipx.PrefixIPNet(prefix)}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: ul.Attrs().Index, Gw: gw.AsSlice()}); err != nil {
		t.Fatalf("default via %v: %v", gw, err)
	}

	// A reverse path filter like firewalld's IPv6_rpfilter, for this
	// family, scoped to the test's replies. The second counter shows the
	// packets that got through it.
	nfproto := map[addrFamily]string{v4: "ipv4", v6: "ipv6"}[fam]
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewReader(fmt.Appendf(nil, `
table inet rpftest {
	chain pre {
		type filter hook prerouting priority raw; policy accept;
		iifname "ul0" meta nfproto %[1]s udp dport %[2]d fib saddr . iif oif missing counter drop comment "rpf-drop"
		iifname "ul0" meta nfproto %[1]s udp dport %[2]d counter comment "rpf-pass"
	}
}
`, nfproto, nfListenPort))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("can't install nftables fib rule (no nf_tables / nft_fib?): %v\n%s", err, out)
	}

	network := map[addrFamily]string{v4: "udp4", v6: "udp6"}[fam]
	e.pc, err = net.ListenUDP(network, &net.UDPAddr{IP: e.local.AsSlice(), Port: nfListenPort})
	if err != nil {
		t.Fatal(err)
	}
	e.closers = append(e.closers, func() { e.pc.Close() })
	e.inj, err = newEthInjector(ulp, ul.Attrs().HardwareAddr)
	if err != nil {
		t.Fatal(err)
	}
	e.closers = append(e.closers, func() { e.inj.Close() })

	tunDev := createTestTUN(t)
	e.closers = append(e.closers, func() { tunDev.Close() })
	bus := eventbus.New()
	e.closers = append(e.closers, bus.Close)
	mon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	mon.Start()
	e.closers = append(e.closers, func() { mon.Close() })
	tunName, err := tunDev.Name()
	if err != nil {
		t.Fatal(err)
	}
	e.lr = newTestRouter(t.Logf, tunName, mon, osCommandRunner{}, nil, bus, func(r *linuxRouter) {
		r.nfr = NewFakeOS(t).nfr // the router's own netfilter isn't under test
		r.interfaceV6Usable = func() bool { return true }
		r.afterFunc = e.timers.afterFunc
	})
	if err := e.lr.Up(); err != nil {
		t.Fatal(err)
	}
	e.closers = append(e.closers, func() { e.lr.Close() })
	// The address source stays off until useNetMonAddrs.
	setTestUnderlayAddrs(e.lr, nil)

	e.cfg = &router.Config{
		LocalAddrs:    mustCIDRs("100.101.102.104/32", "fd7a:115c:a1e0::104/128"),
		Routes:        mustCIDRs("100.64.0.0/10", "fd7a:115c:a1e0::/48", "0.0.0.0/0", "::/0"),
		NetfilterMode: netfilterOff,
	}
	e.noExit = &router.Config{
		LocalAddrs:    e.cfg.LocalAddrs,
		Routes:        mustCIDRs("100.64.0.0/10", "fd7a:115c:a1e0::/48"),
		NetfilterMode: netfilterOff,
	}
	return e
}

func (e *netfilterRPFEnv) close() {
	for _, f := range slices.Backward(e.closers) {
		f()
	}
}

func (e *netfilterRPFEnv) sysctl(k, v string) {
	e.t.Helper()
	if err := writeSysctl(k, v); err != nil {
		e.t.Fatal(err)
	}
}

func (e *netfilterRPFEnv) set(cfg *router.Config) {
	e.t.Helper()
	if err := e.lr.Set(cfg); err != nil {
		e.t.Fatal(err)
	}
}

// useNetMonAddrs switches the router's address source to the real netmon
// state and reconciles, which installs rules for ul0's address if they're
// wanted.
func (e *netfilterRPFEnv) useNetMonAddrs() {
	e.lr.mu.Lock()
	e.lr.underlayAddrs = e.lr.underlayAddrsFromNetMon
	e.lr.mu.Unlock()
	e.lr.onNetworkChange()
}

func (e *netfilterRPFEnv) counter(name string) int {
	e.t.Helper()
	out, err := exec.Command("nft", "list", "chain", "inet", "rpftest", "pre").CombinedOutput()
	if err != nil {
		e.t.Fatalf("nft list: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`counter packets (\d+) bytes \d+ .*comment "` + name + `"`).FindSubmatch(out)
	if m == nil {
		e.t.Fatalf("no %q counter in:\n%s", name, out)
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

// sendReply injects a reply from e.remote to our socket and reports whether
// netfilter passed it or dropped it, having waited for the kernel to account
// for it one way or the other. A passed reply must also reach the socket.
func (e *netfilterRPFEnv) sendReply() (passed bool) {
	t := e.t
	t.Helper()
	e.seq++
	drops, passes := e.counter("rpf-drop"), e.counter("rpf-pass")
	payload := fmt.Appendf(nil, "reply %d", e.seq)
	if err := e.inj.sendUDP(e.remote, e.local, nfRemotePort, nfListenPort, payload); err != nil {
		t.Fatal(err)
	}
	waitFor(t, fmt.Sprintf("reply %d to be filtered", e.seq), func() bool {
		return e.counter("rpf-drop") > drops || e.counter("rpf-pass") > passes
	})
	if e.counter("rpf-drop") > drops {
		return false
	}
	e.pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, from, err := e.pc.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("reply %d passed netfilter but wasn't delivered: %v", e.seq, err)
	}
	if got := string(buf[:n]); got != string(payload) || from.Addr().Unmap() != e.remote {
		t.Fatalf("socket got %q from %v; want %q from %v", got, from, payload, e.remote)
	}
	return true
}

// checkExitNodeOff checks that with the exit node off the rules go, and with
// table 52 no longer claiming the default route the reply still passes.
func (e *netfilterRPFEnv) checkExitNodeOff() {
	t := e.t
	t.Helper()
	e.set(e.noExit)
	if got := kernelUnderlayRules(t, e.lr); len(got) != 0 {
		t.Fatalf("after exit node off: rules %v remain", got)
	}
	if !e.sendReply() {
		t.Fatal("after exit node off: reply dropped")
	}
}

// ethInjector writes Ethernet frames out of a link with AF_PACKET. Written
// to one end of a veth pair, they arrive on the other end as received
// traffic, going through netfilter and the input path like a packet from
// the network.
type ethInjector struct {
	fd     int
	srcMAC net.HardwareAddr
	dstMAC net.HardwareAddr
	ifidx  int
}

func newEthInjector(out netlink.Link, dstMAC net.HardwareAddr) (*ethInjector, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}
	return &ethInjector{
		fd:     fd,
		srcMAC: out.Attrs().HardwareAddr,
		dstMAC: dstMAC,
		ifidx:  out.Attrs().Index,
	}, nil
}

func (e *ethInjector) Close() error { return unix.Close(e.fd) }

// sendUDP injects a UDP packet from src:sport to dst:dport, over IPv4 or
// IPv6 according to the addresses.
func (e *ethInjector) sendUDP(src, dst netip.Addr, sport, dport uint16, payload []byte) error {
	const ethLen, udpLen = 14, 8
	ipLen, etherType := 40, uint16(unix.ETH_P_IPV6)
	if src.Is4() {
		ipLen, etherType = 20, unix.ETH_P_IP
	}
	frame := make([]byte, ethLen+ipLen+udpLen+len(payload))

	copy(frame[0:6], e.dstMAC)
	copy(frame[6:12], e.srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherType)

	ip, udp := frame[ethLen:ethLen+ipLen], frame[ethLen+ipLen:]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen+len(payload)))
	copy(udp[udpLen:], payload)

	if src.Is4() {
		ip[0] = 4<<4 | 5 // version 4, 20-byte header
		binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen+udpLen+len(payload)))
		ip[8] = 64 // TTL
		ip[9] = unix.IPPROTO_UDP
		s4, d4 := src.As4(), dst.As4()
		copy(ip[12:16], s4[:])
		copy(ip[16:20], d4[:])
		binary.BigEndian.PutUint16(ip[10:12], inetChecksum(0, ip))
		// The UDP checksum is optional for IPv4; zero means none.
	} else {
		ip[0] = 6 << 4 // version 6, traffic class 0, flow label 0
		binary.BigEndian.PutUint16(ip[4:6], uint16(udpLen+len(payload)))
		ip[6] = unix.IPPROTO_UDP
		ip[7] = 64 // hop limit
		s16, d16 := src.As16(), dst.As16()
		copy(ip[8:24], s16[:])
		copy(ip[24:40], d16[:])
		// Mandatory for IPv6 (RFC 8200 section 8.1), over a
		// pseudo-header of the addresses, length and protocol.
		sum := inetSum(inetSum(0, s16[:]), d16[:]) + uint32(len(udp)) + unix.IPPROTO_UDP
		cs := inetChecksum(sum, udp)
		if cs == 0 {
			cs = 0xffff // 0 means "no checksum", which IPv6 forbids
		}
		binary.BigEndian.PutUint16(udp[6:8], cs)
	}

	sa := &unix.SockaddrLinklayer{
		Ifindex:  e.ifidx,
		Protocol: htons(etherType),
		Halen:    6,
	}
	copy(sa.Addr[:], e.dstMAC)
	return unix.Sendto(e.fd, frame, 0, sa)
}

// inetSum adds b to the running one's complement sum, as 16-bit words.
func inetSum(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

// inetChecksum returns the Internet checksum (RFC 1071) of b, starting from
// the partial sum sum.
func inetChecksum(sum uint32, b []byte) uint16 {
	sum = inetSum(sum, b)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
