// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/mds/shell"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestPeerAPINotReachableFromLAN checks that a host sharing a LAN with a
// Linux tailscaled node cannot complete a TCP handshake with the node's
// kernel-level peerapi listener by addressing the node's Tailscale IP,
// while everything that should reach that IP still does.
//
// Linux delivers packets addressed to the node's own Tailscale IP via
// INPUT from any interface (weak host model), so unless the peerapi
// listener is bound to the tunnel interface (initListenConfigTun in
// ipn/ipnlocal), any LAN-adjacent host can confirm that a machine's MAC
// address belongs to a given tailnet identity: the peerapi port is
// derived from the Tailscale IP, and the kernel used to answer SYNs
// with a SYN-ACK before tailscaled ever saw a byte.
//
// The target also runs the test agent's webserver on all interfaces
// with no device bind. The attacker must be able to reach that server
// on the same Tailscale IP, which proves the weak-host path works and
// that the peerapi refusal comes from the device bind rather than from
// a broken setup.
func TestPeerAPINotReachableFromLAN(t *testing.T) {
	testPeerAPINotReachableFromLAN(t, vmtest.Ubuntu2404)
}

// TestPeerAPINotReachableFromLAN_FreeBSD is the FreeBSD counterpart of
// TestPeerAPINotReachableFromLAN. FreeBSD is a weak-host stack too, but
// has no per-socket interface bind, so tailscaled with netstack compiled
// in creates no kernel peerapi listener at all
// (peerAPIServer.skipKernelListener in ipn/ipnlocal) and serves peers
// only through netstack. The test checks that no kernel socket listens
// on the Tailscale IP, that a SYN from a LAN-adjacent host to the
// advertised peerapi port draws no SYN-ACK, and that peers still reach
// peerapi.
func TestPeerAPINotReachableFromLAN_FreeBSD(t *testing.T) {
	testPeerAPINotReachableFromLAN(t, vmtest.FreeBSD150)
}

func testPeerAPINotReachableFromLAN(t *testing.T, targetOS vmtest.OSImage) {
	env := vmtest.New(t, vmtest.SameTailnetUser(), vmtest.AllOnline())

	// The shared LAN. It needs a WAN IP so the target can reach the
	// control server and DERP. The attacker shares this LAN but is not
	// on the tailnet.
	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)

	// The target runs tailscaled in tun mode. On Linux it uses the stock
	// systemd unit, so peerapi binds a real kernel socket on the node's
	// Tailscale IP exactly as it does for package installs.
	targetOpts := []any{
		lan,
		vmtest.OS(targetOS),
		vmtest.WebServer(9999),
	}
	if targetOS.GOOS() == "linux" {
		targetOpts = append(targetOpts, vmtest.SystemdUnit())
	}
	target := env.AddNode("target", targetOpts...)

	// A second tailnet node sends the target a Taildrop file at the
	// end, proving peerapi still serves real peers with the device bind
	// in place.
	peer := env.AddNode("peer",
		env.AddNetwork("3.1.1.1", "192.168.2.1/24", vnet.EasyNAT),
		vmtest.OS(vmtest.Gokrazy))

	// The attacker shares the target's LAN but is not on the tailnet.
	attacker := env.AddNode("attacker", lan,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.DontJoinTailnet())

	env.Start()

	st := env.Status(target)
	var tsIP netip.Addr
	for _, ip := range st.Self.TailscaleIPs {
		if ip.Is4() {
			tsIP = ip
			break
		}
	}
	if !tsIP.IsValid() {
		t.Fatalf("target has no IPv4 Tailscale IP: %v", st.Self.TailscaleIPs)
	}
	peerAPI := peerAPIAddrPort(t, st.Self.PeerAPIURL)
	if peerAPI.Addr() != tsIP {
		t.Fatalf("peerapi URL %v does not match Tailscale IP %v", peerAPI, tsIP)
	}

	// Check the kernel side of the fix directly, so that a failure names
	// the cause rather than being inferred from the attacker's probe
	// below. The two platforms differ in what the fix looks like.
	switch targetOS.GOOS() {
	case "linux":
		checkLinuxPeerAPIListenerBoundToTun(t, env, target, peerAPI)
	case "freebsd":
		checkFreeBSDNoKernelPeerAPIListener(t, env, target, peerAPI)
	default:
		t.Fatalf("unsupported target OS %q", targetOS.GOOS())
	}

	// Route the target's Tailscale IP at the target's LAN IP. The
	// attacker now delivers SYNs to the target's NIC with the
	// Tailscale IP as the destination, standing in for the crafted
	// Ethernet frames of a LAN-adjacent attacker.
	env.AddRoute(attacker, tsIP.String()+"/32", target.LanIP(lan).String())

	// The oracle under test is the SYN-ACK: the attacker learns that the
	// machine at this MAC address owns this Tailscale IP the moment the
	// kernel answers a SYN to the peerapi port, so the probes below watch
	// for SYN-ACKs on the attacker's NIC rather than for a completed
	// connection. On FreeBSD that distinction matters: tailscaled's pf
	// source NAT rule for Tailscale addresses leaving non-Tailscale
	// interfaces rewrites the source of the kernel's SYN-ACK to the LAN
	// IP and a random port, so the attacker's kernel resets it and a
	// connect() never completes, but the SYN-ACK still leaked. The probe
	// accepts SYN-ACKs from either the Tailscale IP or the LAN IP.
	replySrcs := []netip.Addr{tsIP, target.LanIP(lan)}

	// Control: a listener on the same Tailscale IP without a device
	// bind answers the attacker. Without this, the missing peerapi
	// SYN-ACK below would not prove anything.
	controlAddr := netip.AddrPortFrom(tsIP, 9999)
	if synAck := synAckReceived(t, env, attacker, controlAddr, replySrcs, 40001); synAck == "" {
		t.Fatalf("no SYN-ACK from target for control probe to %s; the weak-host path is not working", controlAddr)
	} else {
		t.Logf("control probe to %s drew SYN-ACK: %s", controlAddr, synAck)
	}

	// The attack: a SYN to the peerapi port must draw no SYN-ACK.
	if synAck := synAckReceived(t, env, attacker, peerAPI, replySrcs, 40002); synAck != "" {
		t.Fatalf("attacker got a SYN-ACK from peerapi on %s: %s", peerAPI, synAck)
	}

	// On Linux, the target itself must still reach its own peerapi.
	// Local delivery to the Tailscale IP traverses the tunnel
	// interface, so the device bind must admit it. FreeBSD has no
	// kernel listener at all, so there is nothing for the local host
	// to connect to (as on Android).
	if targetOS.GOOS() == "linux" {
		if open := tcpConnectOpen(t, env, target, peerAPI); !open {
			t.Fatalf("target could not connect to its own peerapi on %s", peerAPI)
		}
	}

	// A real peer must still be able to use peerapi end to end.
	const fileName = "hello.txt"
	const fileBody = "hello world"
	env.SendTaildropFile(peer, target, fileName, []byte(fileBody))
	gotName, gotContent := env.RecvTaildropFile(t.Context(), target)
	if gotName != fileName || string(gotContent) != fileBody {
		t.Fatalf("Taildrop got %q (%d bytes); want %q (%d bytes)", gotName, len(gotContent), fileName, len(fileBody))
	}
}

// checkLinuxPeerAPIListenerBoundToTun checks that a kernel listener
// exists on the Linux target at peerAPI, bound to the tunnel interface.
//
// ss prints the socket's bound device after a % in the address. If the
// listen fell back to the netstack fake listener there would be no
// kernel socket at all, and the attacker would be refused for the wrong
// reason; if the device bind did not apply, the attacker would complete
// a handshake and the test would fail later, but asserting it here names
// the cause directly.
func checkLinuxPeerAPIListenerBoundToTun(t *testing.T, env *vmtest.Env, target *vmtest.Node, peerAPI netip.AddrPort) {
	t.Helper()
	listenerRe := regexp.MustCompile(`LISTEN\s+\d+\s+\d+\s+` +
		regexp.QuoteMeta(peerAPI.Addr().String()) + `(?:%(\S+))?:` +
		strconv.Itoa(int(peerAPI.Port())) + `\s`)
	var listenDev string
	if err := tstest.WaitFor(2*time.Minute, func() error {
		out, err := env.SSHExec(target, "ss -tln")
		if err != nil {
			return err
		}
		m := listenerRe.FindStringSubmatch(out)
		if m == nil {
			return fmt.Errorf("no kernel listener on %s in:\n%s", peerAPI, out)
		}
		listenDev = m[1]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The listener's existence is worth waiting for, but the device it is
	// bound to is fixed once it exists, so a wrong device is asserted
	// immediately rather than polled.
	switch {
	case listenDev == "":
		t.Fatalf("kernel listener on %s is not bound to a device (the peerapi tun bind did not apply)", peerAPI)
	case listenDev == "lo":
		t.Fatalf("kernel listener on %s is bound to loopback, not the tunnel interface", peerAPI)
	}
	t.Logf("target listens on %s, bound to %s", peerAPI, listenDev)
}

// checkFreeBSDNoKernelPeerAPIListener checks that the FreeBSD target has
// no kernel TCP listener on its Tailscale IP, nor a wildcard listener on
// the advertised peerapi port. With netstack compiled in, tailscaled
// skips the kernel listener on FreeBSD entirely and peers are served by
// netstack; a kernel socket here would mean that fallback is not in
// effect and the kernel would answer a LAN-adjacent host's SYN.
//
// The peerapi listeners are created before the peerapi URL is advertised
// in the node's status, so by the time the caller has peerAPI the
// listener state is settled and there is nothing to wait for.
func checkFreeBSDNoKernelPeerAPIListener(t *testing.T, env *vmtest.Env, target *vmtest.Node, peerAPI netip.AddrPort) {
	t.Helper()
	out, err := env.SSHExec(target, "sockstat -4 -l -P tcp")
	if err != nil {
		t.Fatalf("sockstat on target: %v\n%s", err, out)
	}
	tsIPPrefix := peerAPI.Addr().String() + ":"
	wildcard := "*:" + strconv.Itoa(int(peerAPI.Port()))
	for line := range strings.Lines(out) {
		// USER COMMAND PID FD PROTO LOCAL-ADDRESS FOREIGN-ADDRESS
		//
		// A dual-stack wildcard listener shows up as tcp46 and
		// accepts IPv4 too, so it counts alongside tcp4.
		f := strings.Fields(line)
		if len(f) < 6 || (f[4] != "tcp4" && f[4] != "tcp46") {
			continue
		}
		local := f[5]
		if strings.HasPrefix(local, tsIPPrefix) || local == wildcard {
			t.Fatalf("target has a kernel TCP listener on %s; want none on the Tailscale IP or peerapi port:\n%s", local, out)
		}
	}
	t.Logf("target has no kernel listener on %s; peerapi is served by netstack only", peerAPI)
}

// peerAPIAddrPort returns the address and port of the first IPv4 peerapi
// URL in urls, failing the test if there is none.
func peerAPIAddrPort(t *testing.T, urls []string) netip.AddrPort {
	t.Helper()
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("peerapi URL %q: %v", u, err)
		}
		host, portStr, err := net.SplitHostPort(parsed.Host)
		if err != nil {
			t.Fatalf("peerapi URL %q: %v", u, err)
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			t.Fatalf("peerapi URL %q: %v", u, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("peerapi URL %q: %v", u, err)
		}
		if ip.Is4() {
			return netip.AddrPortFrom(ip.Unmap(), uint16(port))
		}
	}
	t.Fatalf("no IPv4 peerapi URL in %v", urls)
	return netip.AddrPort{}
}

// synAckReceived sends a TCP SYN from the attacker node to addr and
// returns the tcpdump line of the SYN-ACK that came back, or "" if none
// arrived within a few seconds.
//
// It runs tcpdump on the attacker's interface toward addr, then drives
// the SYN with curl from the fixed local port localPort, so the capture
// filter matches exactly this probe's reply and not a retransmission
// from an earlier one. Replies are accepted from any address in
// replySrcs, since a pf source NAT rule on a FreeBSD target rewrites the
// SYN-ACK's source to the LAN IP. curl's own outcome does not matter;
// only the capture does.
//
// An empty capture is what a passing attack probe looks like, so the
// probe must not send the SYN until tcpdump is actually capturing. It
// waits for tcpdump's "listening on" line on stderr, which tcpdump
// prints only once the capture handle is active, and fails the test if
// that line never appears.
func synAckReceived(t *testing.T, env *vmtest.Env, attacker *vmtest.Node, addr netip.AddrPort, replySrcs []netip.Addr, localPort int) string {
	t.Helper()
	var srcs []string
	for _, ip := range replySrcs {
		srcs = append(srcs, "src host "+ip.String())
	}
	filter := fmt.Sprintf("tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack) and dst port %d and (%s)",
		localPort, strings.Join(srcs, " or "))
	probeURL := "http://" + addr.String() + "/"
	// --immediate-mode delivers each packet as it arrives rather than
	// after libpcap's buffer timeout, and the sleep after curl gives up
	// lets a late reply land before tcpdump is stopped.
	script := strings.Join([]string{
		"dev=$(ip -o route get " + addr.Addr().String() + " | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')",
		"tcpdump --immediate-mode -n -l -i \"$dev\" -c 1 " + shell.Quote(filter) + " >/tmp/synack.txt 2>/tmp/synack.err &",
		"tdpid=$!",
		"for i in $(seq 1 100); do grep -q 'listening on' /tmp/synack.err && break; sleep 0.1; done",
		"if ! grep -q 'listening on' /tmp/synack.err; then echo 'tcpdump did not start capturing:'; cat /tmp/synack.err; kill $tdpid 2>/dev/null; exit 1; fi",
		"curl -s --max-time 3 --local-port " + strconv.Itoa(localPort) + " " + shell.Quote(probeURL) + " >/dev/null 2>&1",
		"sleep 1",
		"kill $tdpid 2>/dev/null",
		"wait $tdpid 2>/dev/null",
		"cat /tmp/synack.txt",
	}, "\n")
	out, err := env.SSHExec(attacker, script)
	if err != nil {
		t.Fatalf("SYN-ACK probe to %s from %s: %v\n%s", addr, attacker.Name(), err, out)
	}
	return strings.TrimSpace(out)
}

// tcpConnectOpen reports whether a TCP connection from node to addr
// completes, printing an OPEN or CLOSED marker inside the VM. Only the
// kernel-level handshake matters, so the probe opens the connection and
// immediately closes it. bash prints the failed connection attempt
// (e.g. "Connection refused") before the marker, and a refused
// connection and a dropped SYN both report CLOSED, which is fine: the
// callers only care whether a handshake completes.
func tcpConnectOpen(t *testing.T, env *vmtest.Env, n *vmtest.Node, addr netip.AddrPort) (open bool) {
	t.Helper()
	// bash's special file form separates the port with a slash, not a
	// colon; with a colon it opens the literal path and the probe would
	// report CLOSED without ever connecting.
	target := addr.Addr().String() + "/" + strconv.Itoa(int(addr.Port()))
	cmd := "timeout 5 bash -c " + shell.Quote("</dev/tcp/"+target) + " && echo OPEN || echo CLOSED"
	out, err := env.SSHExec(n, cmd)
	if err != nil {
		t.Fatalf("TCP probe to %s from %s: %v\n%s", addr, n.Name(), err, out)
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		t.Fatalf("no output from TCP probe to %s from %s", addr, n.Name())
	}
	switch fields[len(fields)-1] {
	case "OPEN":
		return true
	case "CLOSED":
		return false
	default:
		t.Fatalf("unexpected TCP probe output: %q", out)
		return false
	}
}
