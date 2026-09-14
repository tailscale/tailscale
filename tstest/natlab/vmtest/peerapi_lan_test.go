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
	env := vmtest.New(t, vmtest.SameTailnetUser(), vmtest.AllOnline())

	// The shared LAN. It needs a WAN IP so the target can reach the
	// control server and DERP. The attacker shares this LAN but is not
	// on the tailnet.
	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)

	// The target runs tailscaled via the stock systemd unit, so peerapi
	// binds a real kernel socket on the node's Tailscale IP.
	target := env.AddNode("target", lan,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.SystemdUnit(),
		vmtest.WebServer(9999))

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

	// A kernel listener must exist on the Tailscale IP and port, bound
	// to the tunnel interface. ss prints the socket's bound device after
	// a % in the address. If the listen fell back to the netstack fake
	// listener there would be no kernel socket at all, and the attacker
	// would be refused for the wrong reason; if the device bind did not
	// apply, the attacker would complete a handshake and the test would
	// fail below, but asserting it here names the cause directly.
	listenerRe := regexp.MustCompile(`LISTEN\s+\d+\s+\d+\s+` +
		regexp.QuoteMeta(tsIP.String()) + `(?:%(\S+))?:` +
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

	// Route the target's Tailscale IP at the target's LAN IP. The
	// attacker now delivers SYNs to the target's NIC with the
	// Tailscale IP as the destination, standing in for the crafted
	// Ethernet frames of a LAN-adjacent attacker.
	env.AddRoute(attacker, tsIP.String()+"/32", target.LanIP(lan).String())

	// Control: a listener on the same Tailscale IP without a device
	// bind answers the attacker. Without this, the peerapi refusal
	// below would not prove anything.
	controlURL := "http://" + netip.AddrPortFrom(tsIP, 9999).String() + "/"
	status, body := curlStatus(t, env, attacker, controlURL)
	wantGreeting := "Hello world I am target from " + attacker.LanIP(lan).String()
	if status != 200 || !strings.Contains(body, wantGreeting) {
		t.Fatalf("GET %s from attacker = %d, %q; want 200 containing %q", controlURL, status, body, wantGreeting)
	}

	// The attack: a TCP handshake with the peerapi listener must not
	// complete. Only the kernel-level handshake matters, so the probe
	// opens the connection and immediately closes it, exactly like the
	// attribution oracle it replaces.
	if open := tcpConnectOpen(t, env, attacker, peerAPI); open {
		t.Fatalf("attacker completed a TCP handshake with peerapi on %s", peerAPI)
	}

	// The target itself must still reach its own peerapi. Local
	// delivery to the Tailscale IP traverses the tunnel interface, so
	// the device bind must admit it.
	if open := tcpConnectOpen(t, env, target, peerAPI); !open {
		t.Fatalf("target could not connect to its own peerapi on %s", peerAPI)
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

// curlStatus runs curl on the given node against rawURL and returns the
// HTTP status and body, failing the test if curl cannot connect.
func curlStatus(t *testing.T, env *vmtest.Env, n *vmtest.Node, rawURL string) (status int, body string) {
	t.Helper()
	cmd := "curl -s --max-time 15 -w '\\n%{http_code}' " + shell.Quote(rawURL)
	out, err := env.SSHExec(n, cmd)
	if err != nil {
		t.Fatalf("curl %s from %s: %v\n%s", rawURL, n.Name(), err, out)
	}
	i := strings.LastIndexByte(out, '\n')
	if i == -1 {
		t.Fatalf("no status line in curl output: %q", out)
	}
	status, err = strconv.Atoi(strings.TrimSpace(out[i+1:]))
	if err != nil {
		t.Fatalf("bad status line in curl output: %q", out)
	}
	return status, out[:i]
}

// tcpConnectOpen reports whether a TCP connection from node to addr
// completes, printing an OPEN or CLOSED marker inside the VM. Only the
// kernel-level handshake matters, so the probe opens the connection and
// immediately closes it. bash prints the failed connection attempt
// (e.g. "Connection refused") before the marker, and a refused
// connection and a dropped SYN both report CLOSED, which is fine: the
// property under test is that no handshake completes.
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
