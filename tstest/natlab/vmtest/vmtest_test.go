// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"strings"
	"testing"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

func TestSubnetRouter(t *testing.T) {
	testSubnetRouterForOS(t, vmtest.Ubuntu2404)
}

func TestSubnetRouterFreeBSD(t *testing.T) {
	testSubnetRouterForOS(t, vmtest.FreeBSD150)
}

// TestMacOSAndLinuxCanPing verifies basic LAN connectivity between a macOS VM
// (via tailmac/Virtualization.framework) and a Gokrazy Linux VM (via QEMU).
// Neither VM joins a tailnet; this only tests that the vnet virtual network
// routes Ethernet frames correctly between QEMU (stream) and tailmac (dgram)
// protocol clients. The macOS VM responds to ICMP natively (no TTA needed).
func TestMacOSAndLinuxCanPing(t *testing.T) {
	env := vmtest.New(t)

	lan := env.AddNetwork("192.168.1.1/24")

	linux := env.AddNode("linux", lan,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet())
	macos := env.AddNode("macos", lan,
		vmtest.OS(vmtest.MacOS),
		vmtest.DontJoinTailnet(),
		vmtest.NoAgent())

	env.Start()

	// Ping from Linux to macOS. This verifies bidirectional LAN connectivity
	// since ICMP echo requires a reply. LANPing retries until the macOS VM
	// has booted and acquired a DHCP lease from vnet.
	env.LANPing(linux, macos.LanIP(lan))
}

func testSubnetRouterForOS(t testing.TB, srOS vmtest.OSImage) {
	t.Helper()
	env := vmtest.New(t)

	clientNet := env.AddNetwork("2.1.1.1", "192.168.1.1/24", "2000:1::1/64", vnet.EasyNAT)
	internalNet := env.AddNetwork("10.0.0.1/24", "2000:2::1/64")

	client := env.AddNode("client", clientNet,
		vmtest.OS(vmtest.Gokrazy))
	sr := env.AddNode("subnet-router", clientNet, internalNet,
		vmtest.OS(srOS),
		vmtest.AdvertiseRoutes("10.0.0.0/24"))
	backend := env.AddNode("backend", internalNet,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet(),
		vmtest.WebServer(8080))

	env.Start()
	env.ApproveRoutes(sr, "10.0.0.0/24")

	body := env.HTTPGet(client, fmt.Sprintf("http://%s:8080/", backend.LanIP(internalNet)))
	if !strings.Contains(body, "Hello world I am backend") {
		t.Fatalf("got %q", body)
	}
}
