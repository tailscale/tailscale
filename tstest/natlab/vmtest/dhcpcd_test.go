// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"strings"
	"testing"

	"tailscale.com/tstest/natlab/vnet"
)

// TestDhcpcdFiles checks the files [DHCPClientDhcpcd] provisions: the
// networkd drop-in matches the vnet NIC's MAC and leaves it unmanaged, and
// dhcpcd.conf restricts dhcpcd to that NIC.
func TestDhcpcdFiles(t *testing.T) {
	var c vnet.Config
	nw := c.AddNetwork("2.1.1.1", "192.168.1.1/24")
	n := &Node{vnetNode: c.AddNode(nw)}

	files := dhcpcdFiles(n)
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.path] = string(f.content)
	}

	network, ok := byPath["/etc/systemd/network/05-natlab-dhcpcd.network"]
	if !ok {
		t.Fatalf("no .network file in %v", files)
	}
	for _, want := range []string{
		"MACAddress=" + n.vnetNode.NICMac(0).String() + "\n",
		"Unmanaged=yes\n",
	} {
		if !strings.Contains(network, want) {
			t.Errorf(".network file lacks %q:\n%s", want, network)
		}
	}

	conf, ok := byPath["/etc/dhcpcd.conf"]
	if !ok {
		t.Fatalf("no dhcpcd.conf in %v", files)
	}
	if want := "allowinterfaces " + VnetNICName + "\n"; !strings.Contains(conf, want) {
		t.Errorf("dhcpcd.conf lacks %q:\n%s", want, conf)
	}
}

// TestWriteLinuxDHCPClientSetup checks that the default client adds no runcmd
// entries, and that dhcpcd adds a NIC check followed by a dhcpcd that waits
// for the lease.
func TestWriteLinuxDHCPClientSetup(t *testing.T) {
	var c vnet.Config
	nw := c.AddNetwork("2.1.1.1", "192.168.1.1/24")
	n := &Node{vnetNode: c.AddNode(nw)}

	var ud strings.Builder
	writeLinuxDHCPClientSetup(&ud, n)
	if ud.Len() != 0 {
		t.Errorf("DHCPClientDefault wrote %q, want nothing", ud.String())
	}

	n.dhcpClient = DHCPClientDhcpcd
	ud.Reset()
	writeLinuxDHCPClientSetup(&ud, n)
	for _, want := range []string{
		"/sys/class/net/" + VnetNICName + "/address",
		n.vnetNode.NICMac(0).String(),
		`["dhcpcd", "-w", "` + VnetNICName + `"]`,
	} {
		if !strings.Contains(ud.String(), want) {
			t.Errorf("DHCPClientDhcpcd wrote %q, want it to contain %s", ud.String(), want)
		}
	}
	t.Log(ud.String())
}
