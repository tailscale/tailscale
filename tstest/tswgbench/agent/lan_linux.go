// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"

	"github.com/safchain/ethtool"
	"github.com/tailscale/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The LAN that handleLANNetns sets up: a network namespace lanNetns
// behind the veth pair lanHost (here) and lanPeer (in the namespace).
const (
	lanNetns = "lan"
	lanHost  = "lanh"
	lanPeer  = "lanc"
)

// handleLANNetns (POST /lan-netns) sets up a host on a LAN behind this
// node, for tests of forwarding: the network namespace "lan" (see netbench's
// netns parameter), with 192.168.77.2/24 and fd78::2/64, routed through
// this node at 192.168.77.1 and fd78::1 over a veth pair with an MTU of
// 1280. Its side doesn't segment (TSO and GSO off) and this side merges
// what it receives (GRO on), as a NIC on a subnet router's LAN would. This
// node forwards. It replaces any previous one.
func handleLANNetns(w http.ResponseWriter, r *http.Request) {
	if err := setupLANNetns(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "OK\n")
}

func setupLANNetns() error {
	// Before making the links, so that they inherit IPv6's default.
	for _, p := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding",
		"/proc/sys/net/ipv6/conf/default/forwarding",
	} {
		if err := os.WriteFile(p, []byte("1"), 0); err != nil {
			return err
		}
	}
	if l, err := netlink.LinkByName(lanHost); err == nil {
		netlink.LinkDel(l)
	}
	netns.DeleteNamed(lanNetns)

	// NewNamed switches the calling thread to the new namespace, so make
	// it on a thread of its own, which exits with its goroutine.
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		ns, err := netns.NewNamed(lanNetns)
		if err == nil {
			ns.Close()
		}
		errc <- err
	}()
	if err := <-errc; err != nil {
		return fmt.Errorf("creating netns: %w", err)
	}
	ns, err := netns.GetFromName(lanNetns)
	if err != nil {
		return err
	}
	defer ns.Close()

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: lanHost, MTU: 1280},
		PeerName:  lanPeer,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("adding veth: %w", err)
	}
	peer, err := netlink.LinkByName(lanPeer)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetMTU(peer, 1280); err != nil {
		return err
	}
	et, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}
	defer et.Close()
	if err := et.Change(lanHost, map[string]bool{"rx-gro": true}); err != nil {
		return fmt.Errorf("GRO on %s: %w", lanHost, err)
	}
	if err := et.Change(lanPeer, map[string]bool{
		"tx-tcp-segmentation":     false,
		"tx-tcp6-segmentation":    false,
		"tx-generic-segmentation": false,
	}); err != nil {
		return fmt.Errorf("TSO and GSO off on %s: %w", lanPeer, err)
	}
	if err := netlink.LinkSetNsFd(peer, int(ns)); err != nil {
		return err
	}

	host, err := netlink.LinkByName(lanHost)
	if err != nil {
		return err
	}
	root, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer root.Close()
	if err := lanAddrs(root, host, "192.168.77.1/24", "fd78::1/64"); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(host); err != nil {
		return err
	}

	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return err
	}
	defer h.Close()
	peer, err = h.LinkByName(lanPeer)
	if err != nil {
		return err
	}
	if err := lanAddrs(h, peer, "192.168.77.2/24", "fd78::2/64"); err != nil {
		return err
	}
	for _, name := range []string{"lo", lanPeer} {
		l, err := h.LinkByName(name)
		if err != nil {
			return err
		}
		if err := h.LinkSetUp(l); err != nil {
			return err
		}
	}
	for _, gw := range []string{"192.168.77.1", "fd78::1"} {
		if err := h.RouteAdd(&netlink.Route{LinkIndex: peer.Attrs().Index, Gw: net.ParseIP(gw)}); err != nil {
			return fmt.Errorf("default route via %s: %w", gw, err)
		}
	}
	return nil
}

// lanAddrs adds addrs (without IPv6 duplicate address detection) to link,
// with h.
func lanAddrs(h *netlink.Handle, link netlink.Link, addrs ...string) error {
	for _, a := range addrs {
		addr, err := netlink.ParseAddr(a)
		if err != nil {
			return err
		}
		addr.Flags = unix.IFA_F_NODAD
		if err := h.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("adding %s: %w", a, err)
		}
	}
	return nil
}
