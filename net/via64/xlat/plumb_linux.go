// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package xlat

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	nl "github.com/mdlayher/netlink"
	"github.com/safchain/ethtool"
	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
)

const (
	PrimaryName = "tsvia0"
	PeerName    = "tsvia1"

	primaryMTU = 1280 // tailscale0's
	peerMTU    = 1260 // a reply grows by 20 bytes when translated and must still fit 1280
	fragMTU    = 1252 // a fragment grows by 28

	// fragMark marks replies the router must fragment (no DF, over peerMTU), so fragRule routes them with fragMTU. It is outside Tailscale's 0xff0000 mark byte.
	fragMark = 0x01000000

	// From include/uapi/linux/if_link.h.
	iflaNetkitPeerInfo = 1
	iflaNetkitMode     = 5
	netkitL3           = 1
)

// createPair creates the netkit pair in L3 mode and brings it up.
func createPair() (Pair, error) {
	if err := newNetkit(PrimaryName, PeerName); err != nil {
		return Pair{}, fmt.Errorf("creating netkit pair %s/%s: %w", PrimaryName, PeerName, err)
	}
	var p Pair
	for _, d := range []struct {
		name string
		idx  *int
	}{{PrimaryName, &p.PrimaryIndex}, {PeerName, &p.PeerIndex}} {
		l, err := netlink.LinkByName(d.name)
		if err != nil {
			return Pair{}, err
		}
		if l.Type() != "netkit" {
			return Pair{}, fmt.Errorf("%s exists but is a %s device, not netkit", d.name, l.Type())
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return Pair{}, fmt.Errorf("setting %s up: %w", d.name, err)
		}
		*d.idx = l.Attrs().Index
	}
	// The translator cannot change the protocol of a UDP GSO packet.
	if err := disableUDPSegmentation(PrimaryName, PeerName); err != nil {
		return Pair{}, err
	}
	// The peer has no IPv6: its MTU is below IPv6's minimum.
	for _, key := range []string{
		"net/ipv4/conf/" + PrimaryName + "/forwarding",
		"net/ipv6/conf/" + PrimaryName + "/forwarding",
		"net/ipv4/conf/" + PeerName + "/forwarding",
	} {
		if err := writeSysctl(key, "1"); err != nil {
			return Pair{}, err
		}
	}
	return p, nil
}

// newNetkit sends RTM_NEWLINK for a netkit pair; tailscale/netlink predates netkit.
func newNetkit(primary, peer string) error {
	pe := nl.NewAttributeEncoder()
	pe.String(unix.IFLA_IFNAME, peer)
	pe.Uint32(unix.IFLA_MTU, peerMTU)
	peerAttrs, err := pe.Encode()
	if err != nil {
		return err
	}
	ae := nl.NewAttributeEncoder()
	ae.String(unix.IFLA_IFNAME, primary)
	ae.Uint32(unix.IFLA_MTU, primaryMTU)
	ae.Nested(unix.IFLA_LINKINFO, func(li *nl.AttributeEncoder) error {
		li.String(unix.IFLA_INFO_KIND, "netkit")
		li.Nested(unix.IFLA_INFO_DATA, func(d *nl.AttributeEncoder) error {
			d.Uint32(iflaNetkitMode, netkitL3)
			// Like veth's peer info: a struct ifinfomsg followed by the peer's own attributes.
			d.Bytes(iflaNetkitPeerInfo, append(make([]byte, unix.SizeofIfInfomsg), peerAttrs...))
			return nil
		})
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	c, err := nl.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Execute(nl.Message{
		Header: nl.Header{Type: unix.RTM_NEWLINK, Flags: nl.Request | nl.Acknowledge | nl.Create | nl.Excl},
		Data:   append(make([]byte, unix.SizeofIfInfomsg), attrs...),
	})
	return err
}

// Cleanup removes via64's datapath by what identifies it, without a running controller, so tailscaled's cleanup can run it after a process that died or lost the knob: the rules into its two routing tables, its nftables tables, and the pair, which takes via64's routes with it. A host without IPv6 or nftables has nothing there to remove, so those errors are not reported.
func Cleanup(table int) error {
	var errs []error
	for _, err := range []error{
		delRulesTo(table), delRulesTo(table + 1), // first, so nothing is steered into a half-removed datapath
		deleteNAT(),
		delPair(),
	} {
		if !errors.Is(err, unix.EAFNOSUPPORT) && !errors.Is(err, unix.EPROTONOSUPPORT) && !errors.Is(err, unix.EOPNOTSUPP) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// delPair deletes the pair; deleting the primary removes both ends.
func delPair() error {
	l, err := netlink.LinkByName(PrimaryName)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		return err
	}
	if l.Type() != "netkit" {
		return nil // not ours
	}
	return netlink.LinkDel(l)
}

func disableUDPSegmentation(devs ...string) error {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}
	defer e.Close()
	for _, d := range devs {
		if err := e.Change(d, map[string]bool{"tx-udp-segmentation": false}); err != nil {
			return fmt.Errorf("turning off tx-udp-segmentation on %s: %w", d, err)
		}
	}
	return nil
}

func readSysctl(key string) string {
	b, err := os.ReadFile("/proc/sys/" + key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeSysctl(key, val string) error {
	if err := os.WriteFile("/proc/sys/"+key, []byte(val), 0644); err != nil {
		return fmt.Errorf("sysctl %s=%s: %w", strings.ReplaceAll(key, "/", "."), val, err)
	}
	return nil
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// steeringRule sends the canonical prefix to table. It does not match the input interface, because a reverse-path filter looks up the route back to a reply's canonical source without one; the guard chain keeps everything but translated replies out of the prefix.
func steeringRule(table, prio int) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = netlink.FAMILY_V6
	r.Dst = ipNet(Canonical)
	r.Table = table
	r.Priority = prio
	return r
}

// x4Rule sends replies to X4 to table.
func x4Rule(x4 netip.Addr, table, prio int) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = netlink.FAMILY_V4
	r.Dst = ipNet(netip.PrefixFrom(x4, 32))
	r.Table = table
	r.Priority = prio
	return r
}

// fragRule sends replies to X4 carrying fragMark to table, where the X4 route has fragMTU.
func fragRule(x4 netip.Addr, table, prio int) *netlink.Rule {
	r := x4Rule(x4, table, prio)
	r.Mark, r.Mask = fragMark, fragMark
	return r
}

func steeringRoute(pair Pair, table int) *netlink.Route {
	return &netlink.Route{Dst: ipNet(Canonical), LinkIndex: pair.PrimaryIndex, Table: table}
}

func x4Route(pair Pair, x4 netip.Addr, table, mtu int) *netlink.Route {
	return &netlink.Route{Dst: ipNet(netip.PrefixFrom(x4, 32)), LinkIndex: pair.PeerIndex, Table: table, Scope: netlink.SCOPE_LINK, MTU: mtu}
}

// delRulesTo deletes every rule that looks up table, in both families.
func delRulesTo(table int) error {
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(fam)
		if err != nil {
			return err
		}
		for i := range rules {
			if rules[i].Table != table {
				continue
			}
			if err := netlink.RuleDel(&rules[i]); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
	}
	return nil
}

// ruleExists reports whether a rule with r's priority, table and destination exists.
func ruleExists(r *netlink.Rule) (bool, error) {
	rules, err := netlink.RuleList(r.Family)
	if err != nil {
		return false, err
	}
	for _, x := range rules {
		if x.Priority == r.Priority && x.Table == r.Table && x.Dst != nil && r.Dst != nil && x.Dst.String() == r.Dst.String() {
			return true, nil
		}
	}
	return false, nil
}

// routeExists reports whether r's table holds a route to r.Dst through r.LinkIndex. It asks the kernel for that table alone (a strict-checked dump); tailscale/netlink would dump every route of the family, which on a router with a full BGP table is a million routes.
func routeExists(r *netlink.Route) (bool, error) {
	fam := byte(unix.AF_INET)
	if r.Dst.IP.To4() == nil {
		fam = unix.AF_INET6
	}
	c, err := nl.Dial(unix.NETLINK_ROUTE, &nl.Config{Strict: true})
	if err != nil {
		return false, err
	}
	defer c.Close()
	ae := nl.NewAttributeEncoder()
	ae.Uint32(unix.RTA_TABLE, uint32(r.Table))
	attrs, err := ae.Encode()
	if err != nil {
		return false, err
	}
	hdr := make([]byte, unix.SizeofRtMsg)
	hdr[0] = fam
	msgs, err := c.Execute(nl.Message{Header: nl.Header{Type: unix.RTM_GETROUTE, Flags: nl.Request | nl.Dump}, Data: append(hdr, attrs...)})
	if errors.Is(err, unix.ENOENT) {
		return false, nil // the table does not exist yet
	} else if err != nil {
		return false, err
	}
	bits, _ := r.Dst.Mask.Size()
	for _, m := range msgs {
		if len(m.Data) < unix.SizeofRtMsg || int(m.Data[1]) != bits {
			continue
		}
		ad, err := nl.NewAttributeDecoder(m.Data[unix.SizeofRtMsg:])
		if err != nil {
			return false, err
		}
		var dst net.IP
		var oif, table int
		for ad.Next() {
			switch ad.Type() {
			case unix.RTA_DST:
				dst = net.IP(ad.Bytes())
			case unix.RTA_OIF:
				oif = int(ad.Uint32())
			case unix.RTA_TABLE:
				table = int(ad.Uint32())
			}
		}
		if table == r.Table && oif == r.LinkIndex && dst.Equal(r.Dst.IP) {
			return true, nil
		}
	}
	return false, nil
}
