// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
	"tailscale.com/util/linuxfw"
	"tailscale.com/wgengine/router"
)

// The contents of this file are partially adapted from util/linuxfw/iptables_runner.go

const (
	postRoutingChain = "POSTROUTING"
	preroutingChain  = "PREROUTING"
	forwardChain     = "FORWARD"

	tailscaleInterface = "tailscale0*"

	snat       = "SNAT"
	dnat       = "DNAT"
	masquerade = "MASQUERADE"

	insertPosition = 1
)

type netfilterRunner interface {
	addIngressDNAT(netip.Addr, netip.Addr) error
	addEgressSNAT(netip.Addr, netip.Addr) error
	addEgressDNAT(netip.Addr) error
	addClamping(netip.Addr) error
}

// TODO (irbekrm): these heuristics aren't going to be useful in container env-
// make them actually attempt to create some fake rules and decide on basis of
// whether that succeeds
func determineProxyFirewallMode() linuxfw.FirewallMode {
	tableDetector := &router.LinuxFWDetector{}
	switch {
	case os.Getenv("TS_FIREWALL_MODE") == "nftables":
		log.Print("TS_FIREWALL_MODE set to nftables; proxy will use nftables")
		return linuxfw.FirewallModeNfTables
	case os.Getenv("TS_FIREWALL_MODE") == "auto":
		m := router.ChooseFireWallMode(logger.FromContext(context.Background()), tableDetector)
		log.Printf("TS_FIREWALL_MODE set to auto; proxy will use %s", m)
		return m
	case os.Getenv("TS_FIREWALL_MODE") == "iptables":
		log.Print("TS_FIREWALL_MODE set to iptables; proxy will use iptables")
		return linuxfw.FirewallModeIPTables
	default:
		log.Print("TS_FIREWALL_MODE is not set; proxy will use iptables")
		return linuxfw.FirewallModeIPTables
	}
}

func newNetFilterRunner(mode linuxfw.FirewallMode) (netfilterRunner, error) {
	var nfr netfilterRunner
	var err error
	switch mode {
	case linuxfw.FirewallModeIPTables:
		log.Print("using iptables to set up proxy rules")
		nfr, err = newIPTablesRunner(logger.FromContext(context.Background()))
		if err != nil {
			return nil, err
		}
	case linuxfw.FirewallModeNfTables:
		log.Print("using nftables to set up proxy rules")
		nfr, err = newNfTablesRunner(logger.FromContext(context.Background()))
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown firewall mode: %v", mode)
	}
	return nfr, nil
}

// newIPTablesRunner constructs a netFilterRunner that programs iptables rules.
// If the underlying iptables library fails to initialize, that error is
// returned. The runner probes for IPv6 support once at initialization time and
// if not found, no IPv6 rules will be modified for the lifetime of the runner.
func newIPTablesRunner(logf logger.Logf) (netfilterRunner, error) {
	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	supportsV6, supportsV6NAT := false, false
	v6err := linuxfw.CheckIPv6(logf)
	ip6terr := linuxfw.CheckIP6TablesExists()
	switch {
	case v6err != nil:
		logf("disabling tunneled IPv6 due to system IPv6 config: %v", v6err)
	case ip6terr != nil:
		logf("disabling tunneled IPv6 due to missing ip6tables: %v", ip6terr)
	default:
		supportsV6 = true
		supportsV6NAT = supportsV6 && linuxfw.CheckSupportsV6NAT()
		logf("v6nat = %v", supportsV6NAT)
	}

	var ipt6 *iptables.IPTables
	if supportsV6 {
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
	}
	return &iptablesRunner{ipt4, ipt6, supportsV6, supportsV6NAT}, nil
}

type iptablesI interface {
	Insert(string, string, int, ...string) error
	Append(string, string, ...string) error
	Exists(string, string, ...string) (bool, error)
	List(string, string) ([]string, error)
}

// iptablesRunner is an implementation of netfilterRunner for iptables
type iptablesRunner struct {
	ipt4 iptablesI
	ipt6 iptablesI

	v6Available    bool
	v6NATAvailable bool
}

// getIPTByAddr returns the iptablesInterface with correct IP family
// that we will be using for the given address.
func (i *iptablesRunner) getIPTByAddrForTable(addr netip.Addr, table string) (iptablesI, error) {
	nf := i.ipt4
	if addr.Is6() {
		if !i.v6Available {
			return nil, fmt.Errorf("ipv6 address requested %v, but ipv6 iptables are not available", addr)
		}
		if table == "nat" && !i.v6NATAvailable {
			return nil, fmt.Errorf("ipv6 address requested %v, but system does not support nat for ipv6 iptables", addr)
		}
		nf = i.ipt6
	}
	return nf, nil
}

func (i *iptablesRunner) addIngressDNAT(destination netip.Addr, destinationFilter netip.Addr) error {
	table, err := i.getIPTByAddrForTable(destination, "nat")
	if err != nil {
		return fmt.Errorf("error setting up iptables for ingress DNAT: %w", err)
	}
	return table.Insert("nat", preroutingChain, insertPosition, "--destination", destinationFilter.String(), "-j", dnat, "--to-destination", destination.String())
}

func (i *iptablesRunner) addEgressDNAT(destination netip.Addr) error {
	table, err := i.getIPTByAddrForTable(destination, "nat")
	if err != nil {
		return fmt.Errorf("error setting up iptables for egress DNAT: %w", err)
	}
	return table.Insert("nat", preroutingChain, insertPosition, "!", "-i", tailscaleInterface, "-j", dnat, "--to-destination", destination.String())
}

func (i *iptablesRunner) addEgressSNAT(source, destinationFilter netip.Addr) error {
	table, err := i.getIPTByAddrForTable(source, "nat")
	if err != nil {
		return fmt.Errorf("error setting up iptables for egress SNAT: %w", err)
	}
	return table.Insert("nat", postRoutingChain, insertPosition, "--destination", destinationFilter.String(), "-j", masquerade)
}

func (i *iptablesRunner) addClamping(addr netip.Addr) error {
	table, err := i.getIPTByAddrForTable(addr, "mangle")
	if err != nil {
		return fmt.Errorf("error setting up iptables for clamping: %w", err)
	}
	return table.Append("mangle", forwardChain, "-o", tailscaleInterface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
}

type connI interface {
	InsertRule(*nftables.Rule) *nftables.Rule
	Flush() error
}

// nftablesRunner is an implementation of netfilterRunner for nftables
type nftablesRunner struct {
	conn linuxfw.Conn
	nft4 *nftableFamily
	nft6 *nftableFamily

	v6Available    bool
	v6NATAvailable bool
}

type nftableFamily struct {
	Proto  nftables.TableFamily
	Nat    *nftables.Table
	Filter *nftables.Table
}

// newNfTablesRunner creates a new nftablesRunner
func newNfTablesRunner(logf logger.Logf) (*nftablesRunner, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables connection: %w", err)
	}
	nft4 := &nftableFamily{Proto: nftables.TableFamilyIPv4}

	v6err := linuxfw.CheckIPv6(logf)
	if v6err != nil {
		logf("disabling tunneled IPv6 due to system IPv6 config: %v", v6err)
	}
	supportsV6 := v6err == nil
	supportsV6NAT := supportsV6 && linuxfw.CheckSupportsV6NAT()

	var nft6 *nftableFamily
	if supportsV6 {
		logf("v6nat availability: %v", supportsV6NAT)
		nft6 = &nftableFamily{Proto: nftables.TableFamilyIPv6}
	}

	return &nftablesRunner{
		conn:           conn,
		nft4:           nft4,
		nft6:           nft6,
		v6Available:    supportsV6,
		v6NATAvailable: supportsV6NAT,
	}, nil
}

// getNFTByAddr returns the nftables with correct IP family
// that we will be using for the given address.
func (n *nftablesRunner) getNFTByAddrForTable(addr netip.Addr, table string) (*nftableFamily, error) {
	if addr.Is6() {
		if !n.v6Available {
			return nil, fmt.Errorf("ipv6 address in use, but ipv6 nftables are not available")
		}
		if table == "nat" && !n.v6NATAvailable {
			return nil, fmt.Errorf("ipv6 address in use, but ipv6 nftables modules for nat are not available")
		}
		return n.nft6, nil
	}
	return n.nft4, nil
}

// getTables gets the available nftable in nftables runner.
func (n *nftablesRunner) getTables() []*nftableFamily {
	if n.v6Available {
		return []*nftableFamily{n.nft4, n.nft6}
	}
	return []*nftableFamily{n.nft4}
}

func (n *nftablesRunner) addIngressDNAT(destination netip.Addr, destinationFilter netip.Addr) error {
	polAccept := nftables.ChainPolicyAccept
	table, err := n.getNFTByAddrForTable(destination, "nat")
	if err != nil {
		return err
	}
	nat, err := linuxfw.CreateTableIfNotExist(n.conn, table.Proto, "nat")
	if err != nil {
		return fmt.Errorf("error ensuring nat table: %w", err)
	}
	table.Nat = nat

	// ensure prerouting chain exists
	var preroutingCh *nftables.Chain
	if preroutingCh, err = linuxfw.CreateChainIfNotExist(n.conn, linuxfw.ChainInfo{
		Table:         nat,
		Name:          preroutingChain,
		ChainType:     nftables.ChainTypeNAT,
		ChainHook:     nftables.ChainHookPrerouting,
		ChainPriority: nftables.ChainPriorityNATDest,
		ChainPolicy:   &polAccept,
	}); err != nil {
		return fmt.Errorf("error ensuring prerouting chain: %w", err)
	}

	daddrOffset, err := daddrOffsetForFam(table.Proto)
	if err != nil {
		return fmt.Errorf("error determining destination address offset: %w", err)
	}
	daddrLen, err := ipAddressLenForFam(table.Proto)
	if err != nil {
		return fmt.Errorf("error determining ip address length: %w", err)
	}
	famConst, err := nfFamilyConst(table.Proto)
	if err != nil {
		return fmt.Errorf("error determining ip family: %w", err)
	}
	daddr, err := ipForFam(table.Proto, destinationFilter)
	if err != nil {
		return fmt.Errorf("error parsing destination IP address: %w", err)
	}
	clusterDaddr, err := ipForFam(table.Proto, destination)
	if err != nil {
		return fmt.Errorf("error parsing cluster destination IP address: %w", err)
	}

	dnatRule := &nftables.Rule{
		Table: nat,
		Chain: preroutingCh,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       daddrOffset,
				Len:          daddrLen,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     daddr,
			},
			&expr.Immediate{
				Register: 1,
				Data:     clusterDaddr,
			},
			&expr.NAT{
				Type:       expr.NATTypeDestNAT,
				Family:     famConst,
				RegAddrMin: 1,
			},
		},
	}
	n.conn.InsertRule(dnatRule)
	n.conn.Flush()

	return nil
}

func (n *nftablesRunner) addEgressDNAT(destination netip.Addr) error {
	polAccept := nftables.ChainPolicyAccept
	table, err := n.getNFTByAddrForTable(destination, "nat")
	if err != nil {
		return err
	}
	nat, err := linuxfw.CreateTableIfNotExist(n.conn, table.Proto, "nat")
	if err != nil {
		return fmt.Errorf("error ensuring nat table exists: %w", err)
	}
	table.Nat = nat

	// ensure prerouting chain exists
	var preroutingCh *nftables.Chain
	if preroutingCh, err = linuxfw.CreateChainIfNotExist(n.conn, linuxfw.ChainInfo{
		Table:         nat,
		Name:          preroutingChain,
		ChainType:     nftables.ChainTypeNAT,
		ChainHook:     nftables.ChainHookPrerouting,
		ChainPriority: nftables.ChainPriorityNATDest,
		ChainPolicy:   &polAccept,
	}); err != nil {
		return fmt.Errorf("error ensuring prerouting chain: %w", err)
	}
	famConst, err := nfFamilyConst(table.Proto)
	if err != nil {
		return fmt.Errorf("error determining ip family: %w", err)
	}
	ip, err := ipForFam(table.Proto, destination)
	if err != nil {
		return fmt.Errorf("error parsing IP address: %w", err)
	}

	dnatRule := &nftables.Rule{
		Table: nat,
		Chain: preroutingCh,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     ifname(tailscaleInterface),
			},
			&expr.Immediate{
				Register: 1,
				Data:     ip,
			},
			&expr.NAT{
				Type:       expr.NATTypeDestNAT,
				Family:     famConst,
				RegAddrMin: 1,
			},
		},
	}
	// Tailnet egress IP is passed to the proxy as an env var- that means
	// that if it ever changes Pods will be restarted, so we don't have to
	// worry about multiple rules with different destination addresses
	n.conn.AddRule(dnatRule)
	n.conn.Flush()
	return nil
}

func (n *nftablesRunner) addEgressSNAT(source, destinationFilter netip.Addr) error {
	polAccept := nftables.ChainPolicyAccept
	table, err := n.getNFTByAddrForTable(destinationFilter, "nat")
	if err != nil {
		return err
	}
	nat, err := linuxfw.CreateTableIfNotExist(n.conn, table.Proto, "nat")
	if err != nil {
		return fmt.Errorf("error ensuring nat table exists: %w", err)
	}
	table.Nat = nat

	// ensure postrouting chain exists
	var postRoutingCh *nftables.Chain
	if postRoutingCh, err = linuxfw.CreateChainIfNotExist(n.conn, linuxfw.ChainInfo{
		Table:         nat,
		Name:          postRoutingChain,
		ChainType:     nftables.ChainTypeNAT,
		ChainHook:     nftables.ChainHookPostrouting,
		ChainPriority: nftables.ChainPriorityNATSource,
		ChainPolicy:   &polAccept,
	}); err != nil {
		return fmt.Errorf("error ensuring postrouting chain: %w", err)
	}

	daddrOffset, err := daddrOffsetForFam(table.Proto)
	if err != nil {
		return fmt.Errorf("error determining destination address offset: %w", err)
	}
	daddrLen, err := ipAddressLenForFam(table.Proto)
	if err != nil {
		return fmt.Errorf("error determining ip address length: %w", err)
	}
	ip, err := ipForFam(table.Proto, destinationFilter)
	if err != nil {
		return fmt.Errorf("error parsing ip address: %w", err)
	}

	snatRule := &nftables.Rule{
		Table: nat,
		Chain: postRoutingCh,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       daddrOffset,
				Len:          daddrLen,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ip,
			},
			&expr.Masq{},
		},
	}
	// Tailnet egress IP is passed to the proxy as an env var- that means
	// that if it ever changes Pods will be restarted, so we don't have to
	// worry about multiple rules with different destination addresses
	n.conn.AddRule(snatRule)
	n.conn.Flush()
	return nil
}

func (n *nftablesRunner) addClamping(_ netip.Addr) error {
	polAccept := nftables.ChainPolicyAccept

	for _, fam := range n.getTables() {
		filterTable, err := linuxfw.CreateTableIfNotExist(n.conn, fam.Proto, "filter")
		if err != nil {
			return fmt.Errorf("error ensuring filter table: %w", err)
		}
		fam.Filter = filterTable

		// ensure forwarding chain exists
		var fwChain *nftables.Chain

		if fwChain, err = linuxfw.CreateChainIfNotExist(n.conn, linuxfw.ChainInfo{
			Table:         filterTable,
			Name:          forwardChain,
			ChainType:     nftables.ChainTypeFilter,
			ChainHook:     nftables.ChainHookForward,
			ChainPriority: nftables.ChainPriorityFilter,
			ChainPolicy:   &polAccept,
		}); err != nil {
			return fmt.Errorf("error ensuring forward chain: %w", err)
		}
		tcpFlagsOffset, err := tcpFlagsOffsetForFam(fam.Proto)
		if err != nil {
			return fmt.Errorf("error determining TCP flags offset: %w", err)
		}

		clampRule := &nftables.Rule{
			Table: filterTable,
			Chain: fwChain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ifname(tailscaleInterface),
				},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{unix.IPPROTO_TCP},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       tcpFlagsOffset,
					Len:          1,
				},
				&expr.Bitwise{
					DestRegister:   1,
					SourceRegister: 1,
					Len:            1,
					Mask:           []byte{0x02},
					Xor:            []byte{0x00},
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     []byte{0x00},
				},
				&expr.Rt{
					Register: 1,
					Key:      expr.RtTCPMSS,
				},
				&expr.Byteorder{
					DestRegister:   1,
					SourceRegister: 1,
					Op:             expr.ByteorderHton,
					Len:            2,
					Size:           2,
				},
				&expr.Exthdr{
					SourceRegister: 1,
					Type:           2,
					Offset:         2,
					Len:            2,
					Op:             expr.ExthdrOpTcpopt,
				},
			},
		}
		n.conn.AddRule(clampRule)
	}
	n.conn.Flush()
	return nil
}

func daddrOffsetForFam(proto nftables.TableFamily) (uint32, error) {
	switch proto {
	case nftables.TableFamilyIPv4:
		return 16, nil
	case nftables.TableFamilyIPv6:
		return 40, nil
	default:
		return 0, fmt.Errorf("table family %v is neither IPv4 nor IPv6", proto)
	}
}

func ipAddressLenForFam(proto nftables.TableFamily) (uint32, error) {
	switch proto {
	case nftables.TableFamilyIPv4:
		return 4, nil
	case nftables.TableFamilyIPv6:
		return 16, nil
	default:
		return 0, fmt.Errorf("table family %v is neither IPv4 nor IPv6", proto)
	}
}

func nfFamilyConst(proto nftables.TableFamily) (uint32, error) {
	switch proto {
	case nftables.TableFamilyIPv4:
		return unix.NFPROTO_IPV4, nil
	case nftables.TableFamilyIPv6:
		return unix.NFPROTO_IPV6, nil
	default:
		return 0, fmt.Errorf("table family %v is neither IPv4 nor IPv6", proto)
	}
}

func tcpFlagsOffsetForFam(proto nftables.TableFamily) (uint32, error) {
	switch proto {
	case nftables.TableFamilyIPv4:
		return 13, nil
	case nftables.TableFamilyIPv6:
		return 53, nil
	default:
		return 0, fmt.Errorf("table family %v is neither IPv4 nor IPv6", proto)
	}
}

func ipForFam(proto nftables.TableFamily, ip netip.Addr) (net.IP, error) {
	switch proto {
	case nftables.TableFamilyIPv4:
		return net.ParseIP(ip.String()).To4(), nil
	case nftables.TableFamilyIPv6:
		return net.ParseIP(ip.String()).To16(), nil
	default:
		return nil, fmt.Errorf("table family %v is neither IPv4 nor IPv6", proto)
	}
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}
