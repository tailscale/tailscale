// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// This file contains functionality that is currently (09/2024) used to set up
// routing for the Tailscale Kubernetes operator egress proxies. A tailnet
// service (identified by tailnet IP or FQDN) that gets exposed to cluster
// workloads gets a separate prerouting chain created for it for each IP family
// of the chain's target addresses. Each service's prerouting chain contains one
// or more portmapping rules. A portmapping rule DNATs traffic received on a
// particular port to a port of the tailnet service. Creating a chain per
// service makes it easier to delete a service when no longer needed and helps
// with readability.

// EnsurePortMapRuleForSvc:
// - ensures that nat table exists
// - ensures that there is a prerouting chain for the given service and IP family of the target address in the nat table
// - ensures that there is a portmapping rule mathcing the given portmap (only creates the rule if it does not already exist)
func (n *nftablesRunner) EnsurePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm PortMap) error {
	t, ch, err := n.ensureChainForSvc(svc, targetIP)
	if err != nil {
		return fmt.Errorf("error ensuring chain for %s: %w", svc, err)
	}
	meta := svcPortMapRuleMeta(svc, targetIP, pm)
	rule, err := n.findRuleByMetadata(t, ch, meta)
	if err != nil {
		return fmt.Errorf("error looking up rule: %w", err)
	}
	if rule != nil {
		return nil
	}
	p, err := protoFromString(pm.Protocol)
	if err != nil {
		return fmt.Errorf("error converting protocol %s: %w", pm.Protocol, err)
	}

	rule = portMapRule(t, ch, tun, targetIP, pm.MatchPort, pm.TargetPort, p, meta)
	n.conn.InsertRule(rule)
	return n.conn.Flush()
}

// DeletePortMapRuleForSvc deletes a portmapping rule in the given service/IP family chain.
// It finds the matching rule using metadata attached to the rule.
// The caller is expected to call DeleteSvc if the whole service (the chain)
// needs to be deleted, so we don't deal with the case where this is the only
// rule in the chain here.
func (n *nftablesRunner) DeletePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm PortMap) error {
	table, err := n.getNFTByAddr(targetIP)
	if err != nil {
		return fmt.Errorf("error setting up nftables for IP family of %s: %w", targetIP, err)
	}
	t, err := getTableIfExists(n.conn, table.Proto, "nat")
	if err != nil {
		return fmt.Errorf("error checking if nat table exists: %w", err)
	}
	if t == nil {
		return nil
	}
	ch, err := getChainFromTable(n.conn, t, svc)
	if err != nil && !errors.Is(err, errorChainNotFound{t.Name, svc}) {
		return fmt.Errorf("error checking if chain %s exists: %w", svc, err)
	}
	if errors.Is(err, errorChainNotFound{t.Name, svc}) {
		return nil // service chain does not exist, so neither does the portmapping rule
	}
	meta := svcPortMapRuleMeta(svc, targetIP, pm)
	rule, err := n.findRuleByMetadata(t, ch, meta)
	if err != nil {
		return fmt.Errorf("error checking if rule exists: %w", err)
	}
	if rule == nil {
		return nil
	}
	if err := n.conn.DelRule(rule); err != nil {
		return fmt.Errorf("error deleting rule: %w", err)
	}
	return n.conn.Flush()
}

// DeleteSvc deletes the chains for the given service if any exist.
func (n *nftablesRunner) DeleteSvc(svc, tun string, targetIPs []netip.Addr, pm []PortMap) error {
	for _, tip := range targetIPs {
		table, err := n.getNFTByAddr(tip)
		if err != nil {
			return fmt.Errorf("error setting up nftables for IP family of %s: %w", tip, err)
		}
		t, err := getTableIfExists(n.conn, table.Proto, "nat")
		if err != nil {
			return fmt.Errorf("error checking if nat table exists: %w", err)
		}
		if t == nil {
			return nil
		}
		ch, err := getChainFromTable(n.conn, t, svc)
		if err != nil && !errors.Is(err, errorChainNotFound{t.Name, svc}) {
			return fmt.Errorf("error checking if chain %s exists: %w", svc, err)
		}
		if errors.Is(err, errorChainNotFound{t.Name, svc}) {
			return nil
		}
		n.conn.DelChain(ch)
	}
	return n.conn.Flush()
}

func portMapRule(t *nftables.Table, ch *nftables.Chain, tun string, targetIP netip.Addr, matchPort, targetPort uint16, proto uint8, meta []byte) *nftables.Rule {
	var fam uint32
	if targetIP.Is4() {
		fam = unix.NFPROTO_IPV4
	} else {
		fam = unix.NFPROTO_IPV6
	}
	rule := &nftables.Rule{
		Table:    t,
		Chain:    ch,
		UserData: meta,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte(tun),
			},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{proto},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(matchPort),
			},
			&expr.Immediate{
				Register: 1,
				Data:     targetIP.AsSlice(),
			},
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(targetPort),
			},
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      fam,
				RegAddrMin:  1,
				RegAddrMax:  1,
				RegProtoMin: 2,
				RegProtoMax: 2,
			},
		},
	}
	return rule
}

// svcPortMapRuleMeta generates metadata for a rule.
// This metadata can then be used to find the rule.
// https://github.com/google/nftables/issues/48
func svcPortMapRuleMeta(svcName string, targetIP netip.Addr, pm PortMap) []byte {
	return []byte(fmt.Sprintf("svc:%s,targetIP:%s:matchPort:%v,targetPort:%v,proto:%v", svcName, targetIP.String(), pm.MatchPort, pm.TargetPort, pm.Protocol))
}

func (n *nftablesRunner) findRuleByMetadata(t *nftables.Table, ch *nftables.Chain, meta []byte) (*nftables.Rule, error) {
	if n.conn == nil || t == nil || ch == nil || len(meta) == 0 {
		return nil, nil
	}
	rules, err := n.conn.GetRules(t, ch)
	if err != nil {
		return nil, fmt.Errorf("error listing rules: %w", err)
	}
	for _, rule := range rules {
		if reflect.DeepEqual(rule.UserData, meta) {
			return rule, nil
		}
	}
	return nil, nil
}

func (n *nftablesRunner) ensureChainForSvc(svc string, targetIP netip.Addr) (*nftables.Table, *nftables.Chain, error) {
	polAccept := nftables.ChainPolicyAccept
	table, err := n.getNFTByAddr(targetIP)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting up nftables for IP family of %v: %w", targetIP, err)
	}
	nat, err := createTableIfNotExist(n.conn, table.Proto, "nat")
	if err != nil {
		return nil, nil, fmt.Errorf("error ensuring nat table: %w", err)
	}
	svcCh, err := getOrCreateChain(n.conn, chainInfo{
		table:         nat,
		name:          svc,
		chainType:     nftables.ChainTypeNAT,
		chainHook:     nftables.ChainHookPrerouting,
		chainPriority: nftables.ChainPriorityNATDest,
		chainPolicy:   &polAccept,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error ensuring prerouting chain: %w", err)
	}
	return nat, svcCh, nil
}

// // PortMap is the port mapping for a service rule.
type PortMap struct {
	// MatchPort is the local port to which the rule should apply.
	MatchPort uint16
	// TargetPort is the port to which the traffic should be forwarded.
	TargetPort uint16
	// Protocol is the protocol to match packets on. Only TCP and UDP are
	// supported.
	Protocol string
}

func protoFromString(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	case "udp":
		return unix.IPPROTO_UDP, nil
	default:
		return 0, fmt.Errorf("unrecognized protocol: %q", s)
	}
}
