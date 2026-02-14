// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"net/netip"

	"tailscale.com/types/logger"
)

// FakeNetfilterRunner is a fake netfilter runner for tests.
type FakeNetfilterRunner struct {
	// services is a map that tracks the firewall rules added/deleted via
	// EnsureDNATRuleForSvc/DeleteDNATRuleForSvc.
	services map[string]struct {
		TailscaleServiceIP netip.Addr
		ClusterIP          netip.Addr
	}
}

// NewFakeNetfilterRunner creates a new FakeNetfilterRunner.
func NewFakeNetfilterRunner() *FakeNetfilterRunner {
	return &FakeNetfilterRunner{
		services: make(map[string]struct {
			TailscaleServiceIP netip.Addr
			ClusterIP          netip.Addr
		}),
	}
}

func (f *FakeNetfilterRunner) EnsureDNATRuleForSvc(svcName string, origDst, dst netip.Addr) error {
	f.services[svcName] = struct {
		TailscaleServiceIP netip.Addr
		ClusterIP          netip.Addr
	}{origDst, dst}
	return nil
}

func (f *FakeNetfilterRunner) DeleteDNATRuleForSvc(svcName string, origDst, dst netip.Addr) error {
	delete(f.services, svcName)
	return nil
}

func (f *FakeNetfilterRunner) GetServiceState() map[string]struct {
	TailscaleServiceIP netip.Addr
	ClusterIP          netip.Addr
} {
	return f.services
}

func (f *FakeNetfilterRunner) HasIPV6() bool {
	return true
}

func (f *FakeNetfilterRunner) HasIPV6Filter() bool {
	return true
}

func (f *FakeNetfilterRunner) HasIPV6NAT() bool {
	return true
}

func (f *FakeNetfilterRunner) SetPacketMarks(marks PacketMarks)          {}
func (f *FakeNetfilterRunner) AddBase(tunname string) error              { return nil }
func (f *FakeNetfilterRunner) DelBase() error                            { return nil }
func (f *FakeNetfilterRunner) AddChains() error                          { return nil }
func (f *FakeNetfilterRunner) DelChains() error                          { return nil }
func (f *FakeNetfilterRunner) AddHooks() error                           { return nil }
func (f *FakeNetfilterRunner) DelHooks(logf logger.Logf) error           { return nil }
func (f *FakeNetfilterRunner) AddSNATRule() error                        { return nil }
func (f *FakeNetfilterRunner) DelSNATRule() error                        { return nil }
func (f *FakeNetfilterRunner) AddStatefulRule(tunname string) error      { return nil }
func (f *FakeNetfilterRunner) DelStatefulRule(tunname string) error      { return nil }
func (f *FakeNetfilterRunner) AddLoopbackRule(addr netip.Addr) error     { return nil }
func (f *FakeNetfilterRunner) DelLoopbackRule(addr netip.Addr) error     { return nil }
func (f *FakeNetfilterRunner) AddDNATRule(origDst, dst netip.Addr) error { return nil }
func (f *FakeNetfilterRunner) DNATWithLoadBalancer(origDst netip.Addr, dsts []netip.Addr) error {
	return nil
}
func (f *FakeNetfilterRunner) EnsureSNATForDst(src, dst netip.Addr) error               { return nil }
func (f *FakeNetfilterRunner) DNATNonTailscaleTraffic(tun string, dst netip.Addr) error { return nil }
func (f *FakeNetfilterRunner) ClampMSSToPMTU(tun string, addr netip.Addr) error         { return nil }
func (f *FakeNetfilterRunner) AddMagicsockPortRule(port uint16, network string) error   { return nil }
func (f *FakeNetfilterRunner) DelMagicsockPortRule(port uint16, network string) error   { return nil }
func (f *FakeNetfilterRunner) DeletePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm PortMap) error {
	return nil
}
func (f *FakeNetfilterRunner) DeleteSvc(svc, tun string, targetIPs []netip.Addr, pms []PortMap) error {
	return nil
}
func (f *FakeNetfilterRunner) EnsurePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm PortMap) error {
	return nil
}
