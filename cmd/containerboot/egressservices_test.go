// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/linuxfw"
)

func Test_updatesForSvc(t *testing.T) {
	tailnetIPv4, tailnetIPv6 := netip.MustParseAddr("100.99.99.99"), netip.MustParseAddr("fd7a:115c:a1e0::701:b62a")
	tailnetIPv4_1, tailnetIPv6_1 := netip.MustParseAddr("100.88.88.88"), netip.MustParseAddr("fd7a:115c:a1e0::4101:512f")
	ports := map[egressservices.PortMap]struct{}{{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}: {}}
	ports1 := map[egressservices.PortMap]struct{}{{Protocol: "udp", MatchPort: 4004, TargetPort: 53}: {}}
	ports2 := map[egressservices.PortMap]struct{}{{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}: {},
		{Protocol: "tcp", MatchPort: 4005, TargetPort: 443}: {}}
	fqdnSpec := egressservices.Config{
		TailnetTarget: egressservices.TailnetTarget{FQDN: "test"},
		Ports:         ports,
	}
	fqdnSpec1 := egressservices.Config{
		TailnetTarget: egressservices.TailnetTarget{FQDN: "test"},
		Ports:         ports1,
	}
	fqdnSpec2 := egressservices.Config{
		TailnetTarget: egressservices.TailnetTarget{IP: tailnetIPv4.String()},
		Ports:         ports,
	}
	fqdnSpec3 := egressservices.Config{
		TailnetTarget: egressservices.TailnetTarget{IP: tailnetIPv4.String()},
		Ports:         ports2,
	}
	r := rule{containerPort: 4003, tailnetPort: 80, protocol: "tcp", tailnetIP: tailnetIPv4}
	r1 := rule{containerPort: 4003, tailnetPort: 80, protocol: "tcp", tailnetIP: tailnetIPv6}
	r2 := rule{tailnetPort: 53, containerPort: 4004, protocol: "udp", tailnetIP: tailnetIPv4}
	r3 := rule{tailnetPort: 53, containerPort: 4004, protocol: "udp", tailnetIP: tailnetIPv6}
	r4 := rule{containerPort: 4003, tailnetPort: 80, protocol: "tcp", tailnetIP: tailnetIPv4_1}
	r5 := rule{containerPort: 4003, tailnetPort: 80, protocol: "tcp", tailnetIP: tailnetIPv6_1}
	r6 := rule{containerPort: 4005, tailnetPort: 443, protocol: "tcp", tailnetIP: tailnetIPv4}

	tests := []struct {
		name              string
		svcName           string
		tailnetTargetIPs  []netip.Addr
		podIP             string
		spec              egressservices.Config
		status            *egressservices.Status
		wantRulesToAdd    []rule
		wantRulesToDelete []rule
	}{
		{
			name:              "add_fqdn_svc_that_does_not_yet_exist",
			svcName:           "test",
			tailnetTargetIPs:  []netip.Addr{tailnetIPv4, tailnetIPv6},
			spec:              fqdnSpec,
			status:            &egressservices.Status{},
			wantRulesToAdd:    []rule{r, r1},
			wantRulesToDelete: []rule{},
		},
		{
			name:             "fqdn_svc_already_exists",
			svcName:          "test",
			tailnetTargetIPs: []netip.Addr{tailnetIPv4, tailnetIPv6},
			spec:             fqdnSpec,
			status: &egressservices.Status{
				Services: map[string]*egressservices.ServiceStatus{"test": {
					TailnetTargetIPs: []netip.Addr{tailnetIPv4, tailnetIPv6},
					TailnetTarget:    egressservices.TailnetTarget{FQDN: "test"},
					Ports:            ports,
				}}},
			wantRulesToAdd:    []rule{},
			wantRulesToDelete: []rule{},
		},
		{
			name:             "fqdn_svc_already_exists_add_port_remove_port",
			svcName:          "test",
			tailnetTargetIPs: []netip.Addr{tailnetIPv4, tailnetIPv6},
			spec:             fqdnSpec1,
			status: &egressservices.Status{
				Services: map[string]*egressservices.ServiceStatus{"test": {
					TailnetTargetIPs: []netip.Addr{tailnetIPv4, tailnetIPv6},
					TailnetTarget:    egressservices.TailnetTarget{FQDN: "test"},
					Ports:            ports,
				}}},
			wantRulesToAdd:    []rule{r2, r3},
			wantRulesToDelete: []rule{r, r1},
		},
		{
			name:             "fqdn_svc_already_exists_change_fqdn_backend_ips",
			svcName:          "test",
			tailnetTargetIPs: []netip.Addr{tailnetIPv4_1, tailnetIPv6_1},
			spec:             fqdnSpec,
			status: &egressservices.Status{
				Services: map[string]*egressservices.ServiceStatus{"test": {
					TailnetTargetIPs: []netip.Addr{tailnetIPv4, tailnetIPv6},
					TailnetTarget:    egressservices.TailnetTarget{FQDN: "test"},
					Ports:            ports,
				}}},
			wantRulesToAdd:    []rule{r4, r5},
			wantRulesToDelete: []rule{r, r1},
		},
		{
			name:              "add_ip_service",
			svcName:           "test",
			tailnetTargetIPs:  []netip.Addr{tailnetIPv4},
			spec:              fqdnSpec2,
			status:            &egressservices.Status{},
			wantRulesToAdd:    []rule{r},
			wantRulesToDelete: []rule{},
		},
		{
			name:             "add_ip_service_already_exists",
			svcName:          "test",
			tailnetTargetIPs: []netip.Addr{tailnetIPv4},
			spec:             fqdnSpec2,
			status: &egressservices.Status{
				Services: map[string]*egressservices.ServiceStatus{"test": {
					TailnetTargetIPs: []netip.Addr{tailnetIPv4},
					TailnetTarget:    egressservices.TailnetTarget{IP: tailnetIPv4.String()},
					Ports:            ports,
				}}},
			wantRulesToAdd:    []rule{},
			wantRulesToDelete: []rule{},
		},
		{
			name:             "ip_service_add_port",
			svcName:          "test",
			tailnetTargetIPs: []netip.Addr{tailnetIPv4},
			spec:             fqdnSpec3,
			status: &egressservices.Status{
				Services: map[string]*egressservices.ServiceStatus{"test": {
					TailnetTargetIPs: []netip.Addr{tailnetIPv4},
					TailnetTarget:    egressservices.TailnetTarget{IP: tailnetIPv4.String()},
					Ports:            ports,
				}}},
			wantRulesToAdd:    []rule{r6},
			wantRulesToDelete: []rule{},
		},
		{
			name:             "ip_service_delete_port",
			svcName:          "test",
			tailnetTargetIPs: []netip.Addr{tailnetIPv4},
			spec:             fqdnSpec,
			status: &egressservices.Status{
				Services: map[string]*egressservices.ServiceStatus{"test": {
					TailnetTargetIPs: []netip.Addr{tailnetIPv4},
					TailnetTarget:    egressservices.TailnetTarget{IP: tailnetIPv4.String()},
					Ports:            ports2,
				}}},
			wantRulesToAdd:    []rule{},
			wantRulesToDelete: []rule{r6},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRulesToAdd, gotRulesToDelete, err := updatesForCfg(tt.svcName, tt.spec, tt.status, tt.tailnetTargetIPs)
			if err != nil {
				t.Errorf("updatesForSvc() unexpected error %v", err)
				return
			}
			if !reflect.DeepEqual(gotRulesToAdd, tt.wantRulesToAdd) {
				t.Errorf("updatesForSvc() got rulesToAdd = \n%v\n want rulesToAdd \n%v", gotRulesToAdd, tt.wantRulesToAdd)
			}
			if !reflect.DeepEqual(gotRulesToDelete, tt.wantRulesToDelete) {
				t.Errorf("updatesForSvc() got rulesToDelete = \n%v\n want rulesToDelete \n%v", gotRulesToDelete, tt.wantRulesToDelete)
			}
		})
	}
}

// A failure of this test will most likely look like a timeout.
func TestWaitTillSafeToShutdown(t *testing.T) {
	podIP := "10.0.0.1"
	anotherIP := "10.0.0.2"

	tests := []struct {
		name string
		// services is a map of service name to the number of calls to make to the healthcheck endpoint before
		// returning a response that does NOT contain this Pod's IP in headers.
		services       map[string]int
		replicas       int
		healthCheckSet bool
	}{
		{
			name: "no_configs",
		},
		{
			name: "one_service_immediately_safe_to_shutdown",
			services: map[string]int{
				"svc1": 0,
			},
			replicas:       2,
			healthCheckSet: true,
		},
		{
			name: "multiple_services_immediately_safe_to_shutdown",
			services: map[string]int{
				"svc1": 0,
				"svc2": 0,
				"svc3": 0,
			},
			replicas:       2,
			healthCheckSet: true,
		},
		{
			name: "multiple_services_no_healthcheck_endpoints",
			services: map[string]int{
				"svc1": 0,
				"svc2": 0,
				"svc3": 0,
			},
			replicas: 2,
		},
		{
			name: "one_service_eventually_safe_to_shutdown",
			services: map[string]int{
				"svc1": 3, // After 3 calls to health check endpoint, no longer returns this Pod's IP
			},
			replicas:       2,
			healthCheckSet: true,
		},
		{
			name: "multiple_services_eventually_safe_to_shutdown",
			services: map[string]int{
				"svc1": 1, // After 1 call to health check endpoint, no longer returns this Pod's IP
				"svc2": 3, // After 3 calls to health check endpoint, no longer returns this Pod's IP
				"svc3": 5, // After 5 calls to the health check endpoint, no longer returns this Pod's IP
			},
			replicas:       2,
			healthCheckSet: true,
		},
		{
			name: "multiple_services_eventually_safe_to_shutdown_with_higher_replica_count",
			services: map[string]int{
				"svc1": 7,
				"svc2": 10,
			},
			replicas:       5,
			healthCheckSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgs := egressservices.Configs{}
			switches := make(map[string]int)

			for svc, callsToSwitch := range tt.services {
				endpoint := fmt.Sprintf("http://%s.local", svc)
				if tt.healthCheckSet {
					cfgs[svc] = egressservices.Config{
						HealthCheckEndpoint: endpoint,
					}
				}
				switches[endpoint] = callsToSwitch
			}

			ep := &egressProxy{
				podIPv4:    podIP,
				shortSleep: time.Millisecond,
				client: &mockHTTPClient{
					podIP:     podIP,
					anotherIP: anotherIP,
					switches:  switches,
				},
			}

			ep.waitTillSafeToShutdown(context.Background(), cfgs, tt.replicas)
		})
	}
}

// mockHTTPClient is a client that receives an HTTP call for an egress service endpoint and returns a response with an
// IP address in a 'Pod-IPv4' header. It can be configured to return one IP address for N calls, then switch to another
// IP address to simulate a scenario where an IP is eventually no longer a backend for an endpoint.
// TODO(irbekrm): to test this more thoroughly, we should have the client take into account the number of replicas and
// return as if traffic was round robin load balanced across different Pods.
// The tests below cover the contract between how an egress proxy resolves a
// tailnet FQDN target and how it detects that a netmap update changed that
// target's addresses. An FQDN target can be a tailnet device, a Tailscale
// Service or a 4via6 address, and can stop being resolvable at any point. A
// netmap update must trigger a firewall resync exactly when it changes the
// addresses that a configured FQDN target resolves to: never when the addresses
// are unchanged, and always when a target that did not resolve becomes
// resolvable.

const (
	// testTargetFQDN is the FQDN of the target that the tests below move
	// between a tailnet device and a Tailscale Service.
	testTargetFQDN = "foo.tailnet.ts.net"
	// testOtherFQDN is an unrelated tailnet device, used to change the netmap
	// without affecting the target.
	testOtherFQDN = "bar.tailnet.ts.net"

	testDeviceIP1        = "100.64.0.1"
	testDeviceIP2        = "100.64.0.2"
	testOtherDeviceIP    = "100.64.0.3"
	testOtherDeviceIPAlt = "100.64.0.4"
	// testDeviceIP6 is a tailnet IPv6 address of a target device.
	testDeviceIP6 = "fd7a:115c:a1e0::701:b62a"
	// testSvcVIP1 and testSvcVIP2 are consecutive VIPs of the Tailscale
	// Service that testTargetFQDN moves to.
	testSvcVIP1 = "100.100.0.5"
	testSvcVIP2 = "100.100.0.6"
	// testSelfIP is a tailnet address of the egress proxy itself.
	testSelfIP = "100.64.0.10"

	testEgressSvcName = "test"
)

func testAddrPrefixes(ips ...string) []netip.Prefix {
	pfxs := make([]netip.Prefix, 0, len(ips))
	for _, ip := range ips {
		addr := netip.MustParseAddr(ip)
		pfxs = append(pfxs, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return pfxs
}

func testAddrs(ips ...string) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, netip.MustParseAddr(ip))
	}
	return addrs
}

// testEgressNetmapState returns a netmap state as seen by an egress proxy with
// the given self addresses, peers and Tailscale Service DNS records.
func testEgressNetmapState(selfIPs []string, peers []*tailcfg.Node, records []tailcfg.DNSRecord) netmapState {
	self := &tailcfg.Node{
		ID:        tailcfg.NodeID(100),
		Name:      "egress-proxy.tailnet.ts.net.",
		Addresses: testAddrPrefixes(selfIPs...),
	}
	nm := netmapState{
		self:            self.View(),
		dnsExtraRecords: views.SliceOf(records),
	}
	for _, p := range peers {
		nm = nm.upsertPeer(p.View())
	}
	return nm
}

// testDeviceNode returns a tailnet device node with the given FQDN and tailnet
// addresses.
func testDeviceNode(id tailcfg.NodeID, name string, ips ...string) *tailcfg.Node {
	return &tailcfg.Node{ID: id, Name: name, Addresses: testAddrPrefixes(ips...)}
}

// testServiceAdvertiserNode returns a node that advertises the given Tailscale
// Service VIPs as its allowed IPs, the way a ProxyGroup node that backs a
// Tailscale Service does. resolveTailnetFQDN only resolves a Tailscale Service
// if some peer advertises its VIP.
func testServiceAdvertiserNode(id tailcfg.NodeID, name string, vips ...string) *tailcfg.Node {
	return &tailcfg.Node{ID: id, Name: name, AllowedIPs: testAddrPrefixes(vips...)}
}

// testServiceDNSRecord returns a MagicDNS ExtraRecords entry for a Tailscale
// Service VIP.
func testServiceDNSRecord(fqdn, vip string) tailcfg.DNSRecord {
	return tailcfg.DNSRecord{Name: fqdn + ".", Type: "A", Value: vip}
}

// TestShouldResyncOnTailnetTargetChanges verifies that netmap updates that
// change the addresses an FQDN target resolves to are detected with the same
// semantics that sync uses to resolve those addresses. A target that moves
// between a tailnet device, a Tailscale Service and an unresolvable state must
// be detected; an update that leaves the resolved addresses unchanged must not
// trigger a resync.
func TestShouldResyncOnTailnetTargetChanges(t *testing.T) {
	deviceV1 := testDeviceNode(1, testTargetFQDN+".", testDeviceIP1)
	deviceV2 := testDeviceNode(1, testTargetFQDN+".", testDeviceIP2)
	otherDevice := testDeviceNode(2, testOtherFQDN+".", testOtherDeviceIP)
	otherDeviceChanged := testDeviceNode(2, testOtherFQDN+".", testOtherDeviceIPAlt)
	svcAdvertiserV1 := testServiceAdvertiserNode(3, "ingress.tailnet.ts.net.", testSvcVIP1)
	svcAdvertiserV2 := testServiceAdvertiserNode(3, "ingress.tailnet.ts.net.", testSvcVIP2)
	svcAdvertiserBoth := testServiceAdvertiserNode(3, "ingress.tailnet.ts.net.", testSvcVIP1, testSvcVIP2)
	svcRecordsV1 := []tailcfg.DNSRecord{testServiceDNSRecord(testTargetFQDN, testSvcVIP1)}
	svcRecordsV2 := []tailcfg.DNSRecord{testServiceDNSRecord(testTargetFQDN, testSvcVIP2)}
	svcRecordsBoth := append(append([]tailcfg.DNSRecord{}, svcRecordsV1...), svcRecordsV2...)
	self := []string{testSelfIP}

	tests := []struct {
		name         string
		tailnetAddrs []string
		targetFQDNs  map[string][]netip.Prefix
		nm           netmapState
		wantResync   bool
	}{
		{
			name:         "unchanged_device_target",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testDeviceIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{deviceV1}, nil),
			wantResync:   false,
		},
		{
			name:         "device_target_addresses_changed",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testDeviceIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{deviceV2}, nil),
			wantResync:   true,
		},
		{
			name:         "device_target_replaced_by_tailscale_service",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testDeviceIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{svcAdvertiserV1}, svcRecordsV1),
			wantResync:   true,
		},
		{
			name:         "tailscale_service_target_unchanged",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testSvcVIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{svcAdvertiserV1}, svcRecordsV1),
			wantResync:   false,
		},
		{
			name:         "tailscale_service_target_addresses_changed",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testSvcVIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{svcAdvertiserV2}, svcRecordsV2),
			wantResync:   true,
		},
		{
			name:         "tailscale_service_target_addresses_reordered",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testSvcVIP2, testSvcVIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{svcAdvertiserBoth}, svcRecordsBoth),
			wantResync:   false,
		},
		{
			name:         "tailscale_service_target_advertised_by_more_nodes",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testSvcVIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{svcAdvertiserV1, testServiceAdvertiserNode(4, "ingress-2.tailnet.ts.net.", testSvcVIP1)}, svcRecordsV1),
			wantResync:   false,
		},
		{
			name:         "tailscale_service_target_replaced_by_device",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testSvcVIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{deviceV1}, nil),
			wantResync:   true,
		},
		{
			name:         "target_no_longer_resolvable",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testDeviceIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{otherDevice}, nil),
			wantResync:   true,
		},
		{
			name:         "target_still_unresolvable",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: nil},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{otherDevice}, nil),
			wantResync:   false,
		},
		{
			name:         "unresolved_target_becomes_resolvable_as_device",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: nil},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{deviceV1}, nil),
			wantResync:   true,
		},
		{
			name:         "unresolved_target_becomes_resolvable_as_tailscale_service",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: nil},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{svcAdvertiserV1}, svcRecordsV1),
			wantResync:   true,
		},
		{
			name:         "change_to_other_configured_target",
			tailnetAddrs: self,
			targetFQDNs: map[string][]netip.Prefix{
				testTargetFQDN: testAddrPrefixes(testDeviceIP1),
				testOtherFQDN:  testAddrPrefixes(testOtherDeviceIP),
			},
			nm:         testEgressNetmapState(self, []*tailcfg.Node{deviceV1, otherDeviceChanged}, nil),
			wantResync: true,
		},
		{
			name:         "change_to_unconfigured_device",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testDeviceIP1)},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{deviceV1, otherDeviceChanged}, nil),
			wantResync:   false,
		},
		{
			name:         "proxy_tailnet_addresses_changed",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testDeviceIP1)},
			nm:           testEgressNetmapState([]string{"100.64.0.11"}, []*tailcfg.Node{deviceV1}, nil),
			wantResync:   true,
		},
		{
			name:         "no_fqdn_targets",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{},
			nm:           testEgressNetmapState(self, []*tailcfg.Node{deviceV1}, nil),
			wantResync:   false,
		},
		{
			name:         "no_netmap_state_yet",
			tailnetAddrs: self,
			targetFQDNs:  map[string][]netip.Prefix{testTargetFQDN: testAddrPrefixes(testDeviceIP1)},
			nm:           netmapState{},
			wantResync:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Snapshot the recorded target state: shouldResync must not change
			// what the rules that are currently applied forward to, so the
			// state it is given must come back unmodified.
			wantTargetFQDNs := make(map[string][]netip.Prefix, len(tt.targetFQDNs))
			for fqdn, addrs := range tt.targetFQDNs {
				wantTargetFQDNs[fqdn] = slices.Clone(addrs)
			}
			ep := &egressProxy{
				tailnetAddrs: testAddrPrefixes(tt.tailnetAddrs...),
				targetFQDNs:  tt.targetFQDNs,
			}
			if got := ep.shouldResync(tt.nm); got != tt.wantResync {
				t.Errorf("shouldResync() = %v, want %v", got, tt.wantResync)
			}
			if !reflect.DeepEqual(ep.targetFQDNs, wantTargetFQDNs) {
				t.Errorf("shouldResync() changed the recorded target addresses to %v, want %v: the recorded addresses must only be updated by a sync that has applied them", ep.targetFQDNs, wantTargetFQDNs)
			}
		})
	}
}

// TestTailnetTargetIPsForSvcResolvesTargets verifies the addresses that
// resolution produces for each kind of target: a resolvable device, a resolvable
// Tailscale Service, a target that does not resolve and a target for which the
// netmap is not available yet. The resolution result is what determines whether
// a later netmap update needs a resync and is recorded for every configured FQDN
// target by sync.
func TestTailnetTargetIPsForSvcResolvesTargets(t *testing.T) {
	device := testDeviceNode(1, testTargetFQDN+".", testDeviceIP1)
	svcAdvertiser := testServiceAdvertiserNode(3, "ingress.tailnet.ts.net.", testSvcVIP1)
	fqdnSvc := egressservices.Config{TailnetTarget: egressservices.TailnetTarget{FQDN: testTargetFQDN}}
	ipSvc := egressservices.Config{TailnetTarget: egressservices.TailnetTarget{IP: testDeviceIP1}}
	self := []string{testSelfIP}

	tests := []struct {
		name         string
		svc          egressservices.Config
		nm           netmapState
		wantAddrs    []netip.Addr
		wantResolved []netip.Prefix
	}{
		{
			name:         "resolvable_device_target",
			svc:          fqdnSvc,
			nm:           testEgressNetmapState(self, []*tailcfg.Node{device}, nil),
			wantAddrs:    testAddrs(testDeviceIP1),
			wantResolved: testAddrPrefixes(testDeviceIP1),
		},
		{
			name:         "resolvable_tailscale_service_target",
			svc:          fqdnSvc,
			nm:           testEgressNetmapState(self, []*tailcfg.Node{svcAdvertiser}, []tailcfg.DNSRecord{testServiceDNSRecord(testTargetFQDN, testSvcVIP1)}),
			wantAddrs:    testAddrs(testSvcVIP1),
			wantResolved: testAddrPrefixes(testSvcVIP1),
		},
		{
			name:      "unresolvable_target",
			svc:       fqdnSvc,
			nm:        testEgressNetmapState(self, nil, nil),
			wantAddrs: nil,
			// The target did not resolve: recording it with no addresses is
			// what makes a later netmap update that makes it resolvable
			// trigger a resync.
			wantResolved: nil,
		},
		{
			name:         "no_netmap_state_yet",
			svc:          fqdnSvc,
			nm:           netmapState{},
			wantAddrs:    nil,
			wantResolved: nil,
		},
		{
			name:         "ip_target",
			svc:          ipSvc,
			nm:           testEgressNetmapState(self, []*tailcfg.Node{device}, nil),
			wantAddrs:    testAddrs(testDeviceIP1),
			wantResolved: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &egressProxy{nfr: linuxfw.NewFakeNetfilterRunner()}
			gotAddrs, gotResolved, err := ep.tailnetTargetIPsForSvc(tt.svc, tt.nm)
			if err != nil {
				t.Fatalf("tailnetTargetIPsForSvc() unexpected error: %v", err)
			}
			if !slices.Equal(gotAddrs, tt.wantAddrs) {
				t.Errorf("tailnetTargetIPsForSvc() addresses = %v, want %v", gotAddrs, tt.wantAddrs)
			}
			if !slices.Equal(gotResolved, tt.wantResolved) {
				t.Errorf("tailnetTargetIPsForSvc() resolved = %v, want %v", gotResolved, tt.wantResolved)
			}
		})
	}
}

// TestSyncRecordsResolvedTargets verifies that sync records the addresses that
// each configured FQDN target resolved to, including a target that did not
// resolve, and that a target that becomes resolvable on a later netmap update is
// detected and applied. Without a record for an unresolved target, no later
// netmap update could ever trigger a retry for it.
func TestSyncRecordsResolvedTargets(t *testing.T) {
	cfgPath := t.TempDir()
	cfgs := egressservices.Configs{testEgressSvcName: egressservices.Config{
		TailnetTarget: egressservices.TailnetTarget{FQDN: testTargetFQDN},
		Ports:         egressservices.PortMaps{{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}: {}},
	}}
	if err := os.WriteFile(filepath.Join(cfgPath, egressservices.KeyEgressServices), mustJSON(t, cfgs), 0600); err != nil {
		t.Fatal(err)
	}
	kc, status, _ := fakeEgressStateClient(t)
	ep := &egressProxy{
		cfgPath:     cfgPath,
		nfr:         newRecordingNetfilter(),
		kc:          kc,
		stateSecret: "state",
		podIPv4:     "10.0.0.1",
	}
	self := []string{testSelfIP}
	targetGoneNM := testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(2, testOtherFQDN+".", testOtherDeviceIP)}, nil)
	deviceNM := testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(1, testTargetFQDN+".", testDeviceIP1)}, nil)

	if err := ep.sync(t.Context(), targetGoneNM); err != nil {
		t.Fatalf("sync() with an unresolvable target: %v", err)
	}
	recorded, ok := ep.targetFQDNs[testTargetFQDN]
	if !ok {
		t.Fatalf("target %q was not recorded after a sync: an unresolved target must be recorded with no addresses so that a later netmap update triggers a retry", testTargetFQDN)
	}
	if len(recorded) != 0 {
		t.Errorf("recorded addresses for an unresolved target = %v, want none", recorded)
	}
	if st := status(); st == nil || len(st.Services[testEgressSvcName].TailnetTargetIPs) != 0 {
		t.Errorf("state Secret records target IPs %v for an unresolved target, want none", st)
	}

	if !ep.shouldResync(deviceNM) {
		t.Errorf("shouldResync() = false for a netmap update that makes an unresolved target resolvable, want true")
	}
	if err := ep.sync(t.Context(), deviceNM); err != nil {
		t.Fatalf("sync() with a resolvable target: %v", err)
	}
	if got := ep.targetFQDNs[testTargetFQDN]; !slices.Equal(got, testAddrPrefixes(testDeviceIP1)) {
		t.Errorf("recorded addresses = %v, want %v", got, testAddrPrefixes(testDeviceIP1))
	}
	if st := status(); st == nil || !slices.Equal(st.Services[testEgressSvcName].TailnetTargetIPs, testAddrs(testDeviceIP1)) {
		t.Errorf("state Secret does not record the resolved target IPs %v: %v", testAddrs(testDeviceIP1), st)
	}

	// A target that has both an IP and an FQDN configured is forwarded to the
	// IP, so it has no resolved addresses that a netmap update could change,
	// and re-checking its FQDN on every netmap update would resync the proxy
	// forever.
	t.Run("target_with_ip_is_not_recorded", func(t *testing.T) {
		cfgPath := t.TempDir()
		cfgs := egressservices.Configs{testEgressSvcName: egressservices.Config{
			TailnetTarget: egressservices.TailnetTarget{IP: testDeviceIP2, FQDN: testTargetFQDN},
			Ports:         egressservices.PortMaps{{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}: {}},
		}}
		if err := os.WriteFile(filepath.Join(cfgPath, egressservices.KeyEgressServices), mustJSON(t, cfgs), 0600); err != nil {
			t.Fatal(err)
		}
		kc, status, _ := fakeEgressStateClient(t)
		ep := &egressProxy{
			cfgPath:     cfgPath,
			nfr:         newRecordingNetfilter(),
			kc:          kc,
			stateSecret: "state",
			podIPv4:     "10.0.0.1",
		}
		if err := ep.sync(t.Context(), testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(1, testTargetFQDN+".", testDeviceIP1)}, nil)); err != nil {
			t.Fatalf("sync(): %v", err)
		}
		if _, ok := ep.targetFQDNs[testTargetFQDN]; ok {
			t.Errorf("target %q with an IP configured was recorded with resolved addresses %v: forwarding follows the configured IP, not the FQDN, so a netmap update cannot change it", testTargetFQDN, ep.targetFQDNs[testTargetFQDN])
		}
		if st := status(); st == nil || !slices.Equal(st.Services[testEgressSvcName].TailnetTargetIPs, testAddrs(testDeviceIP2)) {
			t.Errorf("state Secret does not record the configured target IP %v: %v", testAddrs(testDeviceIP2), st)
		}
		if ep.shouldResync(testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(1, testTargetFQDN+".", testOtherDeviceIP)}, nil)) {
			t.Errorf("shouldResync() = true for a netmap update that changed only what the FQDN of a target configured by IP resolves to, want false")
		}
	})

	// An FQDN target that is no longer configured must stop being compared to
	// the netmap: its recorded addresses would otherwise make every later
	// netmap update that moves the target trigger a resync for a service that
	// no longer exists.
	t.Run("config_removed_clears_recorded_targets", func(t *testing.T) {
		cfgPath := t.TempDir()
		writeCfgs := func(cfgs egressservices.Configs) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(cfgPath, egressservices.KeyEgressServices), mustJSON(t, cfgs), 0600); err != nil {
				t.Fatal(err)
			}
		}
		writeCfgs(egressservices.Configs{testEgressSvcName: egressservices.Config{
			TailnetTarget: egressservices.TailnetTarget{FQDN: testTargetFQDN},
			Ports:         egressservices.PortMaps{{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}: {}},
		}})
		kc, status, _ := fakeEgressStateClient(t)
		nfr := newRecordingNetfilter()
		ep := &egressProxy{
			cfgPath:     cfgPath,
			nfr:         nfr,
			kc:          kc,
			stateSecret: "state",
			podIPv4:     "10.0.0.1",
		}
		if err := ep.sync(t.Context(), testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(1, testTargetFQDN+".", testDeviceIP1)}, nil)); err != nil {
			t.Fatalf("sync() with a configured target: %v", err)
		}
		if got := ep.targetFQDNs[testTargetFQDN]; !slices.Equal(got, testAddrPrefixes(testDeviceIP1)) {
			t.Fatalf("recorded addresses = %v, want %v", got, testAddrPrefixes(testDeviceIP1))
		}

		// The egress service is removed from the config, e.g. because the
		// user deleted it.
		writeCfgs(egressservices.Configs{})
		if err := ep.sync(t.Context(), testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(1, testTargetFQDN+".", testDeviceIP1)}, nil)); err != nil {
			t.Fatalf("sync() after the target was deconfigured: %v", err)
		}
		if len(ep.targetFQDNs) != 0 {
			t.Errorf("recorded target addresses %v after the target was deconfigured, want none", ep.targetFQDNs)
		}
		if st := status(); st == nil || len(st.Services) != 0 {
			t.Errorf("state Secret records services %v after the target was deconfigured, want none", st)
		}
		if got := nfr.svcDeletions(); !slices.Equal(got, testAddrs(testDeviceIP1)) {
			t.Errorf("proxy removed rules for services with target addresses %v, want %v", got, testAddrs(testDeviceIP1))
		}
		if ep.shouldResync(testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(1, testTargetFQDN+".", testOtherDeviceIP)}, nil)) {
			t.Errorf("shouldResync() = true for a netmap update after the target was deconfigured, want false")
		}
	})
}

// TestSyncRecordsResolutionForDualStackTarget verifies that the addresses that
// sync records and compares are the addresses the target resolved to, not the
// subset that this host's firewall can program. On a host without IPv6 NAT a
// dual-stack target keeps resolving to both families while only IPv4 rules are
// installed; comparing the programmed subset against the resolution would resync
// the proxy on every netmap update forever.
func TestSyncRecordsResolutionForDualStackTarget(t *testing.T) {
	cfgPath := t.TempDir()
	cfgs := egressservices.Configs{testEgressSvcName: egressservices.Config{
		TailnetTarget: egressservices.TailnetTarget{FQDN: testTargetFQDN},
		Ports:         egressservices.PortMaps{{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}: {}},
	}}
	if err := os.WriteFile(filepath.Join(cfgPath, egressservices.KeyEgressServices), mustJSON(t, cfgs), 0600); err != nil {
		t.Fatal(err)
	}
	kc, status, kubeCalls := fakeEgressStateClient(t)
	nfr := newRecordingNetfilter()
	nfr.ipv6NAT = false
	ep := &egressProxy{
		cfgPath:     cfgPath,
		nfr:         nfr,
		kc:          kc,
		stateSecret: "state",
		podIPv4:     "10.0.0.1",
	}
	self := []string{testSelfIP}
	dualStackNM := testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(1, testTargetFQDN+".", testDeviceIP1, testDeviceIP6)}, nil)
	otherDeviceNM := testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(2, testOtherFQDN+".", testOtherDeviceIP)}, nil)

	if err := ep.sync(t.Context(), dualStackNM); err != nil {
		t.Fatalf("sync(): %v", err)
	}
	// Only the IPv4 address can be programmed on this host.
	if added, _ := nfr.rules(); !slices.Equal(added, testAddrs(testDeviceIP1)) {
		t.Errorf("proxy added rules for %v, want only the IPv4 target %v", added, testAddrs(testDeviceIP1))
	}
	if st := status(); st == nil || !slices.Equal(st.Services[testEgressSvcName].TailnetTargetIPs, testAddrs(testDeviceIP1)) {
		t.Errorf("state Secret records target IPs %v, want only the IPv4 target %v", st, testAddrs(testDeviceIP1))
	}
	// The addresses recorded for comparison are the resolution's, so a netmap
	// update that re-resolves the same target must not resync.
	if got := ep.targetFQDNs[testTargetFQDN]; !slices.Equal(got, testAddrPrefixes(testDeviceIP1, testDeviceIP6)) {
		t.Errorf("recorded addresses = %v, want the resolved addresses %v", got, testAddrPrefixes(testDeviceIP1, testDeviceIP6))
	}
	if ep.shouldResync(dualStackNM) {
		t.Errorf("shouldResync() = true for a netmap update that did not change the resolved addresses of a dual-stack target, want false")
	}
	// A netmap update that does change them must still be detected.
	if !ep.shouldResync(otherDeviceNM) {
		t.Errorf("shouldResync() = false for a netmap update that made a dual-stack target unresolvable, want true")
	}
	if reads, patches := kubeCalls(); reads-patches != 1 {
		t.Errorf("egress proxy synced %d times (status reads %d, status writes %d), want 1", reads-patches, reads, patches)
	}
}

// TestEgressProxyTargetLifecycle drives the egress proxy's run loop through the
// lifecycle of an FQDN target: an address change of a device target, a device
// target replaced by a Tailscale Service, a Tailscale Service target whose VIPs
// change, a Tailscale Service replaced by a device, a target that stops being
// resolvable, a target that stays unresolvable and a target that becomes
// resolvable again. For each transition it asserts the addresses the proxy
// forwards to (as recorded in the state Secret that the operator reads) and the
// firewall rules it adds and deletes, and it asserts that netmap updates that do
// not change the resolved target addresses cause no work at all.
func TestEgressProxyTargetLifecycle(t *testing.T) {
	cfgPath := t.TempDir()
	cfgs := egressservices.Configs{testEgressSvcName: egressservices.Config{
		TailnetTarget: egressservices.TailnetTarget{FQDN: testTargetFQDN},
		Ports:         egressservices.PortMaps{{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}: {}},
	}}
	if err := os.WriteFile(filepath.Join(cfgPath, egressservices.KeyEgressServices), mustJSON(t, cfgs), 0600); err != nil {
		t.Fatal(err)
	}

	kc, status, kubeCalls := fakeEgressStateClient(t)
	nfr := newRecordingNetfilter()
	ep := &egressProxy{}
	self := []string{testSelfIP}

	deviceV1NM := testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(1, testTargetFQDN+".", testDeviceIP1)}, nil)
	deviceV2NM := testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(1, testTargetFQDN+".", testDeviceIP2)}, nil)
	targetGoneNM := testEgressNetmapState(self, []*tailcfg.Node{testDeviceNode(2, testOtherFQDN+".", testOtherDeviceIP)}, nil)
	svcV1NM := testEgressNetmapState(self, []*tailcfg.Node{testServiceAdvertiserNode(3, "ingress.tailnet.ts.net.", testSvcVIP1)}, []tailcfg.DNSRecord{testServiceDNSRecord(testTargetFQDN, testSvcVIP1)})
	svcV2NM := testEgressNetmapState(self, []*tailcfg.Node{testServiceAdvertiserNode(3, "ingress.tailnet.ts.net.", testSvcVIP2)}, []tailcfg.DNSRecord{testServiceDNSRecord(testTargetFQDN, testSvcVIP2)})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nmChan := make(chan netmapState)
	var (
		runMu     sync.Mutex
		runResult error
	)
	runDone := make(chan struct{})
	go func() {
		err := ep.run(ctx, deviceV1NM, egressProxyRunOpts{
			cfgPath:      cfgPath,
			nfr:          nfr,
			kc:           kc,
			stateSecret:  "state",
			netmapChan:   nmChan,
			podIPv4:      "10.0.0.1",
			tailnetAddrs: testAddrPrefixes(testSelfIP),
		})
		runMu.Lock()
		runResult = err
		runMu.Unlock()
		close(runDone)
	}()
	waitForEgressTargets := func(want ...string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-runDone:
				runMu.Lock()
				err := runResult
				runMu.Unlock()
				t.Fatalf("egress proxy run loop exited: %v", err)
			default:
			}
			if st := status(); st != nil {
				if svc, ok := st.Services[testEgressSvcName]; ok && slices.Equal(svc.TailnetTargetIPs, testAddrs(want...)) {
					return
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		var got []netip.Addr
		if st := status(); st != nil {
			if svc, ok := st.Services[testEgressSvcName]; ok {
				got = svc.TailnetTargetIPs
			}
		}
		t.Fatalf("timed out waiting for tailnet target IPs %v in the state Secret, last saw %v", testAddrs(want...), got)
	}
	sendNetmap := func(nm netmapState) {
		t.Helper()
		select {
		case nmChan <- nm:
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out sending a netmap update: the egress proxy is not reading netmap updates")
		}
	}

	waitForEgressTargets(testDeviceIP1)

	steps := []struct {
		name string
		nm   netmapState
		// wantResync is whether this netmap update must trigger a resync.
		wantResync bool
		// wantTargets are the tailnet addresses the proxy must forward to
		// after this update.
		wantTargets []string
		// wantAdded and wantDeleted are the firewall rules this update must
		// add and delete.
		wantAdded   []string
		wantDeleted []string
	}{
		{
			name:        "unchanged_device_target",
			nm:          deviceV1NM,
			wantResync:  false,
			wantTargets: []string{testDeviceIP1},
		},
		{
			name:        "device_target_addresses_changed",
			nm:          deviceV2NM,
			wantResync:  true,
			wantTargets: []string{testDeviceIP2},
			wantAdded:   []string{testDeviceIP2},
			wantDeleted: []string{testDeviceIP1},
		},
		{
			name:        "device_target_replaced_by_tailscale_service",
			nm:          svcV1NM,
			wantResync:  true,
			wantTargets: []string{testSvcVIP1},
			wantAdded:   []string{testSvcVIP1},
			wantDeleted: []string{testDeviceIP2},
		},
		{
			name:        "unchanged_tailscale_service_target",
			nm:          svcV1NM,
			wantResync:  false,
			wantTargets: []string{testSvcVIP1},
		},
		{
			name:        "tailscale_service_target_addresses_changed",
			nm:          svcV2NM,
			wantResync:  true,
			wantTargets: []string{testSvcVIP2},
			wantAdded:   []string{testSvcVIP2},
			wantDeleted: []string{testSvcVIP1},
		},
		{
			name:        "tailscale_service_target_replaced_by_device",
			nm:          deviceV1NM,
			wantResync:  true,
			wantTargets: []string{testDeviceIP1},
			wantAdded:   []string{testDeviceIP1},
			wantDeleted: []string{testSvcVIP2},
		},
		{
			name:        "target_no_longer_resolvable",
			nm:          targetGoneNM,
			wantResync:  true,
			wantTargets: nil,
			wantDeleted: []string{testDeviceIP1},
		},
		{
			name:        "target_still_unresolvable",
			nm:          targetGoneNM,
			wantResync:  false,
			wantTargets: nil,
		},
		{
			name:        "unresolved_target_becomes_resolvable",
			nm:          svcV1NM,
			wantResync:  true,
			wantTargets: []string{testSvcVIP1},
			wantAdded:   []string{testSvcVIP1},
		},
		{
			name:        "tailscale_service_target_replaced_by_device_again",
			nm:          deviceV1NM,
			wantResync:  true,
			wantTargets: []string{testDeviceIP1},
			wantAdded:   []string{testDeviceIP1},
			wantDeleted: []string{testSvcVIP1},
		},
	}
	wantSyncs := 1 // the initial sync performed on startup
	for _, step := range steps {
		addedBefore, deletedBefore := nfr.ruleCounts()
		sendNetmap(step.nm)
		if step.wantResync {
			wantSyncs++
			waitForEgressTargets(step.wantTargets...)
		}
		added, deleted := nfr.rules()
		if got := added[addedBefore:]; !slices.Equal(got, testAddrs(step.wantAdded...)) {
			t.Errorf("%s: proxy added rules for %v, want %v", step.name, got, testAddrs(step.wantAdded...))
		}
		if got := deleted[deletedBefore:]; !slices.Equal(got, testAddrs(step.wantDeleted...)) {
			t.Errorf("%s: proxy deleted rules for %v, want %v", step.name, got, testAddrs(step.wantDeleted...))
		}
	}

	// Two netmap updates that arrive while a sync is in flight are queued on
	// the proxy's unbuffered netmap channel and must both be applied, in order:
	// the proxy must end up forwarding to the addresses of the last update.
	queuedAddedBefore, queuedDeletedBefore := nfr.ruleCounts()
	sendNetmap(svcV1NM)
	sendNetmap(svcV2NM)
	waitForEgressTargets(testSvcVIP2)
	wantSyncs += 2
	added, deleted := nfr.rules()
	if got := added[queuedAddedBefore:]; !slices.Equal(got, testAddrs(testSvcVIP1, testSvcVIP2)) {
		t.Errorf("queued netmap updates: proxy added rules for %v, want %v", got, testAddrs(testSvcVIP1, testSvcVIP2))
	}
	if got := deleted[queuedDeletedBefore:]; !slices.Equal(got, testAddrs(testDeviceIP1, testSvcVIP1)) {
		t.Errorf("queued netmap updates: proxy deleted rules for %v, want %v", got, testAddrs(testDeviceIP1, testSvcVIP1))
	}

	cancel()
	<-runDone
	runMu.Lock()
	err := runResult
	runMu.Unlock()
	if err != nil {
		t.Fatalf("egress proxy run loop returned an error: %v", err)
	}
	if reads, patches := kubeCalls(); reads-patches != wantSyncs {
		t.Errorf("egress proxy synced %d times (status reads %d, status writes %d), want %d: netmap updates that do not change the resolved target addresses must not trigger a resync", reads-patches, reads, patches, wantSyncs)
	}
}

// recordingNetfilter is a fake firewall that records the tailnet target
// addresses for which the egress proxy added or deleted rules.
type recordingNetfilter struct {
	*linuxfw.FakeNetfilterRunner
	// ipv6NAT reports whether the fake host supports IPv6 NAT. It is separate
	// from the embedded fake because the egress proxy programs IPv6 target
	// addresses only when it does.
	ipv6NAT bool
	mu      sync.Mutex
	added   []netip.Addr
	deleted []netip.Addr
	// deletedSvc is the target addresses of egress services that were removed
	// from the firewall as a whole.
	deletedSvc []netip.Addr
}

func newRecordingNetfilter() *recordingNetfilter {
	return &recordingNetfilter{
		FakeNetfilterRunner: linuxfw.NewFakeNetfilterRunner(),
		ipv6NAT:             true,
	}
}

func (r *recordingNetfilter) HasIPV6NAT() bool { return r.ipv6NAT }

func (r *recordingNetfilter) EnsurePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm linuxfw.PortMap) error {
	r.mu.Lock()
	r.added = append(r.added, targetIP)
	r.mu.Unlock()
	return r.FakeNetfilterRunner.EnsurePortMapRuleForSvc(svc, tun, targetIP, pm)
}

func (r *recordingNetfilter) DeletePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm linuxfw.PortMap) error {
	r.mu.Lock()
	r.deleted = append(r.deleted, targetIP)
	r.mu.Unlock()
	return r.FakeNetfilterRunner.DeletePortMapRuleForSvc(svc, tun, targetIP, pm)
}

// DeleteSvc is called when an egress service is removed from the firewall as a
// whole, e.g. when its config is deleted.
func (r *recordingNetfilter) DeleteSvc(svc, tun string, targetIPs []netip.Addr, pms []linuxfw.PortMap) error {
	r.mu.Lock()
	r.deletedSvc = append(r.deletedSvc, targetIPs...)
	r.mu.Unlock()
	return r.FakeNetfilterRunner.DeleteSvc(svc, tun, targetIPs, pms)
}

// svcDeletions returns the target addresses of the egress services that were
// removed from the firewall as a whole.
func (r *recordingNetfilter) svcDeletions() []netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.deletedSvc)
}

func (r *recordingNetfilter) rules() (added, deleted []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.added), slices.Clone(r.deleted)
}

func (r *recordingNetfilter) ruleCounts() (added, deleted int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.added), len(r.deleted)
}

// fakeEgressStateClient returns a fake Kubernetes client that stores the egress
// proxy status in an in-memory state Secret, along with accessors for the status
// it currently holds and for the number of times the client was asked to read
// the Secret and to patch it. A proxy sync reads the status exactly once, and
// each status write reads it once more, so reads minus patches is the number of
// syncs the proxy performed.
func fakeEgressStateClient(t *testing.T) (*kubeclient.FakeClient, func() *egressservices.Status, func() (reads, patches int)) {
	t.Helper()
	var (
		mu      sync.Mutex
		secret  = &kubeapi.Secret{Data: map[string][]byte{}}
		reads   int
		patches int
	)
	kc := &kubeclient.FakeClient{
		GetSecretImpl: func(ctx context.Context, name string) (*kubeapi.Secret, error) {
			mu.Lock()
			defer mu.Unlock()
			reads++
			// Return a copy, so that a local mutation of the value that the
			// proxy receives is only observable once the proxy patches the
			// Secret, as it is against the Kubernetes API.
			return &kubeapi.Secret{
				ObjectMeta: secret.ObjectMeta,
				Data:       maps.Clone(secret.Data),
			}, nil
		},
		JSONPatchResourceImpl: func(ctx context.Context, name, typ string, patch []kubeclient.JSONPatch) error {
			mu.Lock()
			defer mu.Unlock()
			if name != "state" || typ != kubeclient.TypeSecrets {
				return fmt.Errorf("unexpected patch to %s %s", typ, name)
			}
			for _, p := range patch {
				if p.Path != "/data/"+egressservices.KeyEgressServices {
					return fmt.Errorf("unexpected patch path %q", p.Path)
				}
				bs, ok := p.Value.([]byte)
				if !ok {
					return fmt.Errorf("unexpected patch value of type %T", p.Value)
				}
				secret.Data[egressservices.KeyEgressServices] = bs
				patches++
			}
			return nil
		},
	}
	status := func() *egressservices.Status {
		mu.Lock()
		defer mu.Unlock()
		raw, ok := secret.Data[egressservices.KeyEgressServices]
		if !ok {
			return nil
		}
		st := &egressservices.Status{}
		if err := json.Unmarshal(raw, st); err != nil {
			t.Fatalf("error unmarshalling egress proxy status %q: %v", raw, err)
		}
		return st
	}
	kubeCalls := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return reads, patches
	}
	return kc, status, kubeCalls
}

type mockHTTPClient struct {
	// podIP - initial IP address to return, that matches the current proxy's IP address.
	podIP     string
	anotherIP string
	// after how many calls to an endpoint, the client should start returning 'anotherIP' instead of 'podIP.
	switches map[string]int
	mu       sync.Mutex // protects the following
	// calls tracks the number of calls received.
	calls map[string]int
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	if m.calls == nil {
		m.calls = make(map[string]int)
	}

	endpoint := req.URL.String()
	m.calls[endpoint]++
	calls := m.calls[endpoint]
	m.mu.Unlock()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
	}

	if calls <= m.switches[endpoint] {
		resp.Header.Set(kubetypes.PodIPv4Header, m.podIP) // Pod is still routable
	} else {
		resp.Header.Set(kubetypes.PodIPv4Header, m.anotherIP) // Pod is no longer routable
	}
	return resp, nil
}
