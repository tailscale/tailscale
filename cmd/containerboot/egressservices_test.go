// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	kubeutils "tailscale.com/k8s-operator"
	"tailscale.com/kube/egressservices"
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

func TestShouldResync(t *testing.T) {
	const fqdn = "foo.tailnetxyz.ts.net"
	const viaFQDN = "10-1-0-5-via-7.tailnetxyz.ts.net"
	// IPv6 is needed to set up SNAT for the 4via6 target.
	self := &tailcfg.Node{ID: 1, Name: "egress-0.tailnetxyz.ts.net.", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0::1/128")}}
	vip := netip.MustParsePrefix("100.100.0.5/32")

	// unresolved returns a netmap in which fqdn does not resolve.
	unresolved := func() netmapState {
		return netmapState{self: self.View()}
	}
	// device returns a netmap in which fqdn is a peer device with addrs.
	device := func(addrs ...string) netmapState {
		n := &tailcfg.Node{ID: 2, Name: fqdn + "."}
		for _, a := range addrs {
			n.Addresses = append(n.Addresses, netip.MustParsePrefix(a))
		}
		return unresolved().upsertPeer(n.View())
	}
	// service returns a netmap in which fqdn is a Tailscale Service, with
	// hosts peers advertising it.
	service := func(hosts int) netmapState {
		nm := unresolved()
		for i := range hosts {
			hostIP := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, byte(10 + i)}), 32)
			host := &tailcfg.Node{ID: tailcfg.NodeID(10 + i), Name: fmt.Sprintf("ingress-%d.tailnetxyz.ts.net.", i), Addresses: []netip.Prefix{hostIP}, AllowedIPs: []netip.Prefix{hostIP, vip}}
			nm = nm.upsertPeer(host.View())
		}
		nm.dnsExtraRecords = views.SliceOf([]tailcfg.DNSRecord{{Name: fqdn + ".", Type: "A", Value: vip.Addr().String()}})
		return nm
	}
	// via returns a netmap with a subnet router, advertising the 4via6
	// route for viaFQDN if advertised is true.
	via := func(advertised bool) netmapState {
		routerIP := netip.MustParsePrefix("100.64.0.6/32")
		router := &tailcfg.Node{ID: 6, Name: "router.tailnetxyz.ts.net.", Addresses: []netip.Prefix{routerIP}, AllowedIPs: []netip.Prefix{routerIP}}
		if advertised {
			addr, _ := kubeutils.ResolveViaDomain(viaFQDN)
			router.AllowedIPs = append(router.AllowedIPs, netip.PrefixFrom(addr, 120).Masked())
		}
		return unresolved().upsertPeer(router.View())
	}

	tests := []struct {
		name    string
		target  string      // FQDN, fqdn if empty
		synced  netmapState // netmap at the last sync
		current netmapState // netmap in the update
		removed bool        // target removed from config before the update
		want    bool
	}{
		{name: "device_unchanged", synced: device("100.64.0.2/32"), current: device("100.64.0.2/32")},
		{name: "device_addresses_changed", synced: device("100.64.0.2/32"), current: device("100.64.0.4/32"), want: true},
		{name: "device_recovers_after_no_addresses", synced: device(), current: device("100.64.0.2/32"), want: true},
		{name: "device_appears_after_failed_lookup", synced: unresolved(), current: device("100.64.0.2/32"), want: true},
		{name: "service_appears_after_failed_lookup", synced: unresolved(), current: service(1), want: true},
		{name: "device_removed", synced: device("100.64.0.2/32"), current: unresolved(), want: true},
		{name: "service_unchanged", synced: service(1), current: service(1)},
		{name: "service_gains_second_host", synced: service(1), current: service(2)},
		{name: "service_loses_host", synced: service(1), current: service(0), want: true},
		{name: "service_recovers_after_no_host", synced: service(0), current: service(1), want: true},
		{name: "device_replaced_by_service", synced: device("100.64.0.2/32"), current: service(1), want: true},
		{name: "via_route_withdrawn", target: viaFQDN, synced: via(true), current: via(false), want: true},
		{name: "via_route_advertised", target: viaFQDN, synced: via(false), current: via(true), want: true},
		{name: "via_route_unchanged", target: viaFQDN, synced: via(true), current: via(true)},
		{name: "unresolved_target_unchanged", synced: unresolved(), current: unresolved()},
		{name: "removed_target_ignored", synced: device("100.64.0.2/32"), current: unresolved(), removed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &egressProxy{
				nfr:          linuxfw.NewFakeNetfilterRunner(),
				tailnetAddrs: self.Addresses,
			}
			cfgs := egressservices.Configs{
				"foo": {
					TailnetTarget: egressservices.TailnetTarget{FQDN: cmp.Or(tt.target, fqdn)},
					Ports:         egressservices.PortMaps{{Protocol: "tcp", MatchPort: 4003, TargetPort: 80}: {}},
				},
			}
			if _, err := ep.syncEgressConfigs(cfgs, nil, tt.synced); err != nil {
				t.Fatalf("syncEgressConfigs() error = %v", err)
			}
			if tt.removed {
				if _, err := ep.syncEgressConfigs(nil, nil, tt.synced); err != nil {
					t.Fatalf("syncEgressConfigs() error = %v", err)
				}
			}

			if got := ep.shouldResync(tt.current); got != tt.want {
				t.Errorf("shouldResync() = %v, want %v", got, tt.want)
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
