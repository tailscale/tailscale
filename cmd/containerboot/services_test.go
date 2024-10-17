// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/kube/egressservices"
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
