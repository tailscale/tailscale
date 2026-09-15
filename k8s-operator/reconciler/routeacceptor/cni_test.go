// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

func TestDataPlaneFromCiliumConfig(t *testing.T) {
	tests := []struct {
		name string
		data map[string]string
		want dataPlane
	}{
		{
			name: "ebpf-host-routing",
			data: map[string]string{
				"enable-bpf-masquerade":  "true",
				"kube-proxy-replacement": "true",
				"devices":                "eth0",
			},
			want: dataPlane{cilium: true, ebpfHostRouting: true, masquerade: true, devices: []string{"eth0"}},
		},
		{
			name: "ip-masq-agent-and-masquerade-off",
			data: map[string]string{
				"enable-ip-masq-agent":   "true",
				"enable-ipv4-masquerade": "false",
			},
			want: dataPlane{cilium: true, ipMasqAgent: true},
		},
		{
			name: "strict-kube-proxy-replacement",
			data: map[string]string{
				"enable-bpf-masquerade":  "true",
				"kube-proxy-replacement": "strict",
			},
			want: dataPlane{cilium: true, ebpfHostRouting: true, masquerade: true},
		},
		{
			name: "legacy-host-routing",
			data: map[string]string{
				"enable-bpf-masquerade":      "true",
				"kube-proxy-replacement":     "true",
				"enable-host-legacy-routing": "true",
			},
			want: dataPlane{cilium: true, masquerade: true},
		},
		{
			name: "no-bpf-masquerade",
			data: map[string]string{
				"enable-bpf-masquerade":  "false",
				"kube-proxy-replacement": "true",
			},
			want: dataPlane{cilium: true, masquerade: true},
		},
		{
			name: "no-conntrack-and-egress-gateway",
			data: map[string]string{
				"install-no-conntrack-iptables-rules": "true",
				"enable-egress-gateway":               "true",
				"devices":                             "eth0,tailscale0",
			},
			want: dataPlane{cilium: true, masquerade: true, noConntrack: true, egressGateway: true, devices: []string{"eth0", "tailscale0"}},
		},
		{
			name: "old-egress-gateway-flag-and-space-separated-devices",
			data: map[string]string{
				"enable-ipv4-egress-gateway": "true",
				"devices":                    "eth+ tailscale+",
			},
			want: dataPlane{cilium: true, masquerade: true, egressGateway: true, devices: []string{"eth+", "tailscale+"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dataPlaneFromCiliumConfig(tt.data)
			if got.cilium != tt.want.cilium || got.ebpfHostRouting != tt.want.ebpfHostRouting || got.noConntrack != tt.want.noConntrack ||
				got.egressGateway != tt.want.egressGateway || got.masquerade != tt.want.masquerade || got.ipMasqAgent != tt.want.ipMasqAgent {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			if len(got.devices) != len(tt.want.devices) {
				t.Errorf("devices = %v, want %v", got.devices, tt.want.devices)
			} else {
				for i := range got.devices {
					if got.devices[i] != tt.want.devices[i] {
						t.Errorf("devices = %v, want %v", got.devices, tt.want.devices)
					}
				}
			}
		})
	}
}

func TestDataPlaneManagesDevice(t *testing.T) {
	dp := dataPlane{devices: []string{"eth0", "tailscale+"}}
	for name, want := range map[string]bool{
		"eth0":       true,
		"eth1":       false,
		"tailscale0": true,
		"tailscale1": true,
		"wg0":        false,
	} {
		if got := dp.managesDevice(name); got != want {
			t.Errorf("managesDevice(%q) = %v, want %v", name, got, want)
		}
	}
	if (dataPlane{}).managesDevice("tailscale0") {
		t.Error("no devices: managesDevice should be false")
	}
}

func TestDataPlaneClassify(t *testing.T) {
	plain := &tsapi.RouteAcceptor{}
	unsafe := &tsapi.RouteAcceptor{Spec: tsapi.RouteAcceptorSpec{UnsafeAllowIncompatibleCNI: true}}
	managed := dataPlane{cilium: true, ebpfHostRouting: true, masquerade: true, devices: []string{"eth0", "tailscale0"}}
	tests := []struct {
		name       string
		dp         dataPlane
		ra         *tsapi.RouteAcceptor
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{"no-cilium", dataPlane{}, plain, metav1.ConditionTrue, ReasonDataPlaneSupported},
		{"legacy-host-routing", dataPlane{cilium: true, masquerade: true}, plain, metav1.ConditionTrue, ReasonDataPlaneSupported},
		{"ebpf-host-routing-unmanaged-tailscale0", dataPlane{cilium: true, ebpfHostRouting: true, masquerade: true, devices: []string{"eth0"}}, plain, metav1.ConditionFalse, ReasonCiliumEBPFHostRouting},
		{"ebpf-host-routing-managed-tailscale0", managed, plain, metav1.ConditionTrue, ReasonCiliumManagedDevice},
		{"ebpf-host-routing-managed-wildcard", dataPlane{cilium: true, ebpfHostRouting: true, masquerade: true, devices: []string{"eth+", "tailscale+"}}, plain, metav1.ConditionTrue, ReasonCiliumManagedDevice},
		{"ebpf-host-routing-managed-but-no-masquerade", dataPlane{cilium: true, ebpfHostRouting: true, devices: []string{"tailscale0"}}, plain, metav1.ConditionFalse, ReasonCiliumEBPFHostRouting},
		{"ebpf-host-routing-managed-but-ip-masq-agent", dataPlane{cilium: true, ebpfHostRouting: true, masquerade: true, ipMasqAgent: true, devices: []string{"tailscale0"}}, plain, metav1.ConditionFalse, ReasonCiliumIPMasqAgent},
		{"legacy-host-routing-managed-ip-masq-agent", dataPlane{cilium: true, masquerade: true, ipMasqAgent: true, devices: []string{"eth0", "tailscale0"}}, plain, metav1.ConditionTrue, ReasonDataPlaneSupported},
		{"no-conntrack", dataPlane{cilium: true, masquerade: true, noConntrack: true}, plain, metav1.ConditionFalse, ReasonCiliumNoConntrackRules},
		{"no-conntrack-unmanaged-tailscale0", dataPlane{cilium: true, masquerade: true, noConntrack: true, devices: []string{"eth0"}}, plain, metav1.ConditionFalse, ReasonCiliumNoConntrackRules},
		{"no-conntrack-managed-tailscale0", dataPlane{cilium: true, masquerade: true, noConntrack: true, devices: []string{"eth0", "tailscale0"}}, plain, metav1.ConditionTrue, ReasonCiliumManagedDevice},
		{"no-conntrack-managed-but-no-masquerade", dataPlane{cilium: true, noConntrack: true, devices: []string{"eth0", "tailscale0"}}, plain, metav1.ConditionFalse, ReasonCiliumNoConntrackRules},
		{"no-conntrack-managed-but-ip-masq-agent", dataPlane{cilium: true, masquerade: true, noConntrack: true, ipMasqAgent: true, devices: []string{"eth0", "tailscale0"}}, plain, metav1.ConditionFalse, ReasonCiliumNoConntrackRules},
		{"unsafe-override", dataPlane{cilium: true, ebpfHostRouting: true, masquerade: true}, unsafe, metav1.ConditionTrue, ReasonDataPlaneSupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dp.classify(tt.ra)
			if got.status != tt.wantStatus || got.reason != tt.wantReason {
				t.Errorf("classify() = %s/%s (%s), want %s/%s", got.status, got.reason, got.message, tt.wantStatus, tt.wantReason)
			}
		})
	}
}
