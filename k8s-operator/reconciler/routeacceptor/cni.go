// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

const (
	// ciliumConfigMapNamespace and ciliumConfigMapName locate the ConfigMap holding the Cilium agent's
	// configuration. Its keys are the agent's flags.
	ciliumConfigMapNamespace = "kube-system"
	ciliumConfigMapName      = "cilium-config"
)

// dataPlane describes what is known about how the cluster's CNI handles Pod traffic to destinations outside the
// cluster. The route acceptor relies on that traffic traversing the node's routing table and netfilter rules,
// which some CNI configurations bypass.
type dataPlane struct {
	// cilium is true if the cluster runs Cilium, i.e. its agent ConfigMap was found.
	cilium bool
	// ebpfHostRouting is true if Cilium is configured for eBPF host routing, which bypasses the node's routing
	// table and netfilter rules for Pod traffic.
	ebpfHostRouting bool
	// noConntrack is true if Cilium exempts Pod traffic from connection tracking, which keeps netfilter from
	// masquerading it.
	noConntrack bool
	// masquerade is true if Cilium masquerades Pod traffic leaving the cluster at all (on by default).
	masquerade bool
	// ipMasqAgent is true if Cilium's ip-masq-agent is enabled, which exempts its nonMasqueradeCIDRs (RFC 1918
	// ranges by default) from masquerading.
	ipMasqAgent bool
	// egressGateway is true if Cilium's egress gateway feature is enabled.
	egressGateway bool
	// devices are the network devices Cilium attaches its programs to. Entries may end in '+' as a prefix
	// wildcard.
	devices []string
}

// detectDataPlane reads the CNI's configuration. Only Cilium is recognised; any other CNI (or no permission to
// read Cilium's configuration) yields a zero dataPlane, which is treated as compatible.
func (r *Reconciler) detectDataPlane(ctx context.Context) (dataPlane, error) {
	var cm corev1.ConfigMap
	// The ConfigMap lives outside the operator's namespace, which the cached client does not see.
	err := r.apiReader.Get(ctx, types.NamespacedName{Namespace: ciliumConfigMapNamespace, Name: ciliumConfigMapName}, &cm)
	switch {
	case apierrors.IsNotFound(err) || apierrors.IsForbidden(err):
		return dataPlane{}, nil
	case err != nil:
		return dataPlane{}, fmt.Errorf("failed to read %s/%s: %w", ciliumConfigMapNamespace, ciliumConfigMapName, err)
	}
	return dataPlaneFromCiliumConfig(cm.Data), nil
}

// dataPlaneFromCiliumConfig interprets the Cilium agent's configuration. eBPF host routing is what Cilium enables
// when BPF masquerading and the kube-proxy replacement are on and legacy host routing is not requested; if the
// kernel lacks support Cilium silently falls back to legacy routing, which the configuration cannot show.
func dataPlaneFromCiliumConfig(data map[string]string) dataPlane {
	boolVal := func(key string) bool {
		return strings.EqualFold(strings.TrimSpace(data[key]), "true")
	}
	kpr := strings.ToLower(strings.TrimSpace(data["kube-proxy-replacement"]))
	kprOn := kpr == "true" || kpr == "strict"

	dp := dataPlane{
		cilium:          true,
		ebpfHostRouting: boolVal("enable-bpf-masquerade") && kprOn && !boolVal("enable-host-legacy-routing"),
		noConntrack:     boolVal("install-no-conntrack-iptables-rules"),
		// Masquerading defaults to on; only an explicit "false" disables it.
		masquerade:  !strings.EqualFold(strings.TrimSpace(data["enable-ipv4-masquerade"]), "false"),
		ipMasqAgent: boolVal("enable-ip-masq-agent"),
		// The flag was renamed between Cilium releases.
		egressGateway: boolVal("enable-ipv4-egress-gateway") || boolVal("enable-egress-gateway"),
	}
	for _, d := range strings.FieldsFunc(data["devices"], func(r rune) bool { return r == ',' || r == ' ' }) {
		if d = strings.TrimSpace(d); d != "" {
			dp.devices = append(dp.devices, d)
		}
	}
	return dp
}

// managesDevice reports whether Cilium attaches its programs to the named device: it is listed explicitly or
// matched by a '+' prefix wildcard.
func (dp dataPlane) managesDevice(name string) bool {
	for _, d := range dp.devices {
		if prefix, ok := strings.CutSuffix(d, "+"); ok {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if d == name {
			return true
		}
	}
	return false
}

// classify returns the RouteAcceptorDataPlaneSupported condition for the host-routing data plane on this CNI
// configuration: True with a reason naming the mode in effect, or False with a reason and a message explaining
// why Pod traffic would not reach the accepted routes and how to fix it. The egress gateway mode is not subject
// to it. spec.unsafeAllowIncompatibleCNI turns any False into True.
func (dp dataPlane) classify(ra *tsapi.RouteAcceptor) conditionSpec {
	supported := conditionSpec{metav1.ConditionTrue, ReasonDataPlaneSupported, ReasonDataPlaneSupported}
	if !dp.cilium {
		return supported
	}

	// With tailscale0 among its devices and BPF masquerading on, Cilium's own program on the device masquerades Pod
	// traffic leaving it to the device's tailnet IP and reverse-translates the replies, without netfilter.
	managed := dp.managesDevice(tailscaleTunName) && dp.masquerade

	var res conditionSpec
	switch {
	case dp.ebpfHostRouting && managed && dp.ipMasqAgent:
		res = conditionSpec{metav1.ConditionFalse, ReasonCiliumIPMasqAgent,
			"Cilium's ip-masq-agent is enabled: its nonMasqueradeCIDRs (RFC 1918 ranges by default) exempt Pod traffic to " +
				"typical subnet routes from masquerading, so it would enter the tailnet with a Pod source address and be dropped. " +
				"Either remove the accepted routes from the agent's nonMasqueradeCIDRs, use spec.cilium.egressGateway (an egress " +
				"gateway policy forces masquerading), or set spec.unsafeAllowIncompatibleCNI"}
	case dp.ebpfHostRouting && managed:
		// Cilium's route lookup honours tailscaled's rules, so its programs steer the Pod traffic to tailscale0 and
		// masquerade it there.
		res = conditionSpec{metav1.ConditionTrue, ReasonCiliumManagedDevice,
			fmt.Sprintf("Cilium routes and masquerades Pod traffic on %s itself (eBPF host routing with %s among Cilium's devices)", tailscaleTunName, tailscaleTunName)}
	case dp.ebpfHostRouting:
		res = conditionSpec{metav1.ConditionFalse, ReasonCiliumEBPFHostRouting,
			fmt.Sprintf("Cilium is configured for eBPF host routing, which bypasses the node's routing table and netfilter "+
				"rules for Pod traffic, so Pods would not reach the accepted routes. Either add %s to Cilium's devices "+
				"(for example devices={eth0,%s}, keeping the devices Cilium detected before) so that Cilium routes and "+
				"masquerades the traffic itself, use spec.cilium.egressGateway, set bpf.hostLegacyRouting=true, or set "+
				"spec.unsafeAllowIncompatibleCNI if Cilium runs with legacy host routing anyway", tailscaleTunName, tailscaleTunName)}
	case dp.noConntrack && managed && !dp.ipMasqAgent:
		// The host stack routes the traffic to tailscale0, and although netfilter cannot masquerade untracked
		// traffic, Cilium's BPF masquerading on the device needs no conntrack.
		res = conditionSpec{metav1.ConditionTrue, ReasonCiliumManagedDevice,
			fmt.Sprintf("Cilium masquerades Pod traffic on %s itself (legacy host routing with no-conntrack rules and %s among Cilium's devices)", tailscaleTunName, tailscaleTunName)}
	case dp.noConntrack:
		fix := fmt.Sprintf("add %s to Cilium's devices so that Cilium masquerades the traffic itself", tailscaleTunName)
		if dp.ipMasqAgent {
			fix += " and remove the accepted routes from ip-masq-agent's nonMasqueradeCIDRs"
		}
		res = conditionSpec{metav1.ConditionFalse, ReasonCiliumNoConntrackRules,
			"Cilium is configured with installNoConntrackIptablesRules=true, which exempts Pod traffic from connection " +
				"tracking, so netfilter cannot masquerade it to the node's tailnet IP. Either disable that setting, " + fix +
				", use spec.cilium.egressGateway, or set spec.unsafeAllowIncompatibleCNI"}
	default:
		res = supported
	}
	if res.status == metav1.ConditionFalse && ra.Spec.UnsafeAllowIncompatibleCNI {
		return supported
	}
	return res
}

// ciliumEgressGatewayEnabled reports whether the RouteAcceptor asks for the Cilium egress gateway mode.
func ciliumEgressGatewayEnabled(ra *tsapi.RouteAcceptor) bool {
	return ra.Spec.Cilium != nil && ra.Spec.Cilium.EgressGateway != nil
}
