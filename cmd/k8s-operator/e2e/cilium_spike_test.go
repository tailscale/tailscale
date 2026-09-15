// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"

	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
)

const spikeAcceptorName = "spike-acceptor"

// spikeRow is one Cilium configuration to try.
type spikeRow struct {
	name string
	// sets are the Cilium Helm overrides applied on top of the harness defaults (eBPF host routing, egress gateway
	// feature enabled, devices={eth0,tailscale0}).
	sets []string
	// egressGatewayPolicy creates the CiliumEgressGatewayPolicy the operator's egress gateway mode would create.
	egressGatewayPolicy bool
	// wantReachable is whether a Pod is expected to reach the subnet.
	wantReachable bool
	// largeDownload also checks that a 1 MiB download from the subnet completes (MTU/MSS behaviour).
	largeDownload bool
}

// TestCiliumSpike validates the RouteAcceptor's data plane under the Cilium
// configurations that matter, without the operator: it deploys the route
// acceptor DaemonSet and a subnet router directly against the test control
// server the harness started, then reconfigures Cilium in place for each row
// and checks whether a Pod can reach the subnet. Every row asserts its expected
// outcome, so the test passes when Cilium behaves as the operator's detection
// and documentation assume.
//
// Run with: go test -count=1 -v -timeout 60m ./cmd/k8s-operator/e2e/ --build --cluster --cni=cilium --cilium-spike
func TestCiliumSpike(t *testing.T) {
	if !ciliumSpike {
		t.Skip("TestCiliumSpike requires --cilium-spike")
	}
	ctx := t.Context()

	spikeDeploy(t, false)

	rows := []spikeRow{
		{name: "ebpf-host-routing-managed-tailscale0", wantReachable: true, largeDownload: true},
		{name: "ebpf-host-routing-ip-masq-agent", sets: []string{"ipMasqAgent.enabled=true"}, wantReachable: false},
		{name: "ebpf-host-routing-ip-masq-agent-egress-gateway", sets: []string{"ipMasqAgent.enabled=true"}, egressGatewayPolicy: true, wantReachable: true},
		{name: "ebpf-host-routing-unmanaged-tailscale0", sets: []string{"devices={eth0}"}, wantReachable: false},
		{name: "legacy-host-routing", sets: []string{"bpf.hostLegacyRouting=true"}, wantReachable: true, largeDownload: true},
		// With tailscale0 among Cilium's devices its BPF masquerading, which needs no conntrack, still applies.
		{name: "legacy-host-routing-no-conntrack", sets: []string{"bpf.hostLegacyRouting=true", "installNoConntrackIptablesRules=true"}, wantReachable: true},
		// The pure netfilter data plane, as on other CNIs.
		{name: "legacy-host-routing-unmanaged-tailscale0", sets: []string{"bpf.hostLegacyRouting=true", "devices={eth0}"}, wantReachable: true, largeDownload: true},
		{name: "legacy-host-routing-unmanaged-no-conntrack", sets: []string{"bpf.hostLegacyRouting=true", "devices={eth0}", "installNoConntrackIptablesRules=true"}, wantReachable: false},
	}

	type result struct {
		row                  spikeRow
		reachable, largeOK   bool
		largeChecked, passed bool
	}
	var results []result
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			res := result{row: row}
			defer func() { results = append(results, res) }()

			if err := ciliumHelm.apply(ctx, kzap.NewRaw().Sugar(), row.sets); err != nil {
				t.Fatalf("reconfiguring Cilium: %v", err)
			}
			// Give the agents a moment to regenerate their programs after the rollout.
			time.Sleep(15 * time.Second)

			if row.egressGatewayPolicy {
				pol := spikeEgressGatewayPolicy(t)
				createAndCleanup(t, kubeClient, pol)
				time.Sleep(10 * time.Second)
			}

			attempts := 40
			if !row.wantReachable {
				attempts = 15
			}
			res.reachable = targetIsReachable(t, fmt.Sprintf("http://%s/healthz", testSubnetIP), attempts)
			res.passed = res.reachable == row.wantReachable
			if res.reachable != row.wantReachable {
				t.Errorf("reachable = %v, want %v", res.reachable, row.wantReachable)
			}
			if row.largeDownload && res.reachable {
				res.largeChecked = true
				res.largeOK = targetDownloadsBytes(t, fmt.Sprintf("http://%s:8080/large.bin", testSubnetIP), largeFileSize)
				if !res.largeOK {
					t.Errorf("a %d-byte download from the subnet did not complete: MTU/MSS mitigation needed", largeFileSize)
					res.passed = false
				}
			}
		})
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "\n%-50s %-10s %-10s %-12s %s\n", "row", "reachable", "expected", "1MiB", "result")
	for _, r := range results {
		large := "n/a"
		if r.largeChecked {
			large = fmt.Sprint(r.largeOK)
		}
		verdict := "PASS"
		if !r.passed {
			verdict = "FAIL"
		}
		fmt.Fprintf(&sb, "%-50s %-10v %-10v %-12s %s\n", r.row.name, r.reachable, r.row.wantReachable, large, verdict)
	}
	t.Log(sb.String())
}

// spikeDeploy deploys the subnet router and the route acceptor DaemonSet (with route sources enforcement if
// sources is set) against the test control server, and waits for the devices to accept the router's subnet.
func spikeDeploy(t *testing.T, sources bool) {
	t.Helper()
	ctx := t.Context()
	applySpikeRBAC(t)

	router := subnetRouterPod(t, "spike-router", testSubnet, testSubnetIP, routerOpts{loginServer: clusterLoginServer, image: builtTailscaleImage})
	createAndCleanup(t, kubeClient, router)
	// The acceptors keep their tailscaled state in per-node Secrets that outlive the DaemonSet; a stale one from an
	// earlier run against a previous control server would satisfy the wait below before the device has re-joined.
	var nodes corev1.NodeList
	if err := kubeClient.List(ctx, &nodes); err != nil {
		t.Fatalf("listing nodes: %v", err)
	}
	for _, n := range nodes.Items {
		stale := &corev1.Secret{ObjectMeta: objectMeta(ns, spikeAcceptorName+"-"+n.Name)}
		if err := kubeClient.Delete(ctx, stale); err != nil && !apierrors.IsNotFound(err) {
			t.Fatalf("deleting the stale state Secret %s: %v", stale.Name, err)
		}
	}
	ds := spikeAcceptorDaemonSet(sources)
	createAndCleanup(t, kubeClient, ds)

	// The acceptor reports the routes it accepts in its state Secret once tailscaled has installed them.
	if err := tstest.WaitFor(5*time.Minute, func() error {
		if err := kubeClient.List(ctx, &nodes); err != nil {
			return err
		}
		for _, n := range nodes.Items {
			var s corev1.Secret
			if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: spikeAcceptorName + "-" + n.Name}, &s); err != nil {
				return fmt.Errorf("state Secret for %s: %w", n.Name, err)
			}
			var routes []string
			if raw := s.Data[kubetypes.KeyAcceptedRoutes]; len(raw) > 0 {
				json.Unmarshal(raw, &routes)
			}
			if !slices.Contains(routes, testSubnet) {
				return fmt.Errorf("device on %s does not accept %s yet: %v (device IPs %s)", n.Name, testSubnet, routes, s.Data[kubetypes.KeyDeviceIPs])
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for the route acceptor devices to accept %s: %v", testSubnet, err)
	}
	t.Logf("control server knows %d nodes", spikeControl.NumNodes())
}

// applySpikeRBAC lets the acceptor Pods keep their tailscaled state in Secrets, as the operator's proxies Role does.
func applySpikeRBAC(t *testing.T) {
	t.Helper()
	sa := &corev1.ServiceAccount{ObjectMeta: objectMeta(ns, spikeAcceptorName)}
	role := &rbacv1.Role{
		ObjectMeta: objectMeta(ns, spikeAcceptorName),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		}, {
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch", "get"},
		}},
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: objectMeta(ns, spikeAcceptorName),
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: spikeAcceptorName, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: spikeAcceptorName},
	}
	for _, obj := range []client.Object{sa, role, rb} {
		createAndCleanup(t, kubeClient, obj)
	}
}

// spikeAcceptorDaemonSet is what the operator deploys for a RouteAcceptor, configured for the test control
// server: a host-network tailscaled per node that accepts routes, with containerboot in route acceptor mode.
// spikeAcceptorDaemonSet returns the route acceptor DaemonSet the operator would create, enforcing route sources
// if sources is set.
func spikeAcceptorDaemonSet(sources bool) *appsv1.DaemonSet {
	labels := map[string]string{"app": spikeAcceptorName}
	privileged := true
	return &appsv1.DaemonSet{
		ObjectMeta: objectMeta(ns, spikeAcceptorName),
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					ServiceAccountName: spikeAcceptorName,
					HostNetwork:        true,
					DNSPolicy:          corev1.DNSClusterFirstWithHostNet,
					InitContainers: []corev1.Container{{
						Name:            "sysctler",
						Image:           builtTailscaleImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
						Command:         []string{"/bin/sh", "-c"},
						Args:            []string{"echo 1 > /proc/sys/net/ipv4/ip_forward"},
					}},
					Containers: []corev1.Container{{
						Name:            "tailscale",
						Image:           builtTailscaleImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
						Env: []corev1.EnvVar{
							{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
							{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
							{Name: "NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
							{Name: "TS_USERSPACE", Value: "false"},
							{Name: "TS_KUBE_SECRET", Value: spikeAcceptorName + "-$(NODE_NAME)"},
							{Name: "TS_EXPERIMENTAL_ROUTE_ACCEPTOR", Value: "true"},
							{Name: "TS_EXPERIMENTAL_ROUTE_ACCEPTOR_SOURCES", Value: fmt.Sprint(sources)},
							{Name: "TS_ACCEPT_DNS", Value: "false"},
							{Name: "TS_EXTRA_ARGS", Value: "--login-server=" + clusterLoginServer + " --accept-routes"},
							{Name: "TS_NO_LOGS_NO_SUPPORT", Value: "true"},
						},
					}},
				},
			},
		},
	}
}

// spikeEgressGatewayPolicy is the policy the operator's egress gateway mode would create for the spike's subnet,
// with every node as a gateway.
func spikeEgressGatewayPolicy(t *testing.T) *unstructured.Unstructured {
	t.Helper()
	var nodes corev1.NodeList
	if err := kubeClient.List(t.Context(), &nodes); err != nil {
		t.Fatal(err)
	}
	var names []any
	for _, n := range nodes.Items {
		names = append(names, n.Name)
	}
	pol := &unstructured.Unstructured{}
	pol.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumEgressGatewayPolicy"})
	pol.SetName(spikeAcceptorName)
	pol.Object["spec"] = map[string]any{
		"selectors":        []any{map[string]any{"podSelector": map[string]any{}}},
		"destinationCIDRs": []any{testSubnet},
		"egressGateway": map[string]any{
			"nodeSelector": map[string]any{
				"matchExpressions": []any{map[string]any{"key": "kubernetes.io/hostname", "operator": "In", "values": names}},
			},
			"interface": "tailscale0",
		},
	}
	return pol
}
