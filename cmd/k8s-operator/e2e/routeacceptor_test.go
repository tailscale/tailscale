// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"

	"tailscale.com/client/tailscale/v2"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
)

// routeAcceptorMu serializes the tests that deploy a RouteAcceptor: each one runs a tailscaled in every node's
// host network namespace, so only one can exist in a cluster at a time.
var routeAcceptorMu sync.Mutex

// A subnet in 10.0.0.0/8 so that its route is auto-approved and reachable on
// port 80 per the ACL in acl.hujson, and a split DNS domain served from it.
const (
	testSubnet    = "10.99.0.0/24"
	testSubnetIP  = "10.99.0.1"
	testDNSDomain = "test.internal"
	testDNSName   = "db." + testDNSDomain
)

// ciliumHostRoutingGate returns the RouteAcceptorDataPlaneSupported reason the operator is expected to refuse the
// host-routing data plane with on the Cilium cluster the harness configured, or "" if it is expected to work. The
// harness installs Cilium with eBPF host routing and tailscale0 among its devices, which works; --cilium-set
// overrides can switch to legacy host routing (works), drop tailscale0 from the devices (refused) or enable
// ip-masq-agent (refused).
func ciliumHostRoutingGate() string {
	legacy, tailscaleManaged, ipMasqAgent, noConntrack := false, true, false, false
	for _, set := range fCiliumSet {
		k, v, _ := strings.Cut(set, "=")
		switch k {
		case "bpf.hostLegacyRouting":
			legacy = v == "true"
		case "devices":
			tailscaleManaged = strings.Contains(v, "tailscale")
		case "ipMasqAgent.enabled":
			ipMasqAgent = v == "true"
		case "installNoConntrackIptablesRules":
			noConntrack = v == "true"
		}
	}
	switch {
	case legacy && noConntrack && !(tailscaleManaged && !ipMasqAgent):
		return "CiliumNoConntrackRules"
	case legacy:
		return ""
	case !tailscaleManaged:
		return "CiliumEBPFHostRouting"
	case ipMasqAgent:
		return "CiliumIPMasqAgent"
	}
	return ""
}

// TestRouteAcceptor verifies that a RouteAcceptor makes a subnet route advertised
// to the tailnet reachable from Pods, that the tailnet's split DNS for a domain
// served from that subnet can be resolved by Pods through the DNSConfig
// nameserver, and that its devices are removed from the tailnet when it is
// deleted.
//
// See [TestMain] for test requirements.
func TestRouteAcceptor(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestRouteAcceptor requires a working tailnet client")
	}

	t.Parallel()
	routeAcceptorMu.Lock()
	defer routeAcceptorMu.Unlock()

	router := subnetRouterPod(t, generateName("subnet-router"), testSubnet, testSubnetIP, routerOpts{})
	createAndCleanup(t, kubeClient, router)

	ra := &tsapi.RouteAcceptor{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("route-acceptor"),
		},
		Spec: tsapi.RouteAcceptorSpec{
			ProxyClass: "default",
		},
	}
	if err := kubeClient.Create(t.Context(), ra); err != nil {
		t.Fatalf("creating RouteAcceptor: %v", err)
	}
	t.Cleanup(func() {
		// The test deletes the RouteAcceptor itself on success.
		if err := kubeClient.Delete(context.Background(), ra); err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("error cleaning up RouteAcceptor %s: %v", ra.Name, err)
		}
	})

	if gate := ciliumHostRoutingGate(); cniIsCilium && gate != "" {
		// This Cilium configuration keeps Pod traffic from reaching the routes: the operator must refuse to
		// deploy and say why.
		waitForRouteAcceptorCondition(t, ra.Name, tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionFalse, gate)
		var ds appsv1.DaemonSet
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Namespace: "tailscale", Name: "routeacceptor-" + ra.Name}, &ds); !apierrors.IsNotFound(err) {
			t.Fatalf("DaemonSet exists (err=%v) despite the %s gate", err, gate)
		}
		return
	}

	ready := waitForRouteAcceptorRoute(t, ra.Name, testSubnet)

	// Every node runs a device.
	var nodes corev1.NodeList
	if err := kubeClient.List(t.Context(), &nodes); err != nil {
		t.Fatalf("listing nodes: %v", err)
	}
	if got, want := len(ready.Status.Nodes), len(nodes.Items); got != want {
		t.Errorf("RouteAcceptor.Status.Nodes has %d entries, want one per node (%d)", got, want)
	}
	for _, n := range ready.Status.Nodes {
		if !n.Ready || n.Hostname == "" || len(n.TailnetIPs) == 0 {
			t.Errorf("device on node %s is not ready: %+v", n.Name, n)
		}
	}

	// Pods reach the subnet through the tailnet.
	requireTargetIsReachable(t, fmt.Sprintf("http://%s/healthz", testSubnetIP))

	t.Run("split-dns", func(t *testing.T) {
		testSplitDNS(t)
	})

	// Deleting the RouteAcceptor removes its devices from the tailnet.
	deviceIDs := deviceIDsForRouteAcceptor(t, ra.Name)
	if len(deviceIDs) == 0 {
		t.Fatal("no device IDs recorded in the RouteAcceptor's state Secrets")
	}
	if err := kubeClient.Delete(t.Context(), ra); err != nil {
		t.Fatalf("deleting RouteAcceptor: %v", err)
	}
	if err := tstest.WaitFor(3*time.Minute, func() error {
		err := kubeClient.Get(t.Context(), client.ObjectKey{Name: ra.Name}, &tsapi.RouteAcceptor{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("RouteAcceptor %s still exists", ra.Name)
	}); err != nil {
		t.Fatalf("waiting for RouteAcceptor deletion: %v", err)
	}
	for _, id := range deviceIDs {
		if err := tstest.WaitFor(time.Minute, func() error {
			_, err := tsClient.Devices().Get(t.Context(), id)
			if tailscale.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("device %s still exists", id)
		}); err != nil {
			t.Errorf("device %s was not removed from the tailnet: %v", id, err)
		}
	}
}

// testSplitDNS configures testDNSDomain as a split DNS domain in the tailnet,
// served by the nameserver in the subnet router Pod, enables split DNS
// forwarding on the DNSConfig, points the cluster DNS at the nameserver for the
// domain and verifies that a Pod can reach the subnet by name. It expects a
// ready RouteAcceptor.
func testSplitDNS(t *testing.T) {
	t.Helper()
	ctx := t.Context()

	if _, err := tsClient.DNS().UpdateSplitDNS(ctx, tailscale.SplitDNSRequest{testDNSDomain: {testSubnetIP}}); err != nil {
		t.Fatalf("configuring split DNS: %v", err)
	}
	t.Cleanup(func() {
		if _, err := tsClient.DNS().UpdateSplitDNS(context.Background(), tailscale.SplitDNSRequest{testDNSDomain: nil}); err != nil {
			t.Errorf("removing split DNS domain: %v", err)
		}
	})

	var dnsCfgs tsapi.DNSConfigList
	if err := kubeClient.List(ctx, &dnsCfgs); err != nil || len(dnsCfgs.Items) != 1 {
		t.Fatalf("expected exactly one DNSConfig, got %d (err=%v)", len(dnsCfgs.Items), err)
	}
	dnsCfgName := dnsCfgs.Items[0].Name
	setSplitDNS := func(ctx context.Context, cfg *tsapi.NameserverSplitDNS) error {
		var dnsCfg tsapi.DNSConfig
		if err := kubeClient.Get(ctx, client.ObjectKey{Name: dnsCfgName}, &dnsCfg); err != nil {
			return err
		}
		dnsCfg.Spec.Nameserver.SplitDNS = cfg
		return kubeClient.Update(ctx, &dnsCfg)
	}
	if err := setSplitDNS(ctx, &tsapi.NameserverSplitDNS{Enabled: true, Domains: []string{testDNSDomain}}); err != nil {
		t.Fatalf("enabling split DNS forwarding: %v", err)
	}
	t.Cleanup(func() {
		if err := setSplitDNS(context.Background(), nil); err != nil {
			t.Errorf("disabling split DNS forwarding: %v", err)
		}
	})

	var nameserverIP string
	if err := tstest.WaitFor(3*time.Minute, func() error {
		var dnsCfg tsapi.DNSConfig
		if err := kubeClient.Get(ctx, client.ObjectKey{Name: dnsCfgName}, &dnsCfg); err != nil {
			return err
		}
		if !slices.Contains(dnsCfg.Status.SplitDNSDomains, testDNSDomain) {
			return fmt.Errorf("DNSConfig does not forward %s yet, forwards: %v", testDNSDomain, dnsCfg.Status.SplitDNSDomains)
		}
		for _, c := range dnsCfg.Status.Conditions {
			if c.Type == string(tsapi.SplitDNSReady) && c.Status == metav1.ConditionTrue {
				nameserverIP = dnsCfg.Status.Nameserver.IP
				return nil
			}
		}
		return fmt.Errorf("SplitDNSReady is not true yet")
	}); err != nil {
		t.Fatalf("waiting for split DNS forwarding: %v", err)
	}

	// Send the domain to the nameserver, as the harness does for ts.net.
	restore, err := patchClusterDNSStubDomain(ctx, testDNSDomain, nameserverIP)
	if err != nil {
		t.Fatalf("configuring the cluster DNS: %v", err)
	}
	t.Cleanup(restore)

	requireTargetIsReachable(t, fmt.Sprintf("http://%s/healthz", testDNSName))
}

// patchClusterDNSStubDomain adds a stub zone for domain forwarding to nameserverIP to the cluster's CoreDNS or
// kube-dns configuration and returns a function that restores the original configuration.
func patchClusterDNSStubDomain(ctx context.Context, domain, nameserverIP string) (func(), error) {
	if cm := getDNSConfigMap(ctx, "coredns"); cm != nil && cm.Data["Corefile"] != "" {
		corefile := cm.Data["Corefile"] + fmt.Sprintf(`
%s:53 {
    errors
    cache 30
    forward . %s
}
`, domain, nameserverIP)
		return patchDNSConfigMap(kzap.NewRaw().Sugar(), cm, "Corefile", corefile)
	}
	return nil, fmt.Errorf("cluster DNS is not a patchable CoreDNS")
}

// TestRouteAcceptorCiliumEgressGateway verifies the RouteAcceptor's Cilium
// egress gateway mode: with a CiliumEgressGatewayPolicy maintained by the
// operator, Pods reach the subnet even with Cilium's eBPF host routing.
//
// See [TestMain] for test requirements; needs --cni=cilium.
func TestRouteAcceptorCiliumEgressGateway(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestRouteAcceptorCiliumEgressGateway requires a working tailnet client")
	}
	if !cniIsCilium {
		t.Skip("TestRouteAcceptorCiliumEgressGateway requires --cni=cilium")
	}

	t.Parallel()
	routeAcceptorMu.Lock()
	defer routeAcceptorMu.Unlock()

	router := subnetRouterPod(t, generateName("subnet-router"), testSubnet, testSubnetIP, routerOpts{})
	createAndCleanup(t, kubeClient, router)

	ra := &tsapi.RouteAcceptor{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("route-acceptor-cilium"),
		},
		Spec: tsapi.RouteAcceptorSpec{
			ProxyClass: "default",
			Cilium:     &tsapi.RouteAcceptorCilium{EgressGateway: &tsapi.CiliumEgressGateway{}},
		},
	}
	createAndCleanup(t, kubeClient, ra)

	waitForRouteAcceptorRoute(t, ra.Name, testSubnet)
	waitForRouteAcceptorCondition(t, ra.Name, tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionTrue, "CiliumEgressGateway")

	pol := &unstructured.Unstructured{}
	pol.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumEgressGatewayPolicy"})
	if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: "routeacceptor-" + ra.Name}, pol); err != nil {
		t.Fatalf("getting CiliumEgressGatewayPolicy: %v", err)
	}
	cidrs, _, _ := unstructured.NestedStringSlice(pol.Object, "spec", "destinationCIDRs")
	if !slices.Contains(cidrs, testSubnet) {
		t.Fatalf("CiliumEgressGatewayPolicy destinationCIDRs = %v, want %s", cidrs, testSubnet)
	}

	requireTargetIsReachable(t, fmt.Sprintf("http://%s/healthz", testSubnetIP))
}

// routerOpts configures subnetRouterPod.
type routerOpts struct {
	// loginServer, if set, is the control server the router logs in to without an auth key (the spike's test
	// control server). Otherwise the router joins the test tailnet with an ephemeral auth key.
	loginServer string
	// image overrides the tailscale image, which defaults to the operator's proxy image.
	image string
}

// largeFileSize is the size of the file the subnet router Pod serves for MTU checks.
const largeFileSize = 1 << 20

// subnetRouterPod returns a Pod that joins the tailnet as a subnet router for
// subnet and answers HTTP requests on subnetIP port 80 (containerboot's health
// check endpoint), serves a largeFileSize-byte file at subnetIP port 8080
// (/large.bin), and answers DNS queries for testDNSDomain on subnetIP port 53
// (a CoreDNS sidecar resolving testDNSName to subnetIP). With the default
// options the device is ephemeral, so it disappears from the tailnet with the
// Pod.
func subnetRouterPod(t *testing.T, name, subnet, subnetIP string, opts routerOpts) *corev1.Pod {
	t.Helper()

	env := []corev1.EnvVar{
		{Name: "TS_HOSTNAME", Value: name},
		{Name: "TS_ROUTES", Value: subnet},
		{Name: "TS_USERSPACE", Value: "false"},
		// Keep state on disk: the Pod's ServiceAccount cannot
		// write Secrets.
		{Name: "TS_KUBE_SECRET", Value: ""},
		{Name: "TS_STATE_DIR", Value: "/tmp"},
		{Name: "TS_ENABLE_HEALTH_CHECK", Value: "true"},
		{Name: "TS_LOCAL_ADDR_PORT", Value: "[::]:80"},
	}
	if opts.loginServer != "" {
		env = append(env,
			corev1.EnvVar{Name: "TS_EXTRA_ARGS", Value: "--login-server=" + opts.loginServer},
			corev1.EnvVar{Name: "TS_NO_LOGS_NO_SUPPORT", Value: "true"},
		)
	} else {
		caps := tailscale.KeyCapabilities{}
		caps.Devices.Create.Preauthorized = true
		caps.Devices.Create.Ephemeral = true
		caps.Devices.Create.Tags = []string{"tag:k8s"}
		authKey, err := tsClient.Keys().CreateAuthKey(t.Context(), tailscale.CreateKeyRequest{Capabilities: caps})
		if err != nil {
			t.Fatalf("creating auth key: %v", err)
		}
		t.Cleanup(func() { tsClient.Keys().Delete(context.Background(), authKey.ID) })
		env = append(env, corev1.EnvVar{Name: "TS_AUTHKEY", Value: authKey.Key})
	}

	image := opts.image
	if image == "" {
		image = proxyImage(t)
	}
	privileged := true
	corefile := fmt.Sprintf(`%s:53 {
    hosts {
        %s %s
    }
}
`, testDNSDomain, subnetIP, testDNSName)
	nginxConf := `server { listen 8080; root /srv; }`
	return &corev1.Pod{
		ObjectMeta: objectMeta(ns, name),
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "coredns-config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "nginx-config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "srv", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			},
			InitContainers: []corev1.Container{{
				Name:            "subnet",
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
				Command:         []string{"/bin/sh", "-c"},
				Args: []string{fmt.Sprintf("ip addr add %s/32 dev lo && printf '%%s' %s > /etc/coredns/Corefile && "+
					"printf '%%s' %s > /etc/nginx/conf.d/default.conf && head -c %d /dev/urandom > /srv/large.bin",
					subnetIP, shellQuote(corefile), shellQuote(nginxConf), largeFileSize)},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "coredns-config", MountPath: "/etc/coredns"},
					{Name: "nginx-config", MountPath: "/etc/nginx/conf.d"},
					{Name: "srv", MountPath: "/srv"},
				},
			}},
			Containers: []corev1.Container{
				{
					Name:            "tailscale",
					Image:           image,
					ImagePullPolicy: corev1.PullIfNotPresent,
					SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
					Env:             env,
				},
				{
					Name:            "coredns",
					Image:           "coredns/coredns:1.12.2",
					ImagePullPolicy: corev1.PullIfNotPresent,
					Args:            []string{"-conf", "/etc/coredns/Corefile"},
					VolumeMounts:    []corev1.VolumeMount{{Name: "coredns-config", MountPath: "/etc/coredns", ReadOnly: true}},
				},
				{
					Name:            "nginx",
					Image:           "nginx:alpine",
					ImagePullPolicy: corev1.PullIfNotPresent,
					VolumeMounts: []corev1.VolumeMount{
						{Name: "nginx-config", MountPath: "/etc/nginx/conf.d", ReadOnly: true},
						{Name: "srv", MountPath: "/srv", ReadOnly: true},
					},
				},
			},
		},
	}
}

// shellQuote single-quotes s for use in a POSIX shell command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// proxyImage returns the image the operator uses for its proxies, from the
// operator Deployment's PROXY_IMAGE env var.
func proxyImage(t *testing.T) string {
	t.Helper()
	var deploy appsv1.Deployment
	if err := kubeClient.Get(t.Context(), client.ObjectKey{Namespace: "tailscale", Name: "operator"}, &deploy); err != nil {
		t.Fatalf("getting operator Deployment: %v", err)
	}
	for _, c := range deploy.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == "PROXY_IMAGE" && e.Value != "" {
				return e.Value
			}
		}
	}
	t.Fatal("operator Deployment does not set PROXY_IMAGE")
	return ""
}

// waitForRouteAcceptorCondition waits for the RouteAcceptor to have the given
// condition with the given status and reason.
func waitForRouteAcceptorCondition(t *testing.T, name string, typ tsapi.ConditionType, status metav1.ConditionStatus, reason string) {
	t.Helper()
	if err := tstest.WaitFor(3*time.Minute, func() error {
		var ra tsapi.RouteAcceptor
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, &ra); err != nil {
			return err
		}
		for _, c := range ra.Status.Conditions {
			if c.Type != string(typ) {
				continue
			}
			if c.Status == status && c.Reason == reason {
				return nil
			}
			return fmt.Errorf("RouteAcceptor %s: %s is %s/%s (%s), want %s/%s", name, typ, c.Status, c.Reason, c.Message, status, reason)
		}
		return fmt.Errorf("RouteAcceptor %s has no %s condition yet", name, typ)
	}); err != nil {
		t.Fatal(err)
	}
}

// waitForRouteAcceptorRoute waits for the RouteAcceptor to be ready and to
// accept the given route on every node, and returns it.
func waitForRouteAcceptorRoute(t *testing.T, name, route string) *tsapi.RouteAcceptor {
	t.Helper()
	forceReconcile := triggerReconcile(t,
		client.ObjectKey{Name: name}, &tsapi.RouteAcceptor{}, 30*time.Second)

	ra := &tsapi.RouteAcceptor{}
	if err := tstest.WaitFor(5*time.Minute, func() error {
		forceReconcile()
		ra = &tsapi.RouteAcceptor{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, ra); err != nil {
			return err
		}
		for _, c := range ra.Status.Conditions {
			if c.Type != string(tsapi.RouteAcceptorReady) {
				continue
			}
			if c.Status != metav1.ConditionTrue {
				return fmt.Errorf("RouteAcceptor %s not ready: %s: %s", name, c.Reason, c.Message)
			}
		}
		if len(ra.Status.Nodes) == 0 {
			return fmt.Errorf("RouteAcceptor %s has no device info yet", name)
		}
		for _, n := range ra.Status.Nodes {
			if !n.Ready {
				return fmt.Errorf("device on node %s is not ready yet", n.Name)
			}
			if !slices.Contains(n.AcceptedRoutes, route) {
				return fmt.Errorf("device on node %s does not accept %s yet, accepted routes: %v", n.Name, route, n.AcceptedRoutes)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for RouteAcceptor %s to accept %s: %v", name, route, err)
	}
	return ra
}

// deviceIDsForRouteAcceptor returns the device IDs recorded in the
// RouteAcceptor's state Secrets.
func deviceIDsForRouteAcceptor(t *testing.T, name string) []string {
	t.Helper()
	var secrets corev1.SecretList
	if err := kubeClient.List(t.Context(), &secrets,
		client.InNamespace("tailscale"),
		client.MatchingLabels{
			kubetypes.LabelSecretType:            kubetypes.LabelSecretTypeState,
			"tailscale.com/parent-resource-type": "routeacceptor",
			"tailscale.com/parent-resource":      name,
		},
	); err != nil {
		t.Fatalf("listing state Secrets for RouteAcceptor %s: %v", name, err)
	}
	var ids []string
	for _, s := range secrets.Items {
		if id := string(s.Data[kubetypes.KeyDeviceID]); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}
