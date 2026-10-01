// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"tailscale.com/client/tailscale/v2"
	"tailscale.com/ipn/store/mem"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
)

func generateName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, strings.ToLower(rand.Text()))
}

func requireTargetIsReachable(t *testing.T, url string) {
	t.Helper()

	volumes, mounts, cacertFlag := certVolumesForURL(url)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("curl"),
			Namespace: ns,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Volumes:       volumes,
			Containers: []corev1.Container{
				{
					Name:         "curl",
					Image:        "curlimages/curl",
					VolumeMounts: mounts,
					Command: []string{"sh", "-c", fmt.Sprintf(
						`for i in $(seq 1 40); do `+
							`code=$(curl -s %s-o /dev/null -w "%%{http_code}" --max-time 5 %q); `+
							`[ "$code" = "200" ] && exit 0; sleep 2; done; exit 1`, cacertFlag, url)},
				},
			},
		},
	}
	createAndCleanup(t, kubeClient, pod)

	if err := tstest.WaitFor(5*time.Minute, func() error {
		p := &corev1.Pod{ObjectMeta: objectMeta(ns, pod.Name)}
		if err := get(t.Context(), kubeClient, p); err != nil {
			return err
		}
		if p.Status.Phase == corev1.PodSucceeded {
			t.Logf("curl pod %s succeeded", pod.Name)
			return nil
		}
		if p.Status.Phase == corev1.PodFailed {
			t.Fatalf("%s not reachable in-cluster: curl pod %s failed", url, pod.Name)
		}
		return fmt.Errorf("curl pod %s phase: %s", pod.Name, p.Status.Phase)
	}); err != nil {
		t.Fatalf("%s not reachable in-cluster: %v", url, err)
	}
}

// certVolumesForURL returns the Pod volume, VolumeMount, and curl "--cacert"
// argument needed to verify an HTTPS url against the test CAs published in the testCAsConfigMap.
func certVolumesForURL(url string) ([]corev1.Volume, []corev1.VolumeMount, string) {
	if !strings.HasPrefix(url, "https://") {
		return nil, nil, ""
	}
	const mountPath = "/etc/test-cas"
	volumes := []corev1.Volume{{
		Name: "test-cas",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: testCAsConfigMap},
			},
		},
	}}
	mounts := []corev1.VolumeMount{{Name: "test-cas", MountPath: mountPath, ReadOnly: true}}
	cacertFlag := "--cacert " + mountPath + "/" + testCAsConfigMapKey + " "
	return volumes, mounts, cacertFlag
}

// newHTTPClient returns a HTTP client for the given tailnet client.
// When running against devcontrol, trusts Pebble testCAs. Otherwise,
// trusts Let's Encrypt staging testCA.
func newHTTPClient(cl *tsnet.Server) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: testCAs},
			DialContext:     cl.Dial,
		},
	}
}

func verifyConnectorTailnet(t *testing.T, cn *tsapi.Connector, cl *tsnet.Server) error {
	t.Helper()
	lc, err := cl.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(t.Context())
	if err != nil {
		return err
	}
	_, expectedTailnet, ok := strings.Cut(strings.TrimSuffix(status.Self.DNSName, "."), ".")
	if !ok {
		return fmt.Errorf("unexpected DNSName format %q", status.Self.DNSName)
	}
	if err := tstest.WaitFor(3*time.Minute, func() error {
		var secrets corev1.SecretList
		if err := kubeClient.List(t.Context(), &secrets,
			client.InNamespace("tailscale"),
			client.MatchingLabels{
				"tailscale.com/parent-resource-type": "connector",
				"tailscale.com/parent-resource":      cn.Name,
			},
		); err != nil {
			return err
		}
		if len(secrets.Items) == 0 {
			return fmt.Errorf("no state secrets found for Connector %q yet", cn.Name)
		}
		fqdn := strings.TrimSuffix(string(secrets.Items[0].Data[kubetypes.KeyDeviceFQDN]), ".")
		_, tailnet, ok := strings.Cut(fqdn, ".")
		if !ok {
			return fmt.Errorf("Connector %q: device FQDN %q has no domain yet", cn.Name, fqdn)
		}
		if tailnet != expectedTailnet {
			return fmt.Errorf("Connector %q on wrong tailnet: got domain %q, want %q", cn.Name, tailnet, expectedTailnet)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("Connector %q not on expected tailnet: %v", cn.Name, err)
	}
	return nil
}

// verifyProxyGroupTailnet verifies that a ProxyGroup is registered to the correct tailnet.
// This is done by getting the expected tailnet domain for the tailnet client,
// and comparing this with the actual device fqdn in the ProxyGroup state secret.
func verifyProxyGroupTailnet(t *testing.T, pg *tsapi.ProxyGroup, cl *tsnet.Server) error {
	t.Helper()
	// Determine the expected tailnet Magic DNS Name.
	lc, err := cl.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(t.Context())
	if err != nil {
		return err
	}
	_, expectedTailnet, ok := strings.Cut(strings.TrimSuffix(status.Self.DNSName, "."), ".")
	if !ok {
		return fmt.Errorf("unexpected DNSName format %q", status.Self.DNSName)
	}
	// Read the device FQDN from the first state secret for the ProxyGroup,
	// and verify that this matches the expected tailnet.
	if err := tstest.WaitFor(3*time.Minute, func() error {
		var secrets corev1.SecretList
		if err := kubeClient.List(t.Context(), &secrets,
			client.InNamespace("tailscale"),
			client.MatchingLabels{
				kubetypes.LabelSecretType:            kubetypes.LabelSecretTypeState,
				"tailscale.com/parent-resource-type": "proxygroup",
				"tailscale.com/parent-resource":      pg.Name,
			},
		); err != nil {
			return err
		}
		if len(secrets.Items) == 0 {
			return fmt.Errorf("no state secrets found for ProxyGroup %q yet", pg.Name)
		}
		fqdn := strings.TrimSuffix(string(secrets.Items[0].Data[kubetypes.KeyDeviceFQDN]), ".")
		_, tailnet, ok := strings.Cut(fqdn, ".")
		if !ok {
			return fmt.Errorf("ProxyGroup %q: device FQDN %q has no domain yet", pg.Name, fqdn)
		}
		if tailnet != expectedTailnet {
			return fmt.Errorf("ProxyGroup %q on wrong tailnet: got domain %q, want %q", pg.Name, tailnet, expectedTailnet)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("ProxyGroup %q not on expected tailnet: %v", pg.Name, err)
	}
	return nil
}

func newTailnetNode(t *testing.T, cl *tailscale.Client, hostname string) *tsnet.Server {
	t.Helper()
	caps := tailscale.KeyCapabilities{}
	caps.Devices.Create.Preauthorized = true
	caps.Devices.Create.Ephemeral = true
	caps.Devices.Create.Tags = []string{"tag:k8s"}
	authKey, err := cl.Keys().CreateAuthKey(t.Context(), tailscale.CreateKeyRequest{Capabilities: caps})
	if err != nil {
		t.Fatalf("creating auth key: %v", err)
	}
	t.Cleanup(func() { cl.Keys().Delete(context.Background(), authKey.ID) })

	srv := &tsnet.Server{
		ControlURL: cl.BaseURL.String(),
		Hostname:   hostname,
		Ephemeral:  true,
		Store:      &mem.Store{},
		AuthKey:    authKey.Key,
	}
	if _, err := srv.Up(t.Context()); err != nil {
		t.Fatalf("bringing up node: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

// staticEndpointsNodeSelector selects the Nodes whose ExternalIPs are
// advertised as static endpoints. Every Linux Node carries this label, so it
// selects all Nodes that can run proxies while still exercising the selector.
var staticEndpointsNodeSelector = map[string]string{"kubernetes.io/os": "linux"}

// staticEndpointsDevice is the parent-type-agnostic status of a single proxy
// replica: its tailnet IPs and the static endpoints reported in the parent
// resource's status.
type staticEndpointsDevice struct {
	tailnetIPs      []string
	staticEndpoints []string
}

// requireNodeExternalIPs returns the ExternalIP addresses of the Nodes matched
// by [staticEndpointsNodeSelector]. It skips the test if there are none, as
// is the case for kind clusters, because the operator can only discover
// static endpoints from Node ExternalIPs.
func requireNodeExternalIPs(t *testing.T) []netip.Addr {
	t.Helper()

	var nodes corev1.NodeList
	if err := kubeClient.List(t.Context(), &nodes, client.MatchingLabels(staticEndpointsNodeSelector)); err != nil {
		t.Fatalf("listing Nodes: %v", err)
	}

	var addrs []netip.Addr
	for _, n := range nodes.Items {
		for _, a := range n.Status.Addresses {
			if a.Type != corev1.NodeExternalIP {
				continue
			}
			addr, err := netip.ParseAddr(a.Address)
			if err != nil {
				t.Fatalf("Node %s has invalid ExternalIP %q: %v", n.Name, a.Address, err)
			}
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 {
		t.Skip("no Nodes have ExternalIP addresses to use as static endpoints")
	}

	return addrs
}

// applyStaticEndpointsProxyClass creates a ProxyClass that configures static
// endpoints with NodePorts from the given range, waits for it to be ready,
// and returns it. Apart from static endpoints it matches the suite's default
// ProxyClass.
func applyStaticEndpointsProxyClass(t *testing.T, ports tsapi.PortRange) *tsapi.ProxyClass {
	t.Helper()

	var env []tsapi.Env
	if *fDevcontrol {
		env = []tsapi.Env{
			{
				Name:  "TS_DEBUG_ACME_DIRECTORY_URL",
				Value: "https://pebble:14000/dir",
			},
		}
	}

	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("static-endpoints")},
		Spec: tsapi.ProxyClassSpec{
			UseLetsEncryptStagingEnvironment: !*fDevcontrol,
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleInitContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
					},
					TailscaleContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
						Env:             env,
					},
				},
			},
			StaticEndpoints: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports:    []tsapi.PortRange{ports},
					Selector: staticEndpointsNodeSelector,
				},
			},
		},
	}
	createAndCleanup(t, kubeClient, pc)
	waitForProxyClassReady(t, pc.Name)

	return pc
}

func waitForProxyClassReady(t *testing.T, name string) {
	t.Helper()

	if err := tstest.WaitFor(time.Minute, func() error {
		pc := &tsapi.ProxyClass{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if err := get(t.Context(), kubeClient, pc); err != nil {
			return err
		}
		if !tsoperator.ProxyClassIsReady(pc) {
			return fmt.Errorf("ProxyClass %s not ready yet: %v", name, pc.Status.Conditions)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for ProxyClass %s to be ready: %v", name, err)
	}
}

// removeStaticEndpoints removes the static endpoints configuration from the
// named ProxyClass and waits for the change to be accepted.
func removeStaticEndpoints(t *testing.T, name string) {
	t.Helper()

	patchObject(t, &tsapi.ProxyClass{ObjectMeta: metav1.ObjectMeta{Name: name}}, func(pc *tsapi.ProxyClass) {
		pc.Spec.StaticEndpoints = nil
	})
	waitForProxyClassReady(t, name)
}

// patchObject fetches obj, applies mutate to it and sends the difference as a
// merge patch. A merge patch carries no resourceVersion, so it does not
// conflict with the operator's concurrent status updates.
func patchObject[T client.Object](t *testing.T, obj T, mutate func(T)) {
	t.Helper()

	if err := get(t.Context(), kubeClient, obj); err != nil {
		t.Fatalf("getting %s: %v", obj.GetName(), err)
	}
	base := obj.DeepCopyObject().(client.Object)
	mutate(obj)
	if err := kubeClient.Patch(t.Context(), obj, client.MergeFrom(base)); err != nil {
		t.Fatalf("patching %s: %v", obj.GetName(), err)
	}
}

func checkDevices(kind, name string, devices []staticEndpointsDevice, replicas int, wantStaticEndpoints bool) error {
	if len(devices) != replicas {
		return fmt.Errorf("%s %s has %d devices in status, want %d", kind, name, len(devices), replicas)
	}
	for _, d := range devices {
		if len(d.tailnetIPs) == 0 {
			return fmt.Errorf("%s %s has a device with no tailnet IPs yet", kind, name)
		}
		if got := len(d.staticEndpoints) > 0; got != wantStaticEndpoints {
			return fmt.Errorf("%s %s device %v has static endpoints %v, want static endpoints: %t", kind, name, d.tailnetIPs, d.staticEndpoints, wantStaticEndpoints)
		}
	}
	return nil
}

// verifyStaticEndpoints verifies, for a parent resource with the given number
// of replicas, that:
//   - each replica has a UDP NodePort Service with a NodePort from ports,
//     whose target port is the port tailscaled listens on (the PORT env var);
//   - the static endpoints in each device's status are Node ExternalIPs
//     combined with the NodePort of one of the replicas' Services, with no two
//     devices sharing a NodePort;
//   - each device advertises its static endpoints to control, and has an
//     endpoint on the tailscaled port, which shows tailscaled bound to it.
func verifyStaticEndpoints(t *testing.T, parentType, parentName string, replicas int, ports tsapi.PortRange, externalIPs []netip.Addr, devices []staticEndpointsDevice) {
	t.Helper()

	svcs := waitForNodePortServices(t, parentType, parentName, replicas)
	tailscaledPort := portEnv(t, parentType, parentName)

	nodePorts := make(map[uint16]bool)
	for _, svc := range svcs {
		if len(svc.Spec.Ports) != 1 {
			t.Fatalf("Service %s has %d ports, want 1", svc.Name, len(svc.Spec.Ports))
		}
		p := svc.Spec.Ports[0]
		if p.Protocol != corev1.ProtocolUDP {
			t.Errorf("Service %s port protocol = %s, want UDP", svc.Name, p.Protocol)
		}
		if !ports.Contains(uint16(p.NodePort)) {
			t.Errorf("Service %s NodePort %d not in configured range %s", svc.Name, p.NodePort, ports.String())
		}
		if p.TargetPort.IntValue() != int(tailscaledPort) {
			t.Errorf("Service %s target port = %s, want tailscaled port %d", svc.Name, p.TargetPort.String(), tailscaledPort)
		}
		nodePorts[uint16(p.NodePort)] = true
	}

	wantEndpoints := min(len(externalIPs), 2)
	deviceIDs := deviceIDsByTailnetIP(t, parentType, parentName)
	usedNodePorts := make(map[uint16]bool)
	for _, d := range devices {
		if len(d.staticEndpoints) != wantEndpoints {
			t.Errorf("device %v has %d static endpoints %v, want %d", d.tailnetIPs, len(d.staticEndpoints), d.staticEndpoints, wantEndpoints)
		}

		var devicePort uint16
		for _, s := range d.staticEndpoints {
			ep, err := netip.ParseAddrPort(s)
			if err != nil {
				t.Fatalf("device %v has invalid static endpoint %q: %v", d.tailnetIPs, s, err)
			}
			if !slices.Contains(externalIPs, ep.Addr()) {
				t.Errorf("device %v static endpoint %s is not a Node ExternalIP %v", d.tailnetIPs, ep, externalIPs)
			}
			if !nodePorts[ep.Port()] {
				t.Errorf("device %v static endpoint %s does not use a NodePort of the Services %v", d.tailnetIPs, ep, nodePorts)
			}
			if devicePort != 0 && devicePort != ep.Port() {
				t.Errorf("device %v static endpoints %v use more than one port", d.tailnetIPs, d.staticEndpoints)
			}
			devicePort = ep.Port()
		}
		if usedNodePorts[devicePort] {
			t.Errorf("device %v shares NodePort %d with another device", d.tailnetIPs, devicePort)
		}
		usedNodePorts[devicePort] = true

		var deviceID string
		for _, ip := range d.tailnetIPs {
			if id, ok := deviceIDs[ip]; ok {
				deviceID = id
				break
			}
		}
		if deviceID == "" {
			t.Fatalf("no state Secret found for device %v", d.tailnetIPs)
		}
		verifyAdvertisedEndpoints(t, deviceID, d.staticEndpoints, tailscaledPort)
	}
}

// verifyAdvertisedEndpoints waits for control to report that the device
// advertises all of staticEndpoints, and an endpoint on tailscaledPort. The
// latter is the device's local Pod IP endpoint, which shows that tailscaled
// listens on the port that the NodePort Services target.
func verifyAdvertisedEndpoints(t *testing.T, deviceID string, staticEndpoints []string, tailscaledPort uint16) {
	t.Helper()

	if err := tstest.WaitFor(2*time.Minute, func() error {
		dev, err := tsClient.Devices().GetWithAllFields(t.Context(), deviceID)
		if err != nil {
			return fmt.Errorf("get device %s: %w", deviceID, err)
		}
		if dev.ClientConnectivity == nil {
			return fmt.Errorf("device %s has no client connectivity info yet", deviceID)
		}
		advertised := dev.ClientConnectivity.Endpoints
		for _, ep := range staticEndpoints {
			if !slices.Contains(advertised, ep) {
				return fmt.Errorf("device %s does not advertise static endpoint %s: %v", deviceID, ep, advertised)
			}
		}
		if !slices.ContainsFunc(advertised, func(s string) bool {
			ep, err := netip.ParseAddrPort(s)
			return err == nil && ep.Port() == tailscaledPort
		}) {
			return fmt.Errorf("device %s advertises no endpoint on tailscaled port %d: %v", deviceID, tailscaledPort, advertised)
		}
		return nil
	}); err != nil {
		t.Fatalf("verifying endpoints advertised by device %s: %v", deviceID, err)
	}
}

// deviceIDsByTailnetIP returns the device IDs of the parent resource's
// replicas, keyed by each of their tailnet IPs, as read from their state
// Secrets.
func deviceIDsByTailnetIP(t *testing.T, parentType, parentName string) map[string]string {
	t.Helper()

	var secrets corev1.SecretList
	if err := kubeClient.List(t.Context(), &secrets, client.InNamespace("tailscale"), client.MatchingLabels{
		"tailscale.com/parent-resource-type": parentType,
		"tailscale.com/parent-resource":      parentName,
	}); err != nil {
		t.Fatalf("listing state Secrets: %v", err)
	}

	ids := make(map[string]string)
	for _, s := range secrets.Items {
		id := string(s.Data[kubetypes.KeyDeviceID])
		if id == "" {
			continue
		}
		var ips []string
		if err := json.Unmarshal(s.Data[kubetypes.KeyDeviceIPs], &ips); err != nil {
			t.Fatalf("parsing device IPs in Secret %s: %v", s.Name, err)
		}
		for _, ip := range ips {
			ids[ip] = id
		}
	}

	return ids
}

// waitForNodePortServices waits for the parent resource to have exactly one
// static endpoints NodePort Service per replica, named after the replica's
// ordinal, and returns them.
func waitForNodePortServices(t *testing.T, parentType, parentName string, replicas int) []corev1.Service {
	t.Helper()

	var svcs []corev1.Service
	if err := tstest.WaitFor(3*time.Minute, func() error {
		var list corev1.ServiceList
		if err := kubeClient.List(t.Context(), &list, client.InNamespace("tailscale"), client.MatchingLabels{
			"tailscale.com/parent-resource-type": parentType,
			"tailscale.com/parent-resource":      parentName,
		}); err != nil {
			return err
		}

		svcs = svcs[:0]
		for _, svc := range list.Items {
			if svc.Spec.Type == corev1.ServiceTypeNodePort {
				svcs = append(svcs, svc)
			}
		}
		if len(svcs) != replicas {
			return fmt.Errorf("found %d NodePort Services for %s %s, want %d", len(svcs), parentType, parentName, replicas)
		}
		for i := range replicas {
			name := fmt.Sprintf("%s-%d-nodeport", parentName, i)
			if !slices.ContainsFunc(svcs, func(svc corev1.Service) bool { return svc.Name == name }) {
				return fmt.Errorf("NodePort Service %s not found", name)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for NodePort Services: %v", err)
	}

	return svcs
}

// statefulSetPortEnv returns the value of the PORT env var of the tailscale
// container in the parent resource's StatefulSet, and whether it is set.
func statefulSetPortEnv(t *testing.T, parentType, parentName string) (string, bool, error) {
	t.Helper()

	var list appsv1.StatefulSetList
	if err := kubeClient.List(t.Context(), &list, client.InNamespace("tailscale"), client.MatchingLabels{
		"tailscale.com/parent-resource-type": parentType,
		"tailscale.com/parent-resource":      parentName,
	}); err != nil {
		return "", false, err
	}
	if len(list.Items) != 1 {
		return "", false, fmt.Errorf("found %d StatefulSets for %s %s, want 1", len(list.Items), parentType, parentName)
	}

	for _, c := range list.Items[0].Spec.Template.Spec.Containers {
		if c.Name != "tailscale" {
			continue
		}
		for _, e := range c.Env {
			if e.Name == "PORT" {
				return e.Value, true, nil
			}
		}
		return "", false, nil
	}

	return "", false, fmt.Errorf("StatefulSet %s has no tailscale container", list.Items[0].Name)
}

// portEnv returns the port tailscaled is configured to listen on via the
// PORT env var of the parent resource's StatefulSet.
func portEnv(t *testing.T, parentType, parentName string) uint16 {
	t.Helper()

	v, ok, err := statefulSetPortEnv(t, parentType, parentName)
	if err != nil {
		t.Fatalf("getting PORT env var: %v", err)
	}
	if !ok {
		t.Fatalf("StatefulSet for %s %s has no PORT env var", parentType, parentName)
	}
	port, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		t.Fatalf("invalid PORT env var %q: %v", v, err)
	}

	return uint16(port)
}

// waitForNoPortEnv waits for the PORT env var to be removed from the parent
// resource's StatefulSet.
func waitForNoPortEnv(t *testing.T, parentType, parentName string) {
	t.Helper()

	if err := tstest.WaitFor(time.Minute, func() error {
		v, ok, err := statefulSetPortEnv(t, parentType, parentName)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("StatefulSet for %s %s still has PORT env var %q", parentType, parentName, v)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for PORT env var to be removed: %v", err)
	}
}
