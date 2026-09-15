// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tailscaleclient "tailscale.com/client/tailscale/v2"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/routeacceptor"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/k8s-operator/tsclient"
	"tailscale.com/kube/kubetypes"
)

const (
	tailscaleNamespace = "tailscale"
	testProxyImage     = "tailscale/tailscale:test"
	testLoginURL       = "https://login.example.com"
	raName             = "test"
	dsName             = "routeacceptor-test"
	configSecretName   = "routeacceptor-test-config"
)

func newTestReconciler(t *testing.T, tsc *fakeTSClient, objs ...client.Object) (*routeacceptor.Reconciler, client.Client) {
	t.Helper()
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(objs...).
		WithStatusSubresource(&tsapi.RouteAcceptor{}, &tsapi.ProxyClass{}, &appsv1.DaemonSet{}).
		Build()
	r := routeacceptor.NewReconciler(routeacceptor.ReconcilerOptions{
		Client:                 cl,
		TailscaleNamespace:     tailscaleNamespace,
		ProxyImage:             testProxyImage,
		ProxyPriorityClassName: "ts-priority",
		DefaultTags:            []string{"tag:k8s"},
		Clients:                &fakeClientProvider{client: tsc},
		Logger:                 logger.Sugar(),
	})
	return r, cl
}

func mustReconcile(t *testing.T, r *routeacceptor.Reconciler, name string) reconcile.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		t.Fatalf("Reconcile(%q): %v", name, err)
	}
	return res
}

func newRouteAcceptor(spec tsapi.RouteAcceptorSpec) *tsapi.RouteAcceptor {
	return &tsapi.RouteAcceptor{
		ObjectMeta: metav1.ObjectMeta{Name: raName},
		Spec:       spec,
	}
}

func newNode(name string, labels map[string]string, podCIDRs ...string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{PodCIDRs: podCIDRs},
	}
}

func readyProxyClass(name string, nodeSelector map[string]string) *tsapi.ProxyClass {
	return &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{NodeSelector: nodeSelector},
			},
		},
		Status: tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Type:   string(tsapi.ProxyClassReady),
				Status: metav1.ConditionTrue,
			}},
		},
	}
}

func stateSecretLabels() map[string]string {
	l := reconciler.Labels("routeacceptor", raName, "")
	l[kubetypes.LabelSecretType] = kubetypes.LabelSecretTypeState
	return l
}

// newStateSecret returns a state Secret for the device on node, as the reconciler creates it and containerboot
// fills it in.
func newStateSecret(node string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        dsName + "-" + node,
			Namespace:   tailscaleNamespace,
			Labels:      stateSecretLabels(),
			Annotations: map[string]string{"tailscale.com/node-name": node},
		},
		Data: map[string][]byte{},
	}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	return s
}

func newConfigSecret(t *testing.T, authKey string, expires time.Time) *corev1.Secret {
	t.Helper()
	s, err := tailscaled.NewConfigSecret(tailscaled.ConfigSecretOptions{
		Name:      configSecretName,
		Namespace: tailscaleNamespace,
		Labels:    reconciler.Labels("routeacceptor", raName, ""),
		Config:    ipn.ConfigVAlpha{Version: "alpha0", AuthKey: &authKey, AcceptRoutes: "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Annotations = map[string]string{"tailscale.com/authkey-expires": expires.UTC().Format(time.RFC3339)}
	return s
}

func getRouteAcceptor(t *testing.T, cl client.Client) *tsapi.RouteAcceptor {
	t.Helper()
	var ra tsapi.RouteAcceptor
	if err := cl.Get(context.Background(), types.NamespacedName{Name: raName}, &ra); err != nil {
		t.Fatalf("getting RouteAcceptor: %v", err)
	}
	return &ra
}

func getDaemonSet(t *testing.T, cl client.Client) *appsv1.DaemonSet {
	t.Helper()
	var ds appsv1.DaemonSet
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: tailscaleNamespace, Name: dsName}, &ds); err != nil {
		t.Fatalf("getting DaemonSet: %v", err)
	}
	return &ds
}

func daemonSetExists(t *testing.T, cl client.Client) bool {
	t.Helper()
	var ds appsv1.DaemonSet
	err := cl.Get(context.Background(), types.NamespacedName{Namespace: tailscaleNamespace, Name: dsName}, &ds)
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("getting DaemonSet: %v", err)
	}
	return true
}

func getSecret(t *testing.T, cl client.Client, name string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: tailscaleNamespace, Name: name}, &s); err != nil {
		t.Fatalf("getting Secret %q: %v", name, err)
	}
	return &s
}

func secretExists(t *testing.T, cl client.Client, name string) bool {
	t.Helper()
	var s corev1.Secret
	err := cl.Get(context.Background(), types.NamespacedName{Namespace: tailscaleNamespace, Name: name}, &s)
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("getting Secret %q: %v", name, err)
	}
	return true
}

func configFromSecret(t *testing.T, s *corev1.Secret) ipn.ConfigVAlpha {
	t.Helper()
	for k, v := range s.Data {
		if !strings.HasPrefix(k, "cap-") {
			continue
		}
		var conf ipn.ConfigVAlpha
		if err := json.Unmarshal(v, &conf); err != nil {
			t.Fatalf("parsing config %q: %v", k, err)
		}
		return conf
	}
	t.Fatalf("no tailscaled config in Secret %q", s.Name)
	return ipn.ConfigVAlpha{}
}

func condition(ra *tsapi.RouteAcceptor, typ tsapi.ConditionType) *metav1.Condition {
	for i := range ra.Status.Conditions {
		if ra.Status.Conditions[i].Type == string(typ) {
			return &ra.Status.Conditions[i]
		}
	}
	return nil
}

func expectCondition(t *testing.T, ra *tsapi.RouteAcceptor, typ tsapi.ConditionType, status metav1.ConditionStatus, reason string) {
	t.Helper()
	c := condition(ra, typ)
	if c == nil {
		t.Fatalf("condition %s not set, got %+v", typ, ra.Status.Conditions)
	}
	if c.Status != status || c.Reason != reason {
		t.Errorf("condition %s = %s/%s (%s), want %s/%s", typ, c.Status, c.Reason, c.Message, status, reason)
	}
}

func envValue(c *corev1.Container, name string) string {
	for _, e := range c.Env {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}

func TestReconcile_CreatesResources(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{}),
		newNode("node-a", nil, "10.244.0.0/24"),
		newNode("node-b", nil, "10.244.1.0/24"),
	)

	res := mustReconcile(t, r, raName)
	if res.RequeueAfter <= 0 || res.RequeueAfter > 30*time.Second {
		t.Errorf("RequeueAfter = %v, want a short requeue while nodes are pending", res.RequeueAfter)
	}

	// The DaemonSet runs tailscaled in the host network namespace with kernel networking, in route acceptor mode,
	// reading the shared config and keeping per-node state.
	ds := getDaemonSet(t, cl)
	pod := ds.Spec.Template.Spec
	if !pod.HostNetwork {
		t.Error("DaemonSet Pods do not use the host network")
	}
	if pod.DNSPolicy != corev1.DNSClusterFirstWithHostNet {
		t.Errorf("DaemonSet Pod dnsPolicy = %q, want %q", pod.DNSPolicy, corev1.DNSClusterFirstWithHostNet)
	}
	if pod.ServiceAccountName != "proxies" {
		t.Errorf("ServiceAccountName = %q, want proxies", pod.ServiceAccountName)
	}
	if pod.PriorityClassName != "ts-priority" {
		t.Errorf("PriorityClassName = %q, want the operator's default", pod.PriorityClassName)
	}
	if len(pod.InitContainers) != 1 || pod.InitContainers[0].Name != "sysctler" || pod.InitContainers[0].SecurityContext == nil || !*pod.InitContainers[0].SecurityContext.Privileged {
		t.Errorf("unexpected init containers: %+v", pod.InitContainers)
	}
	if len(pod.Containers) != 1 {
		t.Fatalf("got %d containers, want 1", len(pod.Containers))
	}
	c := &pod.Containers[0]
	if c.Image != testProxyImage {
		t.Errorf("Image = %q, want %q", c.Image, testProxyImage)
	}
	if c.SecurityContext == nil || c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged {
		t.Error("tailscaled container is not privileged")
	}
	for name, want := range map[string]string{
		"TS_USERSPACE":                         "false",
		"TS_EXPERIMENTAL_ROUTE_ACCEPTOR":       "true",
		"TS_KUBE_SECRET":                       dsName + "-$(NODE_NAME)",
		"TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR": "/etc/tsconfig/" + dsName,
	} {
		if got := envValue(c, name); got != want {
			t.Errorf("env %s = %q, want %q", name, got, want)
		}
	}
	if len(pod.Volumes) != 1 || pod.Volumes[0].Secret == nil || pod.Volumes[0].Secret.SecretName != configSecretName {
		t.Errorf("unexpected volumes: %+v", pod.Volumes)
	}

	// The shared config accepts routes, leaves the hostname to the node, must not accept DNS, and carries a
	// reusable auth key.
	cfgSecret := getSecret(t, cl, configSecretName)
	conf := configFromSecret(t, cfgSecret)
	if conf.AcceptRoutes != "true" {
		t.Errorf("AcceptRoutes = %q, want true", conf.AcceptRoutes)
	}
	if conf.AcceptDNS != "false" {
		t.Errorf("AcceptDNS = %q, want false", conf.AcceptDNS)
	}
	if conf.Hostname != nil {
		t.Errorf("Hostname = %q, want unset", *conf.Hostname)
	}
	if conf.ServerURL == nil || *conf.ServerURL != testLoginURL {
		t.Errorf("ServerURL = %v, want %q", conf.ServerURL, testLoginURL)
	}
	if conf.AuthKey == nil || *conf.AuthKey != "auth-key-1" {
		t.Errorf("AuthKey = %v, want auth-key-1", conf.AuthKey)
	}
	expires, err := time.Parse(time.RFC3339, cfgSecret.Annotations["tailscale.com/authkey-expires"])
	if err != nil {
		t.Fatalf("parsing expiry annotation: %v", err)
	}
	if expires.Before(time.Now().Add(89 * 24 * time.Hour)) {
		t.Errorf("auth key expiry %v is too soon", expires)
	}

	calls := tsc.CreateAuthKeyCalls()
	if len(calls) != 1 {
		t.Fatalf("got %d CreateAuthKey calls, want 1", len(calls))
	}
	caps := calls[0].Capabilities.Devices.Create
	if !caps.Reusable || !caps.Preauthorized || caps.Ephemeral {
		t.Errorf("unexpected key capabilities: %+v", caps)
	}
	if !slices.Equal(caps.Tags, []string{"tag:k8s"}) {
		t.Errorf("Tags = %v, want [tag:k8s]", caps.Tags)
	}
	if calls[0].ExpirySeconds != int64((90 * 24 * time.Hour).Seconds()) {
		t.Errorf("ExpirySeconds = %d, want 90 days", calls[0].ExpirySeconds)
	}

	// One labelled state Secret per node, recording the node's name.
	for _, node := range []string{"node-a", "node-b"} {
		s := getSecret(t, cl, dsName+"-"+node)
		if s.Annotations["tailscale.com/node-name"] != node {
			t.Errorf("state Secret for %s has annotations %v", node, s.Annotations)
		}
		if s.Labels[kubetypes.LabelSecretType] != kubetypes.LabelSecretTypeState || s.Labels[reconciler.LabelParentName] != raName {
			t.Errorf("state Secret for %s has labels %v", node, s.Labels)
		}
	}

	ra := getRouteAcceptor(t, cl)
	if !slices.Contains(ra.Finalizers, reconciler.Finalizer) {
		t.Errorf("finalizer not set, got %v", ra.Finalizers)
	}
	// The fake DaemonSet controller never schedules anything.
	expectCondition(t, ra, tsapi.RouteAcceptorReady, metav1.ConditionFalse, routeacceptor.ReasonNoNodesSelected)
	expectCondition(t, ra, tsapi.RouteAcceptorRoutesValid, metav1.ConditionTrue, routeacceptor.ReasonRoutesValid)

	// A second reconcile keeps the key: it must stay available for nodes joining later.
	mustReconcile(t, r, raName)
	if got := len(tsc.CreateAuthKeyCalls()); got != 1 {
		t.Errorf("got %d CreateAuthKey calls after two reconciles, want 1", got)
	}
	if conf := configFromSecret(t, getSecret(t, cl, configSecretName)); conf.AuthKey == nil || *conf.AuthKey != "auth-key-1" {
		t.Errorf("AuthKey after second reconcile = %v, want auth-key-1", conf.AuthKey)
	}
}

func TestReconcile_StatusFromDevices(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: dsName, Namespace: tailscaleNamespace, Labels: reconciler.Labels("routeacceptor", raName, "")},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, NumberReady: 2},
	}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{ClusterCIDRs: tsapi.Routes{"10.96.0.0/12"}}),
		newNode("node-a", nil, "10.244.0.0/24"),
		newNode("node-b", nil, "10.244.1.0/24"),
		ds,
		newStateSecret("node-a", map[string]string{
			kubetypes.KeyDeviceID:       "dev-a",
			kubetypes.KeyDeviceFQDN:     "node-a.example.ts.net.",
			kubetypes.KeyDeviceIPs:      `["100.64.0.1"]`,
			kubetypes.KeyAcceptedRoutes: `["10.20.0.0/16","192.168.0.0/24"]`,
		}),
		newStateSecret("node-b", map[string]string{
			kubetypes.KeyDeviceID:       "dev-b",
			kubetypes.KeyDeviceFQDN:     "node-b.example.ts.net.",
			kubetypes.KeyDeviceIPs:      `["100.64.0.2"]`,
			kubetypes.KeyAcceptedRoutes: `["10.20.0.0/16","10.244.1.128/25","10.100.0.0/16"]`,
		}),
	)

	res := mustReconcile(t, r, raName)
	if res.RequeueAfter < 60*24*time.Hour {
		t.Errorf("RequeueAfter = %v, want the auth key rotation time as all nodes are ready", res.RequeueAfter)
	}

	ra := getRouteAcceptor(t, cl)
	expectCondition(t, ra, tsapi.RouteAcceptorReady, metav1.ConditionTrue, routeacceptor.ReasonReady)
	if ra.Status.DesiredNodes != 2 || ra.Status.ReadyNodes != 2 {
		t.Errorf("DesiredNodes/ReadyNodes = %d/%d, want 2/2", ra.Status.DesiredNodes, ra.Status.ReadyNodes)
	}
	wantRoutes := []string{"10.20.0.0/16", "10.100.0.0/16", "10.244.1.128/25", "192.168.0.0/24"}
	if !slices.Equal(ra.Status.AcceptedRoutes, wantRoutes) {
		t.Errorf("AcceptedRoutes = %v, want %v", ra.Status.AcceptedRoutes, wantRoutes)
	}
	if len(ra.Status.Nodes) != 2 {
		t.Fatalf("Nodes = %+v, want 2 entries", ra.Status.Nodes)
	}
	a := ra.Status.Nodes[0]
	if a.Name != "node-a" || a.Hostname != "node-a.example.ts.net." || !a.Ready || !slices.Equal(a.TailnetIPs, []string{"100.64.0.1"}) || !slices.Equal(a.AcceptedRoutes, []string{"10.20.0.0/16", "192.168.0.0/24"}) {
		t.Errorf("unexpected status for node-a: %+v", a)
	}
	if ra.Status.Nodes[1].Name != "node-b" {
		t.Errorf("Nodes[1] = %+v, want node-b", ra.Status.Nodes[1])
	}

	// A route overlapping a Pod CIDR recorded on a Node is flagged; the spec.clusterCIDRs range is checked too.
	c := condition(ra, tsapi.RouteAcceptorRoutesValid)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != routeacceptor.ReasonRouteOverlapsClusterCIDR {
		t.Fatalf("RoutesValid = %+v, want False/%s", c, routeacceptor.ReasonRouteOverlapsClusterCIDR)
	}
	if !strings.Contains(c.Message, "10.244.1.128/25 overlaps 10.244.1.0/24") {
		t.Errorf("RoutesValid message = %q, want it to name the overlap", c.Message)
	}
}

func TestReconcile_CGNATOverlap(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{}),
		newNode("node-a", nil, "100.70.0.0/24"),
	)

	if res := mustReconcile(t, r, raName); res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want none: retrying does not help", res.RequeueAfter)
	}
	ra := getRouteAcceptor(t, cl)
	expectCondition(t, ra, tsapi.RouteAcceptorReady, metav1.ConditionFalse, routeacceptor.ReasonClusterCIDROverlapsCGNAT)
	if daemonSetExists(t, cl) {
		t.Error("DaemonSet was created despite the cluster CIDR overlapping the Tailscale IP range")
	}
	if got := len(tsc.CreateAuthKeyCalls()); got != 0 {
		t.Errorf("got %d CreateAuthKey calls, want 0", got)
	}

	// The user takes responsibility.
	ra.Spec.UnsafeAllowCGNATClusterCIDR = true
	if err := cl.Update(context.Background(), ra); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r, raName)
	if !daemonSetExists(t, cl) {
		t.Error("DaemonSet was not created with spec.unsafeAllowCGNATClusterCIDR set")
	}
}

func TestReconcile_ProxyClass(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	pc := readyProxyClass("gateways", map[string]string{"role": "gateway"})
	pc.Spec.StatefulSet.Pod.Tolerations = []corev1.Toleration{{Key: "gateway", Operator: corev1.TolerationOpExists}}
	pc.Spec.StatefulSet.Pod.NodeName = "must-be-ignored"
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{ProxyClass: "gateways"}),
		pc,
		newNode("node-a", map[string]string{"role": "gateway"}),
		newNode("node-b", nil),
		// node-b used to be selected and still holds a device.
		newStateSecret("node-b", map[string]string{kubetypes.KeyDeviceID: "dev-b"}),
		// node-c is gone from the cluster altogether.
		newStateSecret("node-c", map[string]string{kubetypes.KeyDeviceID: "dev-c"}),
	)

	mustReconcile(t, r, raName)

	ds := getDaemonSet(t, cl)
	pod := ds.Spec.Template.Spec
	if pod.NodeSelector["role"] != "gateway" {
		t.Errorf("NodeSelector = %v, want the ProxyClass's", pod.NodeSelector)
	}
	if len(pod.Tolerations) != 1 || pod.Tolerations[0].Key != "gateway" {
		t.Errorf("Tolerations = %v, want the ProxyClass's", pod.Tolerations)
	}
	if pod.NodeName != "" {
		t.Errorf("NodeName = %q, want it ignored for a DaemonSet", pod.NodeName)
	}
	if !secretExists(t, cl, dsName+"-node-a") {
		t.Error("no state Secret for the selected node-a")
	}
	for _, node := range []string{"node-b", "node-c"} {
		if secretExists(t, cl, dsName+"-"+node) {
			t.Errorf("state Secret for %s still exists", node)
		}
	}
	deletes := tsc.DeviceDeletes()
	slices.Sort(deletes)
	if !slices.Equal(deletes, []string{"dev-b", "dev-c"}) {
		t.Errorf("deleted devices = %v, want [dev-b dev-c]", deletes)
	}

	// A not-yet-ready ProxyClass blocks the deployment.
	pc.Status.Conditions[0].Status = metav1.ConditionFalse
	if err := cl.Status().Update(context.Background(), pc); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r, raName)
	expectCondition(t, getRouteAcceptor(t, cl), tsapi.RouteAcceptorReady, metav1.ConditionFalse, routeacceptor.ReasonProxyClassNotReady)
}

func TestReconcile_ProxyClassDeselectsNodeWithPod(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: dsName + "-xyz", Namespace: tailscaleNamespace, Labels: reconciler.Labels("routeacceptor", raName, "")},
		Spec:       corev1.PodSpec{NodeName: "node-b"},
	}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{ProxyClass: "gateways"}),
		readyProxyClass("gateways", map[string]string{"role": "gateway"}),
		newNode("node-a", map[string]string{"role": "gateway"}),
		newNode("node-b", nil),
		newStateSecret("node-b", map[string]string{kubetypes.KeyDeviceID: "dev-b"}),
		pod,
	)

	mustReconcile(t, r, raName)

	// The DaemonSet controller has not removed node-b's Pod yet, so its device must be left alone.
	if !secretExists(t, cl, dsName+"-node-b") {
		t.Error("state Secret for node-b was deleted while its Pod still runs")
	}
	if got := tsc.DeviceDeletes(); len(got) != 0 {
		t.Errorf("deleted devices = %v, want none", got)
	}
}

func TestReconcile_AuthKeyRotation(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{}),
		newNode("node-a", nil),
		// The current key expires within the rotation window.
		newConfigSecret(t, "old-key", time.Now().Add(24*time.Hour)),
	)

	mustReconcile(t, r, raName)

	if got := len(tsc.CreateAuthKeyCalls()); got != 1 {
		t.Fatalf("got %d CreateAuthKey calls, want 1", got)
	}
	if conf := configFromSecret(t, getSecret(t, cl, configSecretName)); conf.AuthKey == nil || *conf.AuthKey != "auth-key-1" {
		t.Errorf("AuthKey = %v, want the rotated key auth-key-1", conf.AuthKey)
	}
	// Nothing to delete: rotation does not affect existing devices.
	if got := tsc.DeviceDeletes(); len(got) != 0 {
		t.Errorf("deleted devices = %v, want none", got)
	}
}

func TestReconcile_AuthKeyReissue(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{}),
		newNode("node-a", nil),
		newNode("node-b", nil),
		newConfigSecret(t, "current-key", time.Now().Add(60*24*time.Hour)),
		// node-a's device could not authenticate with the current key.
		newStateSecret("node-a", map[string]string{
			kubetypes.KeyDeviceID:       "dev-a",
			kubetypes.KeyReissueAuthkey: "current-key",
		}),
		newStateSecret("node-b", map[string]string{kubetypes.KeyDeviceID: "dev-b"}),
	)

	mustReconcile(t, r, raName)

	if got := len(tsc.CreateAuthKeyCalls()); got != 1 {
		t.Fatalf("got %d CreateAuthKey calls, want 1", got)
	}
	if conf := configFromSecret(t, getSecret(t, cl, configSecretName)); conf.AuthKey == nil || *conf.AuthKey != "auth-key-1" {
		t.Errorf("AuthKey = %v, want the reissued key auth-key-1", conf.AuthKey)
	}
	// Only the failing device is cleaned up; node-b's device keeps working.
	if got := tsc.DeviceDeletes(); !slices.Equal(got, []string{"dev-a"}) {
		t.Errorf("deleted devices = %v, want [dev-a]", got)
	}

	// The request is still pending on node-a's state Secret (containerboot clears it once it has picked up the
	// new key), which must not cause another key to be minted.
	mustReconcile(t, r, raName)
	if got := len(tsc.CreateAuthKeyCalls()); got != 1 {
		t.Errorf("got %d CreateAuthKey calls after second reconcile, want 1", got)
	}
}

func TestReconcile_NodeNameTooLong(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{}),
		newNode(strings.Repeat("n", 250), nil),
	)

	mustReconcile(t, r, raName)
	expectCondition(t, getRouteAcceptor(t, cl), tsapi.RouteAcceptorReady, metav1.ConditionFalse, routeacceptor.ReasonNodeNameTooLong)
	if daemonSetExists(t, cl) {
		t.Error("DaemonSet was created despite an unusable node name")
	}
}

func TestReconcile_Delete(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	now := metav1.Now()
	ra := newRouteAcceptor(tsapi.RouteAcceptorSpec{})
	ra.DeletionTimestamp = &now
	ra.Finalizers = []string{reconciler.Finalizer}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: dsName, Namespace: tailscaleNamespace, Labels: reconciler.Labels("routeacceptor", raName, "")},
	}
	r, cl := newTestReconciler(t, tsc,
		ra,
		ds,
		newConfigSecret(t, "current-key", time.Now().Add(60*24*time.Hour)),
		newStateSecret("node-a", map[string]string{kubetypes.KeyDeviceID: "dev-a"}),
		newStateSecret("node-b", map[string]string{}),
	)

	mustReconcile(t, r, raName)

	if daemonSetExists(t, cl) {
		t.Error("DaemonSet still exists")
	}
	for _, name := range []string{configSecretName, dsName + "-node-a", dsName + "-node-b"} {
		if secretExists(t, cl, name) {
			t.Errorf("Secret %s still exists", name)
		}
	}
	if got := tsc.DeviceDeletes(); !slices.Equal(got, []string{"dev-a"}) {
		t.Errorf("deleted devices = %v, want [dev-a]", got)
	}
	var got tsapi.RouteAcceptor
	if err := cl.Get(context.Background(), types.NamespacedName{Name: raName}, &got); !apierrors.IsNotFound(err) {
		t.Errorf("RouteAcceptor still exists (err=%v), finalizer not cleared", err)
	}
}

type fakeClientProvider struct {
	client tsclient.Client
	err    error
}

func (p *fakeClientProvider) For(_ string) (tsclient.Client, error) { return p.client, p.err }

type fakeTSClient struct {
	tsclient.Client

	loginURL string

	mu            sync.Mutex
	keyCalls      []tailscaleclient.CreateKeyRequest
	deviceDeletes []string
}

func (c *fakeTSClient) Keys() tsclient.KeyResource       { return (*fakeKeys)(c) }
func (c *fakeTSClient) Devices() tsclient.DeviceResource { return (*fakeDevices)(c) }
func (c *fakeTSClient) LoginURL() string                 { return c.loginURL }

func (c *fakeTSClient) CreateAuthKeyCalls() []tailscaleclient.CreateKeyRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.keyCalls)
}

func (c *fakeTSClient) DeviceDeletes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.deviceDeletes)
}

type fakeKeys fakeTSClient

func (k *fakeKeys) CreateAuthKey(_ context.Context, req tailscaleclient.CreateKeyRequest) (*tailscaleclient.Key, error) {
	c := (*fakeTSClient)(k)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyCalls = append(c.keyCalls, req)
	return &tailscaleclient.Key{
		Key:     fmt.Sprintf("auth-key-%d", len(c.keyCalls)),
		Expires: time.Now().Add(time.Duration(req.ExpirySeconds) * time.Second),
	}, nil
}

func (k *fakeKeys) List(_ context.Context, _ bool) ([]tailscaleclient.Key, error) { return nil, nil }

type fakeDevices fakeTSClient

func (d *fakeDevices) Delete(_ context.Context, id string) error {
	c := (*fakeTSClient)(d)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deviceDeletes = append(c.deviceDeletes, id)
	return nil
}

func (d *fakeDevices) List(_ context.Context, _ ...tailscaleclient.ListDevicesOptions) ([]tailscaleclient.Device, error) {
	return nil, nil
}

func (d *fakeDevices) Get(_ context.Context, _ string) (*tailscaleclient.Device, error) {
	return nil, nil
}
