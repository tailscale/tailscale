// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

func ciliumConfig(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-config", Namespace: "kube-system"},
		Data:       data,
	}
}

func ciliumEgressGatewayCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ciliumegressgatewaypolicies.cilium.io"},
	}
}

func getEgressGatewayPolicy(t *testing.T, cl client.Client) *unstructured.Unstructured {
	t.Helper()
	return getEgressGatewayPolicyNamed(t, cl, dsName)
}

func getEgressGatewayPolicyNamed(t *testing.T, cl client.Client, name string) *unstructured.Unstructured {
	t.Helper()
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumEgressGatewayPolicy"})
	err := cl.Get(context.Background(), types.NamespacedName{Name: name}, u)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("getting CiliumEgressGatewayPolicy: %v", err)
	}
	return u
}

func TestReconcile_CiliumEBPFHostRoutingBlocks(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{}),
		newNode("node-a", nil),
		ciliumConfig(map[string]string{"enable-bpf-masquerade": "true", "kube-proxy-replacement": "true"}),
	)

	res := mustReconcile(t, r, raName)
	if res.RequeueAfter != 10*time.Minute {
		t.Errorf("RequeueAfter = %v, want 10m to re-check the CNI configuration", res.RequeueAfter)
	}
	ra := getRouteAcceptor(t, cl)
	expectCondition(t, ra, tsapi.RouteAcceptorReady, metav1.ConditionFalse, routeacceptor.ReasonCiliumEBPFHostRouting)
	expectCondition(t, ra, tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionFalse, routeacceptor.ReasonCiliumEBPFHostRouting)
	if daemonSetExists(t, cl) {
		t.Error("DaemonSet was created despite Cilium eBPF host routing")
	}
	if got := len(tsc.CreateAuthKeyCalls()); got != 0 {
		t.Errorf("got %d CreateAuthKey calls, want 0", got)
	}

	// Legacy host routing makes the host-routing data plane work.
	cm := ciliumConfig(map[string]string{"enable-bpf-masquerade": "true", "kube-proxy-replacement": "true", "enable-host-legacy-routing": "true"})
	if err := cl.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r, raName)
	if !daemonSetExists(t, cl) {
		t.Error("DaemonSet was not created with Cilium legacy host routing")
	}
	expectCondition(t, getRouteAcceptor(t, cl), tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionTrue, routeacceptor.ReasonDataPlaneSupported)
}

func TestReconcile_CiliumUnsafeAllow(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{UnsafeAllowIncompatibleCNI: true}),
		newNode("node-a", nil),
		ciliumConfig(map[string]string{"install-no-conntrack-iptables-rules": "true"}),
	)
	mustReconcile(t, r, raName)
	if !daemonSetExists(t, cl) {
		t.Error("DaemonSet was not created with spec.unsafeAllowIncompatibleCNI set")
	}
}

func TestReconcile_CiliumEgressGateway(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: dsName, Namespace: tailscaleNamespace, Labels: reconciler.Labels("routeacceptor", raName, "")},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, NumberReady: 2},
	}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{
			Cilium: &tsapi.RouteAcceptorCilium{EgressGateway: &tsapi.CiliumEgressGateway{}},
		}),
		newNode("node-a", nil),
		newNode("node-b", nil),
		// eBPF host routing does not matter in this mode.
		ciliumConfig(map[string]string{
			"enable-bpf-masquerade":  "true",
			"kube-proxy-replacement": "true",
			"enable-egress-gateway":  "true",
			"devices":                "eth0,tailscale0",
		}),
		ciliumEgressGatewayCRD(),
		ds,
		newStateSecret("node-a", map[string]string{
			kubetypes.KeyDeviceID:       "dev-a",
			kubetypes.KeyDeviceIPs:      `["100.64.0.1"]`,
			kubetypes.KeyAcceptedRoutes: `["10.20.0.0/16"]`,
		}),
		// node-b's device has not joined yet: not a gateway.
		newStateSecret("node-b", map[string]string{}),
	)

	res := mustReconcile(t, r, raName)
	if res.RequeueAfter <= 0 || res.RequeueAfter > 5*time.Minute {
		t.Errorf("RequeueAfter = %v, want at most 5m to re-check the policy", res.RequeueAfter)
	}
	ra := getRouteAcceptor(t, cl)
	expectCondition(t, ra, tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionTrue, routeacceptor.ReasonCiliumEgressGateway)
	expectCondition(t, ra, tsapi.RouteAcceptorReady, metav1.ConditionTrue, routeacceptor.ReasonReady)
	if !daemonSetExists(t, cl) {
		t.Fatal("DaemonSet missing")
	}

	pol := getEgressGatewayPolicy(t, cl)
	if pol == nil {
		t.Fatal("CiliumEgressGatewayPolicy was not created")
	}
	if pol.GetLabels()[reconciler.LabelParentName] != raName {
		t.Errorf("policy labels = %v", pol.GetLabels())
	}
	spec := pol.Object["spec"].(map[string]any)
	wantSpec := map[string]any{
		"selectors":        []any{map[string]any{"podSelector": map[string]any{}}},
		"destinationCIDRs": []any{"10.20.0.0/16"},
		"egressGateway": map[string]any{
			"nodeSelector": map[string]any{
				"matchExpressions": []any{map[string]any{"key": "kubernetes.io/hostname", "operator": "In", "values": []any{"node-a"}}},
			},
			"interface": "tailscale0",
		},
	}
	if diff := cmp.Diff(wantSpec, spec); diff != "" {
		t.Errorf("policy spec mismatch (-want +got):\n%s", diff)
	}

	// node-b joins and accepts a route: the policy follows.
	mustUpdateSecret(t, cl, dsName+"-node-b", map[string]string{
		kubetypes.KeyDeviceID:       "dev-b",
		kubetypes.KeyDeviceIPs:      `["100.64.0.2"]`,
		kubetypes.KeyAcceptedRoutes: `["10.20.0.0/16","10.30.0.0/24"]`,
	})
	mustReconcile(t, r, raName)
	spec = getEgressGatewayPolicy(t, cl).Object["spec"].(map[string]any)
	if diff := cmp.Diff([]any{"10.20.0.0/16", "10.30.0.0/24"}, spec["destinationCIDRs"]); diff != "" {
		t.Errorf("destinationCIDRs mismatch (-want +got):\n%s", diff)
	}
	values := spec["egressGateway"].(map[string]any)["nodeSelector"].(map[string]any)["matchExpressions"].([]any)[0].(map[string]any)["values"]
	if diff := cmp.Diff([]any{"node-a", "node-b"}, values); diff != "" {
		t.Errorf("gateway nodes mismatch (-want +got):\n%s", diff)
	}

	// High availability lists every gateway.
	ra = getRouteAcceptor(t, cl)
	ra.Spec.Cilium.EgressGateway.HighAvailability = true
	if err := cl.Update(context.Background(), ra); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r, raName)
	spec = getEgressGatewayPolicy(t, cl).Object["spec"].(map[string]any)
	if _, ok := spec["egressGateway"]; ok {
		t.Error("egressGateway still set in HA mode")
	}
	gws, _ := spec["egressGateways"].([]any)
	if len(gws) != 2 || gws[1].(map[string]any)["nodeSelector"].(map[string]any)["matchLabels"].(map[string]any)["kubernetes.io/hostname"] != "node-b" {
		t.Errorf("egressGateways = %v, want one per ready node", gws)
	}

	// Deleting the RouteAcceptor deletes the policy.
	ra = getRouteAcceptor(t, cl)
	if err := cl.Delete(context.Background(), ra); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r, raName)
	if getEgressGatewayPolicy(t, cl) != nil {
		t.Error("CiliumEgressGatewayPolicy still exists after deleting the RouteAcceptor")
	}
}

func TestReconcile_CiliumEgressGatewayPreconditions(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		objs       []client.Object
		wantReason string
	}{
		{
			name:       "no-cilium",
			wantReason: routeacceptor.ReasonCiliumNotDetected,
		},
		{
			name:       "crd-missing",
			objs:       []client.Object{ciliumConfig(map[string]string{"enable-egress-gateway": "true", "devices": "tailscale0"})},
			wantReason: routeacceptor.ReasonCiliumEgressGatewayCRDMissing,
		},
		{
			name:       "feature-disabled",
			objs:       []client.Object{ciliumConfig(map[string]string{"devices": "tailscale0"}), ciliumEgressGatewayCRD()},
			wantReason: routeacceptor.ReasonCiliumEgressGatewayDisabled,
		},
		{
			name:       "tailscale0-not-managed",
			objs:       []client.Object{ciliumConfig(map[string]string{"enable-egress-gateway": "true", "devices": "eth0"}), ciliumEgressGatewayCRD()},
			wantReason: routeacceptor.ReasonCiliumDevicesMissingTailscale0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tsc := &fakeTSClient{loginURL: testLoginURL}
			objs := append([]client.Object{
				newRouteAcceptor(tsapi.RouteAcceptorSpec{Cilium: &tsapi.RouteAcceptorCilium{EgressGateway: &tsapi.CiliumEgressGateway{}}}),
				newNode("node-a", nil),
			}, tt.objs...)
			r, cl := newTestReconciler(t, tsc, objs...)
			mustReconcile(t, r, raName)
			ra := getRouteAcceptor(t, cl)
			expectCondition(t, ra, tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionFalse, tt.wantReason)
			// The devices are still deployed: they are needed once the precondition is met.
			if !daemonSetExists(t, cl) {
				t.Error("DaemonSet missing")
			}
		})
	}
}

func TestReconcile_CiliumEgressGatewayNoRoutes(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	pol := &unstructured.Unstructured{}
	pol.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumEgressGatewayPolicy"})
	pol.SetName(dsName)
	pol.Object["spec"] = map[string]any{"destinationCIDRs": []any{"10.20.0.0/16"}}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{Cilium: &tsapi.RouteAcceptorCilium{EgressGateway: &tsapi.CiliumEgressGateway{}}}),
		newNode("node-a", nil),
		ciliumConfig(map[string]string{"enable-egress-gateway": "true", "devices": "eth0,tailscale0"}),
		ciliumEgressGatewayCRD(),
		// A stale policy from before the routes were withdrawn.
		pol,
		newStateSecret("node-a", map[string]string{kubetypes.KeyDeviceIPs: `["100.64.0.1"]`}),
	)
	mustReconcile(t, r, raName)
	expectCondition(t, getRouteAcceptor(t, cl), tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionTrue, routeacceptor.ReasonCiliumEgressGateway)
	if getEgressGatewayPolicy(t, cl) != nil {
		t.Error("policy without routes should have been deleted")
	}
}

func mustUpdateSecret(t *testing.T, cl client.Client, name string, data map[string]string) {
	t.Helper()
	s := getSecret(t, cl, name)
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	if err := cl.Update(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

func TestReconcile_CiliumManagedDevice(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{}),
		newNode("node-a", nil),
		// eBPF host routing, but Cilium manages tailscale0 and masquerades on it.
		ciliumConfig(map[string]string{
			"enable-bpf-masquerade":  "true",
			"kube-proxy-replacement": "true",
			"enable-ipv4-masquerade": "true",
			"devices":                "eth0,tailscale0",
		}),
	)
	mustReconcile(t, r, raName)
	if !daemonSetExists(t, cl) {
		t.Fatal("DaemonSet was not created")
	}
	expectCondition(t, getRouteAcceptor(t, cl), tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionTrue, routeacceptor.ReasonCiliumManagedDevice)

	// Enabling ip-masq-agent defeats the masquerading on tailscale0.
	cm := ciliumConfig(map[string]string{
		"enable-bpf-masquerade":  "true",
		"kube-proxy-replacement": "true",
		"enable-ip-masq-agent":   "true",
		"devices":                "eth0,tailscale0",
	})
	if err := cl.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r, raName)
	ra := getRouteAcceptor(t, cl)
	expectCondition(t, ra, tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionFalse, routeacceptor.ReasonCiliumIPMasqAgent)
	expectCondition(t, ra, tsapi.RouteAcceptorReady, metav1.ConditionFalse, routeacceptor.ReasonCiliumIPMasqAgent)
}

func TestReconcile_SourcesEnableEnforcement(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{
			Sources: []tsapi.RouteAcceptorSource{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}},
		}),
		newNode("node-a", nil, "10.244.0.0/24"),
	)
	mustReconcile(t, r, raName)
	ds := getDaemonSet(t, cl)
	var found bool
	for _, e := range ds.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "TS_EXPERIMENTAL_ROUTE_ACCEPTOR_SOURCES" && e.Value == "true" {
			found = true
		}
	}
	if !found {
		t.Errorf("TS_EXPERIMENTAL_ROUTE_ACCEPTOR_SOURCES=true missing from the DaemonSet env: %v", ds.Spec.Template.Spec.Containers[0].Env)
	}
	ra := getRouteAcceptor(t, cl)
	if !slices.Contains(ra.Status.ClusterCIDRs, "10.244.0.0/24") {
		t.Errorf("status.clusterCIDRs = %v, want the node's Pod CIDR", ra.Status.ClusterCIDRs)
	}

	// Without sources the env var is absent.
	ra.Spec.Sources = nil
	if err := cl.Update(context.Background(), ra); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r, raName)
	for _, e := range getDaemonSet(t, cl).Spec.Template.Spec.Containers[0].Env {
		if e.Name == "TS_EXPERIMENTAL_ROUTE_ACCEPTOR_SOURCES" {
			t.Errorf("TS_EXPERIMENTAL_ROUTE_ACCEPTOR_SOURCES still set without spec.sources")
		}
	}
}

func TestReconcile_SourcesNeedPodCIDRs(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{
			Sources: []tsapi.RouteAcceptorSource{{}},
		}),
		newNode("node-a", nil), // no Pod CIDR, as with IPAMs that do not record them on Nodes
	)
	mustReconcile(t, r, raName)
	if daemonSetExists(t, cl) {
		t.Error("DaemonSet created although the Pod CIDRs are unknown")
	}
	expectCondition(t, getRouteAcceptor(t, cl), tsapi.RouteAcceptorReady, metav1.ConditionFalse, routeacceptor.ReasonPodCIDRsUnknown)

	// spec.clusterCIDRs supplies them.
	ra := getRouteAcceptor(t, cl)
	ra.Spec.ClusterCIDRs = tsapi.Routes{"10.0.0.0/8"}
	if err := cl.Update(context.Background(), ra); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r, raName)
	if !daemonSetExists(t, cl) {
		t.Error("DaemonSet not created with spec.clusterCIDRs set")
	}
}

func TestReconcile_CiliumEgressGatewayFollowsSources(t *testing.T) {
	t.Parallel()
	tsc := &fakeTSClient{loginURL: testLoginURL}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: dsName, Namespace: tailscaleNamespace, Labels: reconciler.Labels("routeacceptor", raName, "")},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 1, NumberReady: 1},
	}
	r, cl := newTestReconciler(t, tsc,
		newRouteAcceptor(tsapi.RouteAcceptorSpec{
			Cilium: &tsapi.RouteAcceptorCilium{EgressGateway: &tsapi.CiliumEgressGateway{}},
			Sources: []tsapi.RouteAcceptorSource{
				{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
				{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "data"}}, Routes: tsapi.Routes{"10.20.0.0/16"}},
				// No accepted route within these: no policy.
				{Routes: tsapi.Routes{"192.168.0.0/16"}},
			},
		}),
		newNode("node-a", nil, "10.244.0.0/24"),
		ciliumConfig(map[string]string{
			"enable-bpf-masquerade":  "true",
			"kube-proxy-replacement": "true",
			"enable-egress-gateway":  "true",
			"devices":                "eth0,tailscale0",
		}),
		ciliumEgressGatewayCRD(),
		ds,
		newStateSecret("node-a", map[string]string{
			kubetypes.KeyDeviceID:       "dev-a",
			kubetypes.KeyDeviceIPs:      `["100.64.0.1"]`,
			kubetypes.KeyAcceptedRoutes: `["10.20.5.0/24", "10.30.0.0/16"]`,
		}),
	)
	mustReconcile(t, r, raName)
	expectCondition(t, getRouteAcceptor(t, cl), tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionTrue, routeacceptor.ReasonCiliumEgressGateway)

	if pol := getEgressGatewayPolicy(t, cl); pol != nil {
		t.Errorf("the unscoped policy %q exists although spec.sources is set", dsName)
	}
	web := getEgressGatewayPolicyNamed(t, cl, dsName+"-0")
	if web == nil {
		t.Fatal("policy for spec.sources[0] missing")
	}
	spec := web.Object["spec"].(map[string]any)
	if got, want := spec["selectors"], []any{map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}}}}; !reflect.DeepEqual(got, want) {
		t.Errorf("sources[0] selectors = %v, want %v", got, want)
	}
	if got, want := spec["destinationCIDRs"], []any{"10.20.5.0/24", "10.30.0.0/16"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sources[0] destinationCIDRs = %v, want every accepted route %v", got, want)
	}
	data := getEgressGatewayPolicyNamed(t, cl, dsName+"-1")
	if data == nil {
		t.Fatal("policy for spec.sources[1] missing")
	}
	spec = data.Object["spec"].(map[string]any)
	if got, want := spec["selectors"], []any{map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"team": "data"}}}}; !reflect.DeepEqual(got, want) {
		t.Errorf("sources[1] selectors = %v, want %v", got, want)
	}
	if got, want := spec["destinationCIDRs"], []any{"10.20.5.0/24"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sources[1] destinationCIDRs = %v, want the accepted routes within 10.20.0.0/16 %v", got, want)
	}
	if pol := getEgressGatewayPolicyNamed(t, cl, dsName+"-2"); pol != nil {
		t.Errorf("policy for spec.sources[2] exists although no accepted route falls within its routes")
	}

	// Dropping an entry deletes its policy.
	ra := getRouteAcceptor(t, cl)
	ra.Spec.Sources = ra.Spec.Sources[:1]
	if err := cl.Update(context.Background(), ra); err != nil {
		t.Fatal(err)
	}
	mustReconcile(t, r, raName)
	if pol := getEgressGatewayPolicyNamed(t, cl, dsName+"-1"); pol != nil {
		t.Errorf("policy for the removed spec.sources[1] still exists")
	}
	if pol := getEgressGatewayPolicyNamed(t, cl, dsName+"-0"); pol == nil {
		t.Errorf("policy for spec.sources[0] disappeared")
	}
}
