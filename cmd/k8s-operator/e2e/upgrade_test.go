// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/semver"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
	"tailscale.com/cmd/k8s-operator/e2e/internal/build"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
)

const (
	AnnotationProxyGroup        = "tailscale.com/proxy-group"
	AnnotationTailnetTargetIP   = "tailscale.com/tailnet-ip"
	AnnotationTailnetTargetFQDN = "tailscale.com/tailnet-fqdn"
	AnnotationExpose            = "tailscale.com/expose"
)

// testResource is one resource under test, with checks reusable before and after
// the version change. All func fields are optional (nil => skipped) except waitReady.
type testResource struct {
	name           string
	waitReady      func(t *testing.T)
	reconcileCheck func(t *testing.T) // asserts the operator reconciled the correct managed objects/config.
	trafficCheck   func(t *testing.T) // sends real traffic through the resource.
	objConds       func(t *testing.T) (conds []metav1.Condition, ok bool)
	// primaryCond is the Ready condition watched for flapping.
	primaryCond tsapi.ConditionType
	// secondaryConds are other conditions that must also be True.
	secondaryConds  []tsapi.ConditionType
	postChangeCheck func(t *testing.T)
}

// condProbe reads the resource's primary Ready condition, or ok=false
// if it can't be read yet (treated as "no observation", not a flip).
func (r testResource) condProbe(t *testing.T) (metav1.Condition, bool) {
	if r.objConds == nil || r.primaryCond == "" {
		return metav1.Condition{}, false
	}
	conds, ok := r.objConds(t)
	if !ok {
		return metav1.Condition{}, false
	}
	return findCond(conds, r.primaryCond)
}

// TestOperatorVersionChange provisions operator resources at --from-version, then
// changes the operator to --to-version, asserting requireStackHealthy afterwards
// on the same resources.
//
// With --round-trip (which requires --from older than --to) it then rolls back to
// --from-version, testing upgrade and downgrade.
//
// See [TestMain] for test requirements. Runs only when --from-version is set.
func TestOperatorVersionChange(t *testing.T) {
	if !upgradeMode() {
		t.Skip("TestOperatorVersionChange requires --from-version")
	}
	if tnClient == nil {
		t.Skip("TestOperatorVersionChange requires a working tailnet client")
	}
	ctx := t.Context()

	// Remove any worktrees leaked by a prior interrupted run.
	build.PruneWorktrees(ctx, repoRoot)
	fromDir, fromCleanup := refDir(t, ctx, *fFromVersion)
	defer fromCleanup()
	toDir, toCleanup := refDir(t, ctx, *fToVersion)
	defer toCleanup()

	fromVer, toVer := versionInWorktree(t, fromDir), versionInWorktree(t, toDir)
	if fromVer == toVer {
		t.Fatalf("--from-version and --to-version resolve to the same version (%s); nothing to change", fromVer)
	}
	verb := "upgrade"
	if semver.Compare(fromVer, toVer) > 0 {
		verb = "downgrade"
	}
	if *fRoundTrip && verb != "upgrade" {
		t.Fatalf("--round-trip requires --from-version (%s) older than --to-version (%s): it installs the baseline, upgrades to the candidate, then rolls back", fromVer, toVer)
	}

	crdAvailable, crdHasField := crdSupportForVersions(t, fromDir, toDir)

	start := time.Now()
	t.Logf("provisioning baseline operator %s from %s (builds and side-loads images; interleaved build and tsnet logs below are expected)", fromVer, fromDir)
	cleanup, err := provisionOperatorStack(ctx, e2eLogger, fromDir)
	if err != nil {
		t.Fatalf("provisioning operator at %q: %v", fromVer, err)
	}
	t.Cleanup(cleanup)
	t.Logf("baseline operator %s provisioned in %s", fromVer, time.Since(start).Round(time.Second))

	resources := createResources(t, crdAvailable, crdHasField)

	// Baseline: each resource runs as a subtest for per-resource pass/fail signal.
	t.Logf("waiting for resources to become ready at %s", fromVer)
	for _, r := range resources {
		t.Run("baseline/"+r.name, func(t *testing.T) { runResourceChecks(t, r, false) })
	}
	t.Logf("resources ready and serving traffic at %s", fromVer)

	hops := 1
	if *fRoundTrip {
		hops = 2
	}
	changeHopAndVerify(t, ctx, hop{n: 1, of: hops, verb: verb, fromVer: fromVer, toVer: toVer}, toDir, resources)

	if *fRoundTrip {
		changeHopAndVerify(t, ctx, hop{n: 2, of: hops, verb: "downgrade", fromVer: toVer, toVer: fromVer}, fromDir, resources)
	}
}

// hop describes one operator version change, for logging and subtest labels.
type hop struct {
	n, of          int
	verb           string // "upgrade" / "downgrade"
	fromVer, toVer string
}

// changeHopAndVerify changes the operator to the version built from dir, then
// asserts the stack stayed healthy. It snapshots the operator image + managed
// revisions before the change so requireStackHealthy can prove they updated.
func changeHopAndVerify(t *testing.T, ctx context.Context, h hop, dir string, resources []testResource) {
	fromOperatorImage := operatorDeploymentImage(t)
	preChange := managedStatefulSetRevisions(t)

	t.Logf("hop %d/%d [%s]: operator %s -> %s (%s)", h.n, h.of, h.verb, h.fromVer, h.toVer, dir)
	toTag, err := installOrUpgradeOperatorStack(ctx, e2eLogger, dir)
	if err != nil {
		t.Fatalf("hop %d/%d [%s]: changing operator to %s: %v", h.n, h.of, h.verb, h.toVer, err)
	}

	if toTag != "" {
		repointNameserverImage(t, ctx, toTag)
	}

	requireStackHealthy(t, h.verb, h.toVer, resources, fromOperatorImage, toTag, preChange)
}

// repointNameserverImage patches DNSConfig so the nameserver Deployment updates to
// the given image tag. requireNameserverUpdated asserts the update actually happened.
func repointNameserverImage(t *testing.T, ctx context.Context, tag string) {
	t.Helper()
	dc := &tsapi.DNSConfig{}
	if err := kubeClient.Get(ctx, client.ObjectKey{Name: "dns"}, dc); err != nil {
		t.Fatalf("getting DNSConfig to re-point nameserver image: %v", err)
	}
	dc.Spec.Nameserver = &tsapi.Nameserver{Image: nameserverImage(*fRegistry, tag)}
	if err := kubeClient.Update(ctx, dc); err != nil {
		t.Fatalf("re-pointing nameserver image to tag %q: %v", tag, err)
	}
	t.Logf("re-pointed nameserver image to tag %q", tag)
}

// versionInWorktree returns the operator version a worktree ships (from its
// VERSION.txt) as a semver string ("v1.105.0"), failing if it isn't valid semver.
func versionInWorktree(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "VERSION.txt")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	v := "v" + strings.TrimSpace(string(b))
	if !semver.IsValid(v) {
		t.Fatalf("%s is not valid semver: %q", path, v)
	}
	return v
}

func runResourceChecks(t *testing.T, r testResource, postChange bool) {
	r.waitReady(t)
	requireSecondaryConds(t, r)
	if r.reconcileCheck != nil {
		r.reconcileCheck(t)
	}
	if r.trafficCheck != nil {
		r.trafficCheck(t)
	}
	if postChange && r.postChangeCheck != nil {
		r.postChangeCheck(t)
	}
}

func refDir(t *testing.T, ctx context.Context, ref string) (string, func()) {
	t.Helper()
	if ref == "" || ref == "HEAD" {
		return repoRoot, func() {}
	}
	return worktreeForRef(t, ctx, ref)
}

// worktreeForRef materializes ref as a git worktree and returns its dir plus a
// cleanup func, failing the test on error.
func worktreeForRef(t *testing.T, ctx context.Context, ref string) (string, func()) {
	t.Helper()
	dir, cleanup, err := build.WorktreeForRef(ctx, repoRoot, ref)
	if err != nil {
		t.Fatalf("creating worktree for ref %q: %v", ref, err)
	}
	return dir, cleanup
}

// createResources provisions the test resources on the (already installed)
// from-version and returns them. IP-family-specific resources are gated on
// clusterIPv4Support/clusterIPv6Support.
//
// A resource whose CRD or required field is absent in either version is omitted
// rather than orphaned by the version change.
func createResources(t *testing.T, crdAvailable func(plural string) bool, crdHasField func(plural, field string) bool) []testResource {
	t.Helper()
	var resources []testResource

	egressTarget := startEgressTarget(t, tsClient)
	egressPG := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-eg")},
		Spec:       tsapi.ProxyGroupSpec{Type: tsapi.ProxyGroupTypeEgress, Replicas: new(int32(3))},
	}
	createAndCleanup(t, kubeClient, egressPG)
	resources = append(resources, proxyGroupResource("proxygroup-egress", egressPG.Name))

	if clusterIPv4Support {
		svc := egressService(generateName("up-eg-v4"), map[string]string{
			AnnotationTailnetTargetIP: egressTarget.ipv4,
			AnnotationProxyGroup:      egressPG.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		resources = append(resources, pgEgressServiceResource("egress-svc-v4", svc.Name))
	}

	if clusterIPv6Support {
		svc := egressService(generateName("up-eg-v6"), map[string]string{
			AnnotationTailnetTargetIP: egressTarget.ipv6,
			AnnotationProxyGroup:      egressPG.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		resources = append(resources, pgEgressServiceResource("egress-svc-v6", svc.Name))
	}

	if clusterIPv6Support {
		via := setup4via6Backend(t)
		viaPC := applyAcceptRoutesProxyClass(t)
		viaPG := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{Name: generateName("up-v6eg")},
			Spec:       tsapi.ProxyGroupSpec{Type: tsapi.ProxyGroupTypeEgress, ProxyClass: viaPC.Name},
		}
		createAndCleanup(t, kubeClient, viaPG)
		resources = append(resources, proxyGroupResource("proxygroup-egress-4via6", viaPG.Name))

		viaSvc := egressService(generateName("up-v6eg-svc"), map[string]string{
			AnnotationTailnetTargetIP: via.viaIP,
			AnnotationProxyGroup:      viaPG.Name,
		})
		createAndCleanup(t, kubeClient, viaSvc)
		resources = append(resources, pgEgressServiceResource("egress-4via6", viaSvc.Name))
	}

	singletonEgress := egressService(generateName("up-eg-sgl"), map[string]string{
		AnnotationTailnetTargetFQDN: egressTarget.fqdn,
	})
	createAndCleanup(t, kubeClient, singletonEgress)
	resources = append(resources, testResource{
		name:         "egress-singleton",
		waitReady:    func(t *testing.T) { waitForEgress(t, singletonEgress.Name, tsoperator.SvcIsReady) },
		trafficCheck: func(t *testing.T) { requireTargetIsReachable(t, egressURL(singletonEgress.Name)) },
		objConds:     serviceObjConds(singletonEgress.Name),
		primaryCond:  tsapi.ProxyReady,
	})

	const subnetRoute = "10.40.0.0/14"
	subnetCn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-subnet")},
		Spec: tsapi.ConnectorSpec{
			SubnetRouter: &tsapi.SubnetRouter{AdvertiseRoutes: []tsapi.Route{subnetRoute}},
			ProxyClass:   "default",
		},
	}
	createAndCleanup(t, kubeClient, subnetCn)
	resources = append(resources, connectorResource("connector-subnet-router", subnetCn.Name))

	exitCn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-exit")},
		Spec:       tsapi.ConnectorSpec{ExitNode: true, ProxyClass: "default"},
	}
	createAndCleanup(t, kubeClient, exitCn)
	resources = append(resources, connectorResource("connector-exit-node", exitCn.Name))

	const appConnectorRoute = "10.50.0.0/16"
	appCn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-appc")},
		Spec: tsapi.ConnectorSpec{
			AppConnector: &tsapi.AppConnector{Routes: []tsapi.Route{appConnectorRoute}},
			ProxyClass:   "default",
		},
	}
	createAndCleanup(t, kubeClient, appCn)
	resources = append(resources, connectorResource("connector-app-connector", appCn.Name))

	switch {
	case secondTNClient == nil:
		t.Log("resources: omitting multi-tailnet Connector (no second tailnet; needs --devcontrol)")
	case !crdAvailable("tailnets"):
		t.Log("resources: omitting multi-tailnet Connector (tailnets CRD not in all versions)")
	default:
		createAndCleanup(t, kubeClient, secondTailnetCredentialsSecret())
		createAndCleanup(t, kubeClient, secondTailnetCR())
		const secondTailnetRoute = "10.60.0.0/16"
		multiTNCn := &tsapi.Connector{
			ObjectMeta: metav1.ObjectMeta{Name: generateName("up-mtn")},
			Spec: tsapi.ConnectorSpec{
				Tailnet:      "second-tailnet",
				SubnetRouter: &tsapi.SubnetRouter{AdvertiseRoutes: []tsapi.Route{secondTailnetRoute}},
				ProxyClass:   "default",
			},
		}
		createAndCleanup(t, kubeClient, multiTNCn)
		r := connectorResource("connector-multi-tailnet", multiTNCn.Name)
		r.reconcileCheck = func(t *testing.T) {
			if err := verifyConnectorTailnet(t, multiTNCn, secondTNClient); err != nil {
				t.Fatalf("multi-tailnet Connector %s not on the second tailnet: %v", multiTNCn.Name, err)
			}
		}
		resources = append(resources, r)
	}

	switch {
	case !crdAvailable("peerrelays"):
		t.Log("resources: omitting PeerRelay (peerrelays CRD not in both versions)")
	case !crdHasField("peerrelays", "staticEndpoints"):
		t.Log("resources: omitting PeerRelay (both versions' CRD need spec.staticEndpoints)")
	default:
		const peerRelayPort uint16 = 6969
		endpoint := fmt.Sprintf("203.0.113.10:%d", peerRelayPort)
		wantEndpoints := []netip.AddrPort{netip.MustParseAddrPort(endpoint)}
		pr := &tsapi.PeerRelay{
			ObjectMeta: metav1.ObjectMeta{Name: generateName("up-pr")},
			Spec: tsapi.PeerRelaySpec{
				ProxyClass:      "default",
				Service:         &tsapi.PeerRelayService{Port: new(peerRelayPort)},
				StaticEndpoints: []string{endpoint},
			},
		}
		createAndCleanup(t, kubeClient, pr)
		resources = append(resources, testResource{
			name:      "peerrelay",
			waitReady: func(t *testing.T) { waitForPeerRelayReady(t, pr.Name) },
			reconcileCheck: func(t *testing.T) {
				verifyPeerRelayStatusEndpoints(t, pr.Name, 1, wantEndpoints)
				verifyPeerRelayReplica(t, pr.Name, 0, peerRelayPort, wantEndpoints)
			},
			objConds:    peerRelayObjConds(pr.Name),
			primaryCond: tsapi.PeerRelayReady,
		})
	}

	customPC := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-pc")},
		Spec: tsapi.ProxyClassSpec{
			UseLetsEncryptStagingEnvironment: !*fDevcontrol,
			Metrics:                          &tsapi.Metrics{Enable: true},
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
						Env:             customProxyClassEnv(),
					},
				},
			},
		},
	}
	createAndCleanup(t, kubeClient, customPC)
	resources = append(resources, testResource{
		name:        "proxyclass-custom",
		waitReady:   func(t *testing.T) { waitForProxyClassReady(t, customPC.Name) },
		objConds:    proxyClassObjConds(customPC.Name),
		primaryCond: tsapi.ProxyClassReady,
	})

	// An egress ProxyGroup bound to the custom ProxyClass above: the other
	// ProxyGroups use the default config, so this is the only member that proves
	// the version change preserves user-defined StatefulSet/Pod overrides (metrics,
	// env, image-pull policy), which the operator re-applies when it rolls managed
	// workloads.
	customPGEgress := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-eg-pc")},
		Spec:       tsapi.ProxyGroupSpec{Type: tsapi.ProxyGroupTypeEgress, ProxyClass: customPC.Name},
	}
	createAndCleanup(t, kubeClient, customPGEgress)
	resources = append(resources, proxyGroupResource("proxygroup-egress-customproxyclass", customPGEgress.Name))

	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)
	ingressPG := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-ing")},
		Spec:       tsapi.ProxyGroupSpec{Type: tsapi.ProxyGroupTypeIngress},
	}
	createAndCleanup(t, kubeClient, ingressPG)
	resources = append(resources, proxyGroupResource("proxygroup-ingress", ingressPG.Name))

	backend := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-nginx"), Namespace: ns},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app.kubernetes.io/name": nginx.Name},
			Ports:    []corev1.ServicePort{{Name: "http", Port: 80}},
		},
	}
	createAndCleanup(t, kubeClient, backend)
	haIngress := l7Ingress(ns, backend.Name, map[string]string{AnnotationProxyGroup: ingressPG.Name})
	createAndCleanup(t, kubeClient, haIngress)
	resources = append(resources, testResource{
		name: "ingress-l7-ha",
		waitReady: func(t *testing.T) {
			hostname, err := waitForIngressHostname(t, ns, haIngress.Name)
			if err != nil {
				t.Fatalf("waiting for Ingress %s hostname: %v", haIngress.Name, err)
			}
			if err := testIngressIsReachable(t, newHTTPClient(tnClient), fmt.Sprintf("https://%s:443", hostname)); err != nil {
				t.Fatalf("Ingress %s not reachable: %v", haIngress.Name, err)
			}
		},
	})

	singletonIngress := l7Ingress(ns, backend.Name, nil)
	createAndCleanup(t, kubeClient, singletonIngress)
	resources = append(resources, testResource{
		name: "ingress-l7-singleton",
		waitReady: func(t *testing.T) {
			hostname, err := waitForIngressHostname(t, ns, singletonIngress.Name)
			if err != nil {
				t.Fatalf("waiting for Ingress %s hostname: %v", singletonIngress.Name, err)
			}
			if err := testIngressIsReachable(t, newHTTPClient(tnClient), fmt.Sprintf("https://%s:443", hostname)); err != nil {
				t.Fatalf("Ingress %s not reachable: %v", singletonIngress.Name, err)
			}
		},
	})

	dnsIngress := l7Ingress(ns, backend.Name, map[string]string{
		"tailscale.com/experimental-forward-cluster-traffic-via-ingress": "true",
	})
	createAndCleanup(t, kubeClient, dnsIngress)
	resources = append(resources, testResource{
		name:      "dnsconfig/dns",
		waitReady: func(t *testing.T) { waitForDNSConfigReady(t, "dns") },
		trafficCheck: func(t *testing.T) {
			hostname, err := waitForIngressHostname(t, ns, dnsIngress.Name)
			if err != nil {
				t.Fatalf("waiting for DNS-probe Ingress %s hostname: %v", dnsIngress.Name, err)
			}
			requireTargetIsReachable(t, fmt.Sprintf("https://%s:443", hostname))
		},
		objConds:    dnsConfigObjConds("dns"),
		primaryCond: tsapi.NameserverReady,
	})

	l3Family := clusterPrimaryFamily
	l3Singleton := l3ExposeService(generateName("up-l3"), nginx.Name, l3Family)
	createAndCleanup(t, kubeClient, l3Singleton)
	resources = append(resources, testResource{
		name:         "ingress-l3-singleton",
		waitReady:    func(t *testing.T) { waitForEgress(t, l3Singleton.Name, tsoperator.SvcIsReady) },
		trafficCheck: func(t *testing.T) { requireL3ProxyReachable(t, l3Singleton.Name) },
		objConds:     serviceObjConds(l3Singleton.Name),
		primaryCond:  tsapi.ProxyReady,
	})

	l3HAPG := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-l3ha")},
		Spec:       tsapi.ProxyGroupSpec{Type: tsapi.ProxyGroupTypeIngress},
	}
	createAndCleanup(t, kubeClient, l3HAPG)
	resources = append(resources, proxyGroupResource("proxygroup-ingress-l3ha", l3HAPG.Name))

	l3HASvc := l3LoadBalancerService(generateName("up-l3ha-svc"), nginx.Name, l3HAPG.Name, l3Family)
	createAndCleanup(t, kubeClient, l3HASvc)
	resources = append(resources, testResource{
		name:        "ingress-l3-ha",
		waitReady:   func(t *testing.T) { waitForL3HAIngressReady(t, l3HASvc.Name) },
		objConds:    serviceObjConds(l3HASvc.Name),
		primaryCond: tsapi.IngressSvcConfigured,
	})

	apiPCName := applyProxyGroupProxyClass(t)
	apiRoleName := generateName("up-api-crud")
	createAndCleanup(t, kubeClient, &rbacv1.Role{
		ObjectMeta: objectMeta(ns, apiRoleName),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Verbs:     []string{"get", "list", "create", "update", "delete"},
			Resources: []string{"configmaps"},
		}},
	})
	createAndCleanup(t, kubeClient, &rbacv1.RoleBinding{
		ObjectMeta: objectMeta(ns, apiRoleName),
		Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "ts:e2e-test-proxy"}},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: apiRoleName},
	})
	apiPG := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("up-api")},
		Spec: tsapi.ProxyGroupSpec{
			Type:          tsapi.ProxyGroupTypeKubernetesAPIServer,
			ProxyClass:    apiPCName,
			KubeAPIServer: &tsapi.KubeAPIServerConfig{Mode: new(tsapi.APIServerProxyModeAuth)},
		},
	}
	createAndCleanup(t, kubeClient, apiPG)
	apiResource := proxyGroupResource("proxygroup-kube-apiserver", apiPG.Name,
		tsapi.KubeAPIServerProxyConfigured, tsapi.KubeAPIServerProxyValid)
	apiResource.trafficCheck = func(t *testing.T) {
		proxyURL := waitForKubeAPIServerProxyReady(t, apiPG.Name)
		proxyCl, err := apiServerProxyClient(proxyURL)
		if err != nil {
			t.Fatalf("creating API server proxy client for %s: %v", apiPG.Name, err)
		}
		runAPIServerProxyCRUD(t, proxyCl)
	}
	resources = append(resources, apiResource)

	// TODO(beckypauley): consider a ProxyGroupPolicy test resource.

	return resources
}

func proxyGroupResource(label, pgName string, extra ...tsapi.ConditionType) testResource {
	return testResource{
		name:           label,
		waitReady:      func(t *testing.T) { waitForProxyGroupReady(t, pgName) },
		objConds:       proxyGroupObjConds(pgName),
		primaryCond:    tsapi.ProxyGroupReady,
		secondaryConds: append([]tsapi.ConditionType{tsapi.ProxyGroupAvailable}, extra...),
	}
}

func pgEgressServiceResource(label, svcName string) testResource {
	return testResource{
		name:           label,
		waitReady:      func(t *testing.T) { waitForEgress(t, svcName, pgEgressReady) },
		reconcileCheck: func(t *testing.T) { requireEgressEndpointSlicesHealthy(t, svcName) },
		trafficCheck:   func(t *testing.T) { requireTargetIsReachable(t, egressURL(svcName)) },
		objConds:       serviceObjConds(svcName),
		primaryCond:    tsapi.EgressSvcReady,
		secondaryConds: []tsapi.ConditionType{tsapi.EgressSvcConfigured, tsapi.EgressSvcValid},
	}
}

func connectorResource(label, name string) testResource {
	return testResource{
		name:        label,
		waitReady:   func(t *testing.T) { waitForConnectorReady(t, name) },
		objConds:    connectorObjConds(name),
		primaryCond: tsapi.ConnectorReady,
	}
}

func customProxyClassEnv() []tsapi.Env {
	env := []tsapi.Env{{Name: "TS_DEBUG_UPGRADE_E2E", Value: "1"}}
	if *fDevcontrol {
		env = append(env, tsapi.Env{Name: "TS_DEBUG_ACME_DIRECTORY_URL", Value: "https://pebble:14000/dir"})
	}
	return env
}

// l3ExposeService returns a single-family Service exposing nginx via a singleton
// L3 ingress proxy (tailscale.com/expose).
func l3ExposeService(name, nginxName string, family corev1.IPFamily) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: map[string]string{AnnotationExpose: "true"},
		},
		Spec: corev1.ServiceSpec{
			IPFamilyPolicy: new(corev1.IPFamilyPolicySingleStack),
			IPFamilies:     []corev1.IPFamily{family},
			Selector:       map[string]string{"app.kubernetes.io/name": nginxName},
			Ports:          []corev1.ServicePort{{Name: "http", Protocol: "TCP", Port: 80}},
		},
	}
}

// l3LoadBalancerService returns a single-family LoadBalancer Service (class
// "tailscale") exposing nginx via a ProxyGroup-backed L3 ingress.
func l3LoadBalancerService(name, nginxName, pgName string, family corev1.IPFamily) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: map[string]string{AnnotationProxyGroup: pgName},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: new("tailscale"),
			IPFamilyPolicy:    new(corev1.IPFamilyPolicySingleStack),
			IPFamilies:        []corev1.IPFamily{family},
			Selector:          map[string]string{"app.kubernetes.io/name": nginxName},
			Ports:             []corev1.ServicePort{{Name: "http", Protocol: "TCP", Port: 80}},
		},
	}
}

func waitForDNSConfigReady(t *testing.T, name string) {
	t.Helper()
	if err := tstest.WaitFor(3*time.Minute, func() error {
		dc := &tsapi.DNSConfig{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, dc); err != nil {
			return err
		}
		if !tsoperator.DNSCfgIsReady(dc) {
			return fmt.Errorf("DNSConfig %s not ready yet", name)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for DNSConfig %s to become ready: %v", name, err)
	}
}

// crdSupportForVersions compares the CRDs shipped by each version's worktree and
// returns two helpers for asking what they have in common. createResources uses
// them to skip any resource whose CRD or field is missing from one version (e.g.
// a downgrade target that predates a field):
//   - crdAvailable(plural) reports whether every version ships that CRD.
//   - crdHasField(plural, field) reports whether every version's CRD has spec.<field>.
func crdSupportForVersions(t *testing.T, dirs ...string) (crdAvailable func(string) bool, crdHasField func(string, string) bool) {
	t.Helper()
	sets := make([]map[string]bool, len(dirs))
	for i, dir := range dirs {
		sets[i] = crdsInWorktree(t, dir)
	}
	crdAvailable = func(plural string) bool {
		for _, s := range sets {
			if !s[plural] {
				return false
			}
		}
		return true
	}
	crdHasField = func(plural, field string) bool {
		for _, dir := range dirs {
			if !crdSpecHasField(t, dir, plural, field) {
				return false
			}
		}
		return true
	}
	return crdAvailable, crdHasField
}

// crdsInWorktree returns the set of CRD plurals the chart at dir ships, taken
// from the deploy/crds/tailscale.com_<plural>.yaml filenames.
func crdsInWorktree(t *testing.T, dir string) map[string]bool {
	t.Helper()
	crdDir := filepath.Join(dir, "cmd", "k8s-operator", "deploy", "crds")
	entries, err := os.ReadDir(crdDir)
	if err != nil {
		t.Fatalf("reading CRD dir %s: %v", crdDir, err)
	}
	out := make(map[string]bool)
	for _, e := range entries {
		name := e.Name()
		const prefix, suffix = "tailscale.com_", ".yaml"
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			out[strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)] = true
		}
	}
	if len(out) == 0 {
		t.Fatalf("no tailscale.com CRDs found in %s", crdDir)
	}
	return out
}

// crdSpecHasField reports whether the given resource's CRD (in dir) has the
// field spec.<field>.
func crdSpecHasField(t *testing.T, dir, plural, field string) bool {
	t.Helper()
	path := filepath.Join(dir, "cmd", "k8s-operator", "deploy", "crds", "tailscale.com_"+plural+".yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		t.Fatalf("reading CRD %s: %v", path, err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(b, &crd); err != nil {
		t.Fatalf("parsing CRD %s: %v", path, err)
	}
	for _, v := range crd.Spec.Versions {
		if v.Schema == nil || v.Schema.OpenAPIV3Schema == nil {
			continue
		}
		spec, ok := v.Schema.OpenAPIV3Schema.Properties["spec"]
		if !ok {
			continue
		}
		if _, ok := spec.Properties[field]; ok {
			return true
		}
	}
	return false
}

func proxyGroupObjConds(name string) func(*testing.T) ([]metav1.Condition, bool) {
	return func(t *testing.T) ([]metav1.Condition, bool) {
		pg := &tsapi.ProxyGroup{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, pg); err != nil {
			return nil, false
		}
		return pg.Status.Conditions, true
	}
}

func connectorObjConds(name string) func(*testing.T) ([]metav1.Condition, bool) {
	return func(t *testing.T) ([]metav1.Condition, bool) {
		cn := &tsapi.Connector{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, cn); err != nil {
			return nil, false
		}
		return cn.Status.Conditions, true
	}
}

func peerRelayObjConds(name string) func(*testing.T) ([]metav1.Condition, bool) {
	return func(t *testing.T) ([]metav1.Condition, bool) {
		pr := &tsapi.PeerRelay{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, pr); err != nil {
			return nil, false
		}
		return pr.Status.Conditions, true
	}
}

func proxyClassObjConds(name string) func(*testing.T) ([]metav1.Condition, bool) {
	return func(t *testing.T) ([]metav1.Condition, bool) {
		pc := &tsapi.ProxyClass{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, pc); err != nil {
			return nil, false
		}
		return pc.Status.Conditions, true
	}
}

func dnsConfigObjConds(name string) func(*testing.T) ([]metav1.Condition, bool) {
	return func(t *testing.T) ([]metav1.Condition, bool) {
		dc := &tsapi.DNSConfig{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: name}, dc); err != nil {
			return nil, false
		}
		return dc.Status.Conditions, true
	}
}

func serviceObjConds(name string) func(*testing.T) ([]metav1.Condition, bool) {
	return func(t *testing.T) ([]metav1.Condition, bool) {
		svc := &corev1.Service{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Namespace: ns, Name: name}, svc); err != nil {
			return nil, false
		}
		return svc.Status.Conditions, true
	}
}

// requireSecondaryConds asserts every r.secondaryConds condition is present and
// True, retrying until they settle.
func requireSecondaryConds(t *testing.T, r testResource) {
	t.Helper()
	if len(r.secondaryConds) == 0 || r.objConds == nil {
		return
	}
	if err := tstest.WaitFor(3*time.Minute, func() error {
		conds, ok := r.objConds(t)
		if !ok {
			return fmt.Errorf("%s: conditions not readable yet", r.name)
		}
		for _, w := range r.secondaryConds {
			c, ok := findCond(conds, w)
			if !ok {
				return fmt.Errorf("%s: condition %s not set yet", r.name, w)
			}
			if c.Status != metav1.ConditionTrue {
				return fmt.Errorf("%s: condition %s is %s (reason=%s)", r.name, w, c.Status, c.Reason)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("secondary conditions not healthy: %v", err)
	}
}

func findCond(conds []metav1.Condition, ct tsapi.ConditionType) (metav1.Condition, bool) {
	c := meta.FindStatusCondition(conds, string(ct))
	if c == nil {
		return metav1.Condition{}, false
	}
	return *c, true
}

// requireEgressEndpointSlicesHealthy asserts that the managed EndpointSlices for
// a ProxyGroup egress Service match the operator-managed ClusterIP Service's IP
// families exactly.
func requireEgressEndpointSlicesHealthy(t *testing.T, egressSvcName string) {
	t.Helper()
	ctx := t.Context()
	extSvc := &corev1.Service{}
	if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: egressSvcName}, extSvc); err != nil {
		t.Fatalf("getting egress Service %s: %v", egressSvcName, err)
	}
	if extSvc.Annotations[AnnotationProxyGroup] == "" {
		return // singleton egress.
	}

	parent := client.MatchingLabels{
		kubetypes.LabelManaged: "true",
		LabelParentType:        "svc",
		LabelParentName:        egressSvcName,
	}
	familyAddrType := map[corev1.IPFamily]discoveryv1.AddressType{
		corev1.IPv4Protocol: discoveryv1.AddressTypeIPv4,
		corev1.IPv6Protocol: discoveryv1.AddressTypeIPv6,
	}
	if err := tstest.WaitFor(2*time.Minute, func() error {
		var clusterSvcs corev1.ServiceList
		if err := kubeClient.List(ctx, &clusterSvcs, client.InNamespace(tsNamespace), parent); err != nil {
			return err
		}
		switch len(clusterSvcs.Items) {
		case 0:
			return fmt.Errorf("no managed ClusterIP Service for egress Service %s yet", egressSvcName)
		case 1: // expected
		default:
			return fmt.Errorf("egress Service %s has %d managed ClusterIP Services, want 1", egressSvcName, len(clusterSvcs.Items))
		}
		var slices discoveryv1.EndpointSliceList
		if err := kubeClient.List(ctx, &slices, client.InNamespace(tsNamespace), parent); err != nil {
			return err
		}
		if len(slices.Items) == 0 {
			return fmt.Errorf("no managed EndpointSlices for egress Service %s yet", egressSvcName)
		}

		// The managed EndpointSlices must cover exactly the ClusterIP Service's IP
		// families: an unexpected family is an orphaned/blackhole slice, a missing
		// one means no endpoints were programmed for it.
		want := map[discoveryv1.AddressType]bool{}
		for _, f := range clusterSvcs.Items[0].Spec.IPFamilies {
			want[familyAddrType[f]] = true
		}
		got := map[discoveryv1.AddressType]bool{}
		for _, s := range slices.Items {
			got[s.AddressType] = true
			if !want[s.AddressType] {
				return fmt.Errorf("EndpointSlice %s has AddressType %s but egress Service %s has no such family (orphaned/stale slice)", s.Name, s.AddressType, egressSvcName)
			}
			if len(s.Endpoints) == 0 {
				return fmt.Errorf("EndpointSlice %s (%s) for %s has no endpoints", s.Name, s.AddressType, egressSvcName)
			}
			for _, ep := range s.Endpoints {
				if len(ep.Addresses) == 0 {
					return fmt.Errorf("EndpointSlice %s (%s) has an endpoint with no addresses", s.Name, s.AddressType)
				}
			}
		}
		for at := range want {
			if !got[at] {
				return fmt.Errorf("egress Service %s has family for %s but no managed EndpointSlice of that type", egressSvcName, at)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("egress EndpointSlices for %s not healthy: %v", egressSvcName, err)
	}
}

// requireNoFlapDuringSettle guards against a resource that converges but then
// won't stay settled: it requires every Ready condition to hold steady and pod
// restarts to stop climbing for a sustained quiet window. It runs after the
// blocking readiness waits, so it starts from a converged state and does not see
// the update's own churn. The poll loop is hand-rolled because the signal is
// "quiet for a stretch", not "true once".
func requireNoFlapDuringSettle(t *testing.T, resources []testResource) {
	t.Helper()
	const window = 5 * time.Minute    // max time to allow the stack to converge.
	const quietFor = 30 * time.Second // required stretch of no change.
	const tick = 3 * time.Second

	type probeState struct {
		lastTransition metav1.Time
		transitions    int
	}
	states := make(map[string]*probeState)
	for _, r := range resources {
		if r.primaryCond != "" {
			states[r.name] = &probeState{}
		}
	}
	lastRestarts := managedPodRestarts(t)

	lastChange := time.Now()
	deadline := time.Now().Add(window)
	for {
		time.Sleep(tick)

		for _, r := range resources {
			c, ok := r.condProbe(t)
			if !ok {
				continue
			}
			st := states[r.name]
			if st.lastTransition.IsZero() {
				st.lastTransition = c.LastTransitionTime
				continue
			}
			if c.LastTransitionTime.After(st.lastTransition.Time) {
				st.transitions++
				st.lastTransition = c.LastTransitionTime
				lastChange = time.Now()
				t.Logf("settle: %s Ready transitioned to %s (reason=%s)", r.name, c.Status, c.Reason)
			}
		}

		cur := managedPodRestarts(t)
		for key, after := range cur {
			if after > valueOr(lastRestarts, key, 0) {
				lastChange = time.Now()
				t.Logf("settle: managed Pod container %s restarted (now %d)", key, after)
			}
		}
		lastRestarts = cur

		if time.Since(lastChange) >= quietFor {
			// Quiet is necessary but not sufficient: a resource that regressed to a
			// stable non-True (no flapping, no restarts) also produces silence, so
			// report any primary or secondary condition that is readable and not True
			// (e.g. ProxyGroupAvailable False while Ready stays True).
			var bad []string
			for _, r := range resources {
				if c, ok := r.condProbe(t); ok && c.Status != metav1.ConditionTrue {
					bad = append(bad, fmt.Sprintf("%s: Ready=%s (reason=%s)", r.name, c.Status, c.Reason))
				}
				if r.objConds != nil && len(r.secondaryConds) > 0 {
					if conds, ok := r.objConds(t); ok {
						for _, want := range r.secondaryConds {
							if c, ok := findCond(conds, want); ok && c.Status != metav1.ConditionTrue {
								bad = append(bad, fmt.Sprintf("%s: %s=%s (reason=%s)", r.name, want, c.Status, c.Reason))
							}
						}
					}
				}
			}
			if len(bad) > 0 {
				failAll(t, "stack went quiet but a member is not Ready", bad)
			}
			t.Logf("stack converged: no transitions or Pod restarts for %s, all resources Ready", quietFor)
			return
		}
		if time.Now().After(deadline) {
			// A member fails if its Ready condition is readable and not True, or if
			// it transitioned more than twice (a healthy single update is <=2:
			// True->False->True).
			var problems []string
			for _, r := range resources {
				if r.primaryCond == "" {
					continue
				}
				c, ok := r.condProbe(t)
				transitions := states[r.name].transitions
				if ok && c.Status != metav1.ConditionTrue {
					problems = append(problems, fmt.Sprintf("%s: Ready=%s (reason=%s) and still churning (%d transitions)", r.name, c.Status, c.Reason, transitions))
				} else if transitions > 2 {
					problems = append(problems, fmt.Sprintf("%s: Ready condition transitioned %d times and did not settle", r.name, transitions))
				}
			}
			if len(problems) == 0 {
				problems = append(problems, fmt.Sprintf("stack did not go quiet for %s within %s (last change %s ago)", quietFor, window, time.Since(lastChange).Round(time.Second)))
			}
			failAll(t, "stack did not converge", problems)
		}
	}
}

// failAll reports each problem under a shared prefix and fails the test.
func failAll(t *testing.T, prefix string, problems []string) {
	t.Helper()
	for _, p := range problems {
		t.Errorf("%s: %s", prefix, p)
	}
	t.FailNow()
}

func valueOr(m map[string]int32, k string, def int32) int32 {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

// managedPodRestarts returns container restart counts keyed by "<pod>/<container>"
// for all operator-managed Pods.
func managedPodRestarts(t *testing.T) map[string]int32 {
	t.Helper()
	var pods corev1.PodList
	if err := kubeClient.List(t.Context(), &pods,
		client.InNamespace(tsNamespace),
		client.MatchingLabels{kubetypes.LabelManaged: "true"},
	); err != nil {
		t.Fatalf("listing managed Pods: %v", err)
	}
	out := make(map[string]int32)
	for _, p := range pods.Items {
		for _, cs := range p.Status.ContainerStatuses {
			out[p.Name+"/"+cs.Name] = cs.RestartCount
		}
	}
	return out
}

func operatorDeploymentImage(t *testing.T) string {
	t.Helper()
	d := &appsv1.Deployment{}
	if err := kubeClient.Get(t.Context(), client.ObjectKey{Namespace: tsNamespace, Name: "operator"}, d); err != nil {
		t.Fatalf("getting operator Deployment: %v", err)
	}
	if len(d.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("operator Deployment has no containers")
	}
	return d.Spec.Template.Spec.Containers[0].Image
}

// requireStackHealthy validates, after the version change, that the operator and
// every managed workload updated to the to-version image, every CR is Ready, no
// managed Pod is degraded, traffic still flows, and nothing flaps.
//
// preChange maps managed StatefulSet name -> its updateRevision before the change,
// feeding the freshness check. targetVer labels the post-change subtests
// "<verb>-to-<targetVer>/<resource>".
func requireStackHealthy(t *testing.T, verb, targetVer string, resources []testResource, fromOperatorImage, toTag string, preChange map[string]string) {
	t.Helper()

	if got := operatorDeploymentImage(t); got == fromOperatorImage {
		t.Errorf("operator image did not change across %s (still %q); it may not have applied", verb, got)
	} else {
		t.Logf("operator updated %q -> %q", fromOperatorImage, got)
	}

	// The revision-changed + image-tag checks prove we're observing post-change
	// state, not a steady state the new operator never touched.
	requireManagedWorkloadsUpdated(t, toTag, preChange)

	if toTag != "" {
		requireNameserverUpdated(t, toTag)
	}

	label := verb + "-to-" + targetVer
	for _, r := range resources {
		t.Run(label+"/"+r.name, func(t *testing.T) { runResourceChecks(t, r, true) })
	}

	requireNoDegradedManagedPods(t)
	requireNoFlapDuringSettle(t, resources)

	t.Logf("stack healthy after %s to %s: CRs ready, workloads updated, traffic flowing, no flap", verb, targetVer)
}

func managedStatefulSetRevisions(t *testing.T) map[string]string {
	t.Helper()
	var stsList appsv1.StatefulSetList
	if err := kubeClient.List(t.Context(), &stsList,
		client.InNamespace(tsNamespace),
		client.MatchingLabels{kubetypes.LabelManaged: "true"},
	); err != nil {
		t.Fatalf("listing managed StatefulSets: %v", err)
	}
	revs := make(map[string]string, len(stsList.Items))
	for _, sts := range stsList.Items {
		revs[sts.Name] = sts.Status.UpdateRevision
	}
	return revs
}

// updateTimeout bounds how long a managed StatefulSet may take to update to the
// new revision; exceeding it is a stuck/slow-update regression this test catches.
const updateTimeout = 5 * time.Minute

// requireManagedWorkloadsUpdated waits until every managed StatefulSet has updated
// to a new revision (vs preRevisions) carrying the to-version image and is ready.
// toTag "" (nothing built) skips the image-tag check but keeps the revision check.
func requireManagedWorkloadsUpdated(t *testing.T, toTag string, preRevisions map[string]string) {
	t.Helper()
	start := time.Now()
	loggedDone := -1 // last reported count, so we log progress only as it climbs.
	if err := tstest.WaitFor(updateTimeout, func() error {
		var stsList appsv1.StatefulSetList
		if err := kubeClient.List(t.Context(), &stsList,
			client.InNamespace(tsNamespace),
			client.MatchingLabels{kubetypes.LabelManaged: "true"},
		); err != nil {
			return err
		}
		if len(stsList.Items) == 0 {
			return fmt.Errorf("no managed StatefulSets found yet")
		}
		var firstErr error
		done := 0
		for _, sts := range stsList.Items {
			if err := managedStatefulSetUpdated(&sts, toTag, preRevisions); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			done++
		}
		if done != loggedDone {
			t.Logf("managed workloads updated: %d/%d (%s elapsed)", done, len(stsList.Items), time.Since(start).Round(time.Second))
			loggedDone = done
		}
		return firstErr
	}); err != nil {
		t.Fatalf("waiting for managed workloads to update to the new revision within %s: %v", updateTimeout, err)
	}
	t.Logf("all managed workloads updated to the new revision in %s", time.Since(start).Round(time.Second))
}

// managedStatefulSetUpdated reports whether a managed StatefulSet has rolled to a
// new revision (vs preRevisions) carrying the to-version image and is ready,
// returning the first unmet condition as an error otherwise. toTag "" skips the
// image-tag check but keeps the revision check.
func managedStatefulSetUpdated(sts *appsv1.StatefulSet, toTag string, preRevisions map[string]string) error {
	want := int32(1)
	if sts.Spec.Replicas != nil {
		want = *sts.Spec.Replicas
	}
	s := sts.Status
	if s.ObservedGeneration != sts.Generation {
		return fmt.Errorf("STS %s: observedGeneration %d != generation %d", sts.Name, s.ObservedGeneration, sts.Generation)
	}
	if s.UpdateRevision != "" && s.CurrentRevision != s.UpdateRevision {
		return fmt.Errorf("STS %s: still rolling (currentRevision %q != updateRevision %q)", sts.Name, s.CurrentRevision, s.UpdateRevision)
	}
	// A pre-existing workload whose revision is unchanged means the new
	// operator never updated it. New workloads (not in the snapshot) are exempt.
	if pre, existed := preRevisions[sts.Name]; existed && pre != "" && s.CurrentRevision == pre {
		return fmt.Errorf("STS %s: revision unchanged across the version change (still %q); new operator did not update it", sts.Name, pre)
	}
	if toTag != "" {
		if img, ok := tailscaleContainerImage(sts); ok && !strings.HasSuffix(img, ":"+toTag) {
			return fmt.Errorf("STS %s: proxy image %q does not carry to-version tag %q", sts.Name, img, toTag)
		}
	}
	if s.UpdatedReplicas != want {
		return fmt.Errorf("STS %s: updatedReplicas %d != desired %d", sts.Name, s.UpdatedReplicas, want)
	}
	if s.ReadyReplicas != want {
		return fmt.Errorf("STS %s: readyReplicas %d != desired %d", sts.Name, s.ReadyReplicas, want)
	}
	return nil
}

// tailscaleContainerImage returns the StatefulSet's tailscale container image,
// falling back to the first container.
func tailscaleContainerImage(sts *appsv1.StatefulSet) (string, bool) {
	cs := sts.Spec.Template.Spec.Containers
	for _, c := range cs {
		if c.Name == "tailscale" {
			return c.Image, true
		}
	}
	if len(cs) > 0 {
		return cs[0].Image, true
	}
	return "", false
}

// requireNameserverUpdated waits until the nameserver Deployment has the
// to-version image tag and is fully updated (Available, updated replicas ready).
func requireNameserverUpdated(t *testing.T, toTag string) {
	t.Helper()
	start := time.Now()
	wantSuffix := ":" + toTag
	if err := tstest.WaitFor(updateTimeout, func() error {
		d := &appsv1.Deployment{ObjectMeta: objectMeta(tsNamespace, "nameserver")}
		if err := get(t.Context(), kubeClient, d); err != nil {
			return err
		}
		cs := d.Spec.Template.Spec.Containers
		if len(cs) == 0 {
			return fmt.Errorf("nameserver Deployment has no containers")
		}
		if img := cs[0].Image; !strings.HasSuffix(img, wantSuffix) {
			return fmt.Errorf("nameserver image %q does not carry to-version tag %q", img, toTag)
		}
		if d.Status.ObservedGeneration != d.Generation {
			return fmt.Errorf("nameserver Deployment: observedGeneration %d != generation %d", d.Status.ObservedGeneration, d.Generation)
		}
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		if d.Status.UpdatedReplicas != want {
			return fmt.Errorf("nameserver Deployment: updatedReplicas %d != desired %d", d.Status.UpdatedReplicas, want)
		}
		if d.Status.ReadyReplicas != want {
			return fmt.Errorf("nameserver Deployment: readyReplicas %d != desired %d", d.Status.ReadyReplicas, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for nameserver to update to tag %q within %s: %v", toTag, updateTimeout, err)
	}
	t.Logf("nameserver updated to tag %q in %s", toTag, time.Since(start).Round(time.Second))
}

// requireNoDegradedManagedPods fails if any operator-managed Pod is in
// CrashLoopBackOff or stuck Terminating.
func requireNoDegradedManagedPods(t *testing.T) {
	t.Helper()
	var pods corev1.PodList
	if err := kubeClient.List(t.Context(), &pods,
		client.InNamespace(tsNamespace),
		client.MatchingLabels{kubetypes.LabelManaged: "true"},
	); err != nil {
		t.Fatalf("listing managed Pods: %v", err)
	}
	var problems []string
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil && time.Since(p.DeletionTimestamp.Time) > time.Minute {
			problems = append(problems, fmt.Sprintf("Pod %s stuck Terminating since %s", p.Name, p.DeletionTimestamp))
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
				problems = append(problems, fmt.Sprintf("Pod %s container %s in CrashLoopBackOff", p.Name, cs.Name))
			}
		}
	}
	if len(problems) > 0 {
		failAll(t, "degraded managed Pod", problems)
	}
}
