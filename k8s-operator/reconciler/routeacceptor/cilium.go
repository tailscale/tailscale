// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	"go.uber.org/zap"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go4.org/netipx"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

const (
	// ciliumEgressGatewayPolicyCRD is the name of the CRD that must exist for the egress gateway mode.
	ciliumEgressGatewayPolicyCRD = "ciliumegressgatewaypolicies.cilium.io"

	// tailscaleTunName is the interface Cilium masquerades to and routes via on the gateway nodes.
	tailscaleTunName = "tailscale0"

	// hostnameLabel is the well-known node label Cilium's node selectors match gateway nodes by.
	hostnameLabel = "kubernetes.io/hostname"
)

// ciliumEgressGatewayPolicyGVK identifies the policy resource. It is handled as unstructured to avoid depending
// on Cilium's Go API.
var ciliumEgressGatewayPolicyGVK = schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumEgressGatewayPolicy"}

// ciliumEgressGatewayPolicies builds the policies that steer traffic to the accepted routes via the given
// gateway nodes, masqueraded to the first address of tailscale0 on the gateway: one policy selecting every Pod
// when spec.sources is unset, otherwise one per source entry, steering the entry's Pods to the accepted routes
// that fall within the entry's routes. Entries with no such route get no policy.
func ciliumEgressGatewayPolicies(ra *tsapi.RouteAcceptor, accepted []netip.Prefix, gatewayNodes []string) ([]*unstructured.Unstructured, error) {
	if len(ra.Spec.Sources) == 0 {
		// An empty podSelector selects every Pod.
		selectors := []any{map[string]any{"podSelector": map[string]any{}}}
		u, err := ciliumEgressGatewayPolicy(ra, resourceName(ra.Name), selectors, accepted, gatewayNodes)
		if err != nil {
			return nil, err
		}
		return []*unstructured.Unstructured{u}, nil
	}

	var acceptedSet *netipx.IPSet
	{
		var b netipx.IPSetBuilder
		for _, p := range accepted {
			b.AddPrefix(p)
		}
		var err error
		if acceptedSet, err = b.IPSet(); err != nil {
			return nil, fmt.Errorf("failed to build the set of accepted routes: %w", err)
		}
	}

	var policies []*unstructured.Unstructured
	for i, src := range ra.Spec.Sources {
		routes := accepted
		if src.Routes != nil {
			var b netipx.IPSetBuilder
			for _, route := range src.Routes {
				if pfx, err := netip.ParsePrefix(string(route)); err == nil {
					b.AddPrefix(pfx.Masked())
				}
			}
			b.Intersect(acceptedSet)
			set, err := b.IPSet()
			if err != nil {
				return nil, fmt.Errorf("spec.sources[%d]: failed to intersect routes: %w", i, err)
			}
			routes = set.Prefixes()
		}
		if len(routes) == 0 {
			continue
		}
		sel := map[string]any{}
		if src.PodSelector != nil {
			ps, err := runtime.DefaultUnstructuredConverter.ToUnstructured(src.PodSelector)
			if err != nil {
				return nil, fmt.Errorf("spec.sources[%d]: failed to convert podSelector: %w", i, err)
			}
			sel["podSelector"] = ps
		}
		if src.NamespaceSelector != nil {
			ns, err := runtime.DefaultUnstructuredConverter.ToUnstructured(src.NamespaceSelector)
			if err != nil {
				return nil, fmt.Errorf("spec.sources[%d]: failed to convert namespaceSelector: %w", i, err)
			}
			sel["namespaceSelector"] = ns
		}
		if len(sel) == 0 {
			sel["podSelector"] = map[string]any{}
		}
		u, err := ciliumEgressGatewayPolicy(ra, fmt.Sprintf("%s-%d", resourceName(ra.Name), i), []any{sel}, routes, gatewayNodes)
		if err != nil {
			return nil, err
		}
		policies = append(policies, u)
	}
	return policies, nil
}

// ciliumEgressGatewayPolicy builds one policy.
func ciliumEgressGatewayPolicy(ra *tsapi.RouteAcceptor, name string, selectors []any, routes []netip.Prefix, gatewayNodes []string) (*unstructured.Unstructured, error) {
	cfg := ra.Spec.Cilium.EgressGateway

	var cidrs []string
	for _, r := range routes {
		cidrs = append(cidrs, r.String())
	}
	spec := map[string]any{
		"selectors":        selectors,
		"destinationCIDRs": toAnySlice(cidrs),
	}
	if cfg.HighAvailability {
		var gateways []any
		for _, node := range gatewayNodes {
			gateways = append(gateways, map[string]any{
				"nodeSelector": map[string]any{"matchLabels": map[string]any{hostnameLabel: node}},
				"interface":    tailscaleTunName,
			})
		}
		spec["egressGateways"] = gateways
	} else {
		// Cilium uses the first matching node in lexical order; listing every ready node lets it fail over.
		spec["egressGateway"] = map[string]any{
			"nodeSelector": map[string]any{
				"matchExpressions": []any{map[string]any{
					"key":      hostnameLabel,
					"operator": "In",
					"values":   toAnySlice(gatewayNodes),
				}},
			},
			"interface": tailscaleTunName,
		}
	}

	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(ciliumEgressGatewayPolicyGVK)
	u.SetName(name)
	u.SetLabels(routeAcceptorLabels(ra.Name))
	u.Object["spec"] = spec
	return u, nil
}

func toAnySlice(strs []string) []any {
	out := make([]any, 0, len(strs))
	for _, s := range strs {
		out = append(out, s)
	}
	return out
}

// ensureCiliumEgressGatewayPolicy creates or updates the policy for the RouteAcceptor's accepted routes and ready
// devices, and returns the RouteAcceptorDataPlaneSupported condition to set. It must run after collectStatus.
// Preconditions that Cilium cannot report through the API (the policy has no status) are checked from Cilium's
// configuration instead.
func (r *Reconciler) ensureCiliumEgressGatewayPolicy(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor, dp dataPlane) conditionSpec {
	unsupported := func(reason, message string) conditionSpec {
		return conditionSpec{metav1.ConditionFalse, reason, message}
	}
	if !dp.cilium {
		return unsupported(ReasonCiliumNotDetected, fmt.Sprintf("spec.cilium.egressGateway is set, but Cilium's configuration (%s/%s) was not found", ciliumConfigMapNamespace, ciliumConfigMapName))
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := r.apiReader.Get(ctx, types.NamespacedName{Name: ciliumEgressGatewayPolicyCRD}, &crd); err != nil {
		if apierrors.IsNotFound(err) {
			return unsupported(ReasonCiliumEgressGatewayCRDMissing, fmt.Sprintf("the %s CRD does not exist: enable Cilium's egress gateway feature", ciliumEgressGatewayPolicyCRD))
		}
		return unsupported(ReasonCiliumEgressGatewayPolicyFailed, fmt.Sprintf("failed to check for the %s CRD: %v", ciliumEgressGatewayPolicyCRD, err))
	}
	if !dp.egressGateway {
		return unsupported(ReasonCiliumEgressGatewayDisabled, "Cilium's egress gateway feature is not enabled: set egressGateway.enabled=true (requires bpf.masquerade=true and kubeProxyReplacement=true)")
	}
	if !dp.managesDevice(tailscaleTunName) {
		return unsupported(ReasonCiliumDevicesMissingTailscale0, fmt.Sprintf("Cilium does not manage %s (devices=%q): add it to Cilium's devices, for example devices={eth0,%s}, so that Cilium reverse-translates the replies", tailscaleTunName, strings.Join(dp.devices, ","), tailscaleTunName))
	}

	var gatewayNodes []string
	for _, n := range ra.Status.Nodes {
		if n.Ready {
			gatewayNodes = append(gatewayNodes, n.Name)
		}
	}
	var routes []netip.Prefix
	for _, r := range ra.Status.AcceptedRoutes {
		if pfx, err := netip.ParsePrefix(r); err == nil {
			routes = append(routes, pfx)
		}
	}
	var desired []*unstructured.Unstructured
	if len(routes) > 0 && len(gatewayNodes) > 0 {
		// Cilium requires at least one destination CIDR, and a policy without a ready gateway drops traffic.
		var err error
		if desired, err = ciliumEgressGatewayPolicies(ra, routes, gatewayNodes); err != nil {
			return unsupported(ReasonCiliumEgressGatewayPolicyFailed, err.Error())
		}
	}

	existing, err := r.listCiliumEgressGatewayPolicies(ctx, ra)
	if err != nil {
		return unsupported(ReasonCiliumEgressGatewayPolicyFailed, err.Error())
	}
	wanted := map[string]bool{}
	for _, d := range desired {
		wanted[d.GetName()] = true
		e, ok := existing[d.GetName()]
		switch {
		case !ok:
			logger.Infof("creating CiliumEgressGatewayPolicy %q for routes %v via %v", d.GetName(), d.Object["spec"].(map[string]any)["destinationCIDRs"], gatewayNodes)
			if err := r.Create(ctx, d); err != nil {
				return unsupported(ReasonCiliumEgressGatewayPolicyFailed, fmt.Sprintf("failed to create CiliumEgressGatewayPolicy %s: %v", d.GetName(), err))
			}
		case !reflect.DeepEqual(e.Object["spec"], d.Object["spec"]) || !reflect.DeepEqual(e.GetLabels(), d.GetLabels()):
			logger.Infof("updating CiliumEgressGatewayPolicy %q for routes %v via %v", d.GetName(), d.Object["spec"].(map[string]any)["destinationCIDRs"], gatewayNodes)
			e.Object["spec"] = d.Object["spec"]
			e.SetLabels(d.GetLabels())
			if err := r.Update(ctx, e); err != nil {
				return unsupported(ReasonCiliumEgressGatewayPolicyFailed, fmt.Sprintf("failed to update CiliumEgressGatewayPolicy %s: %v", d.GetName(), err))
			}
		}
	}
	for name, e := range existing {
		if wanted[name] {
			continue
		}
		logger.Infof("deleting CiliumEgressGatewayPolicy %q", name)
		if err := r.Delete(ctx, e); err != nil && !apierrors.IsNotFound(err) {
			return unsupported(ReasonCiliumEgressGatewayPolicyFailed, fmt.Sprintf("failed to delete CiliumEgressGatewayPolicy %s: %v", name, err))
		}
	}
	if len(desired) == 0 {
		return conditionSpec{metav1.ConditionTrue, ReasonCiliumEgressGateway, "waiting for ready devices and accepted routes before creating the CiliumEgressGatewayPolicy"}
	}
	return conditionSpec{metav1.ConditionTrue, ReasonCiliumEgressGateway, fmt.Sprintf("%d CiliumEgressGatewayPolicy(ies) steer traffic for %d route(s) via %d gateway node(s)", len(desired), len(routes), len(gatewayNodes))}
}

// listCiliumEgressGatewayPolicies returns the RouteAcceptor's policies by name. A cluster without the CRD has none.
func (r *Reconciler) listCiliumEgressGatewayPolicies(ctx context.Context, ra *tsapi.RouteAcceptor) (map[string]*unstructured.Unstructured, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{Group: ciliumEgressGatewayPolicyGVK.Group, Version: ciliumEgressGatewayPolicyGVK.Version, Kind: ciliumEgressGatewayPolicyGVK.Kind + "List"})
	if err := r.apiReader.List(ctx, list, client.MatchingLabels(routeAcceptorLabels(ra.Name))); err != nil {
		if meta.IsNoMatchError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list CiliumEgressGatewayPolicies: %w", err)
	}
	out := map[string]*unstructured.Unstructured{}
	for i := range list.Items {
		out[list.Items[i].GetName()] = &list.Items[i]
	}
	// The unscoped policy is also looked up by name, in case it predates the labels.
	if _, ok := out[resourceName(ra.Name)]; !ok {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(ciliumEgressGatewayPolicyGVK)
		err := r.apiReader.Get(ctx, types.NamespacedName{Name: resourceName(ra.Name)}, u)
		switch {
		case err == nil:
			out[u.GetName()] = u
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		default:
			return nil, fmt.Errorf("failed to get CiliumEgressGatewayPolicy: %w", err)
		}
	}
	return out, nil
}

// deleteCiliumEgressGatewayPolicy deletes the RouteAcceptor's policies if any exist. A cluster without the CRD is
// not an error.
func (r *Reconciler) deleteCiliumEgressGatewayPolicy(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor) error {
	existing, err := r.listCiliumEgressGatewayPolicies(ctx, ra)
	if err != nil {
		return err
	}
	for name, e := range existing {
		logger.Infof("deleting CiliumEgressGatewayPolicy %q", name)
		if err := r.Delete(ctx, e); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete CiliumEgressGatewayPolicy %s: %w", name, err)
		}
	}
	return nil
}
