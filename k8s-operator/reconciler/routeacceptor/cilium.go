// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor

import (
	"context"
	"fmt"
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

// ciliumEgressGatewayPolicy builds the policy that steers traffic from the selected Pods to routes via the given
// gateway nodes, masqueraded to the first address of tailscale0 on the gateway.
func ciliumEgressGatewayPolicy(ra *tsapi.RouteAcceptor, routes, gatewayNodes []string) (*unstructured.Unstructured, error) {
	cfg := ra.Spec.Cilium.EgressGateway

	var selectors []any
	for _, sel := range cfg.Selectors {
		m := map[string]any{}
		if sel.PodSelector != nil {
			ps, err := runtime.DefaultUnstructuredConverter.ToUnstructured(sel.PodSelector)
			if err != nil {
				return nil, fmt.Errorf("failed to convert podSelector: %w", err)
			}
			m["podSelector"] = ps
		}
		if sel.NamespaceSelector != nil {
			ns, err := runtime.DefaultUnstructuredConverter.ToUnstructured(sel.NamespaceSelector)
			if err != nil {
				return nil, fmt.Errorf("failed to convert namespaceSelector: %w", err)
			}
			m["namespaceSelector"] = ns
		}
		selectors = append(selectors, m)
	}
	if len(selectors) == 0 {
		// An empty podSelector selects every Pod.
		selectors = []any{map[string]any{"podSelector": map[string]any{}}}
	}

	spec := map[string]any{
		"selectors":        selectors,
		"destinationCIDRs": toAnySlice(routes),
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
	u.SetName(resourceName(ra.Name))
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
	routes := ra.Status.AcceptedRoutes
	if len(routes) == 0 || len(gatewayNodes) == 0 {
		// Cilium requires at least one destination CIDR, and a policy without a ready gateway drops traffic.
		if err := r.deleteCiliumEgressGatewayPolicy(ctx, logger, ra); err != nil {
			return unsupported(ReasonCiliumEgressGatewayPolicyFailed, err.Error())
		}
		return conditionSpec{metav1.ConditionTrue, ReasonCiliumEgressGateway, "waiting for ready devices and accepted routes before creating the CiliumEgressGatewayPolicy"}
	}

	desired, err := ciliumEgressGatewayPolicy(ra, routes, gatewayNodes)
	if err != nil {
		return unsupported(ReasonCiliumEgressGatewayPolicyFailed, err.Error())
	}
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(ciliumEgressGatewayPolicyGVK)
	err = r.apiReader.Get(ctx, types.NamespacedName{Name: desired.GetName()}, existing)
	switch {
	case apierrors.IsNotFound(err):
		logger.Infof("creating CiliumEgressGatewayPolicy %q for routes %v via %v", desired.GetName(), routes, gatewayNodes)
		if err := r.Create(ctx, desired); err != nil {
			return unsupported(ReasonCiliumEgressGatewayPolicyFailed, fmt.Sprintf("failed to create CiliumEgressGatewayPolicy: %v", err))
		}
	case err != nil:
		return unsupported(ReasonCiliumEgressGatewayPolicyFailed, fmt.Sprintf("failed to get CiliumEgressGatewayPolicy: %v", err))
	default:
		if !reflect.DeepEqual(existing.Object["spec"], desired.Object["spec"]) || !reflect.DeepEqual(existing.GetLabels(), desired.GetLabels()) {
			logger.Infof("updating CiliumEgressGatewayPolicy %q for routes %v via %v", desired.GetName(), routes, gatewayNodes)
			existing.Object["spec"] = desired.Object["spec"]
			existing.SetLabels(desired.GetLabels())
			if err := r.Update(ctx, existing); err != nil {
				return unsupported(ReasonCiliumEgressGatewayPolicyFailed, fmt.Sprintf("failed to update CiliumEgressGatewayPolicy: %v", err))
			}
		}
	}
	return conditionSpec{metav1.ConditionTrue, ReasonCiliumEgressGateway, fmt.Sprintf("CiliumEgressGatewayPolicy %s steers traffic for %d route(s) via %d gateway node(s)", desired.GetName(), len(routes), len(gatewayNodes))}
}

// deleteCiliumEgressGatewayPolicy deletes the RouteAcceptor's policy if it exists. A cluster without the CRD is
// not an error.
func (r *Reconciler) deleteCiliumEgressGatewayPolicy(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor) error {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(ciliumEgressGatewayPolicyGVK)
	err := r.apiReader.Get(ctx, types.NamespacedName{Name: resourceName(ra.Name)}, existing)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return nil
	case err != nil:
		return fmt.Errorf("failed to get CiliumEgressGatewayPolicy: %w", err)
	}
	logger.Infof("deleting CiliumEgressGatewayPolicy %q", existing.GetName())
	if err := r.Delete(ctx, existing); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete CiliumEgressGatewayPolicy: %w", err)
	}
	return nil
}
