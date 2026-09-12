// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/net/tsaddr"
)

// conditionSpec is a condition's status, reason and message.
type conditionSpec struct {
	status  metav1.ConditionStatus
	reason  string
	message string
}

// collectStatus fills in the RouteAcceptor's status fields from the DaemonSet's status and the devices' state
// Secrets: the per-node device status, the accepted routes, and the node counts. It does not set conditions or
// update the resource.
func (r *Reconciler) collectStatus(ctx context.Context, ra *tsapi.RouteAcceptor, ds *appsv1.DaemonSet) error {
	secrets, err := r.listStateSecrets(ctx, ra)
	if err != nil {
		return err
	}

	var nodes []tsapi.RouteAcceptorNode
	var routes []netip.Prefix
	for i := range secrets {
		n, ok := nodeStatusFromSecret(&secrets[i])
		if !ok {
			continue
		}
		nodes = append(nodes, n)
		for _, route := range n.AcceptedRoutes {
			if pfx, err := netip.ParsePrefix(route); err == nil {
				routes = append(routes, pfx)
			}
		}
	}
	slices.SortFunc(nodes, func(a, b tsapi.RouteAcceptorNode) int { return cmp.Compare(a.Name, b.Name) })
	routes = sortedPrefixes(routes)

	ra.Status.Nodes = nodes
	ra.Status.AcceptedRoutes = nil
	for _, route := range routes {
		ra.Status.AcceptedRoutes = append(ra.Status.AcceptedRoutes, route.String())
	}
	ra.Status.DesiredNodes = 0
	ra.Status.ReadyNodes = 0
	if ds != nil {
		ra.Status.DesiredNodes = ds.Status.DesiredNumberScheduled
		ra.Status.ReadyNodes = ds.Status.NumberReady
	}
	return nil
}

// writeStatus sets the RouteAcceptorReady, RouteAcceptorRoutesValid and RouteAcceptorDataPlaneSupported
// conditions from the collected status and updates the resource if anything changed since prevStatus.
func (r *Reconciler) writeStatus(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor, prevStatus *tsapi.RouteAcceptorStatus, clusterCIDRs []netip.Prefix, dataPlane conditionSpec) error {
	var routes []netip.Prefix
	for _, route := range ra.Status.AcceptedRoutes {
		if pfx, err := netip.ParsePrefix(route); err == nil {
			routes = append(routes, pfx)
		}
	}

	switch {
	case ra.Status.DesiredNodes == 0:
		message := "no nodes are selected to run a route acceptor device"
		operatorutils.SetRouteAcceptorCondition(ra, tsapi.RouteAcceptorReady, metav1.ConditionFalse, ReasonNoNodesSelected, message, r.clock, logger)
	case ra.Status.ReadyNodes < ra.Status.DesiredNodes:
		message := fmt.Sprintf("%d of %d nodes are ready", ra.Status.ReadyNodes, ra.Status.DesiredNodes)
		operatorutils.SetRouteAcceptorCondition(ra, tsapi.RouteAcceptorReady, metav1.ConditionFalse, ReasonPodsPending, message, r.clock, logger)
	default:
		operatorutils.SetRouteAcceptorCondition(ra, tsapi.RouteAcceptorReady, metav1.ConditionTrue, ReasonReady, ReasonReady, r.clock, logger)
	}

	if overlapping := overlappingRoutes(routes, clusterCIDRs); len(overlapping) > 0 {
		message := fmt.Sprintf("accepted routes overlap IP ranges used by the cluster, so cluster traffic to them is routed into the tailnet: %s", strings.Join(overlapping, ", "))
		if !hasCondition(ra, tsapi.RouteAcceptorRoutesValid, metav1.ConditionFalse) {
			r.event(ra, corev1.EventTypeWarning, ReasonRouteOverlapsClusterCIDR, message)
		}
		operatorutils.SetRouteAcceptorCondition(ra, tsapi.RouteAcceptorRoutesValid, metav1.ConditionFalse, ReasonRouteOverlapsClusterCIDR, message, r.clock, logger)
	} else {
		operatorutils.SetRouteAcceptorCondition(ra, tsapi.RouteAcceptorRoutesValid, metav1.ConditionTrue, ReasonRoutesValid, ReasonRoutesValid, r.clock, logger)
	}

	if dataPlane.status == metav1.ConditionFalse && !hasCondition(ra, tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionFalse) {
		r.event(ra, corev1.EventTypeWarning, dataPlane.reason, dataPlane.message)
	}
	operatorutils.SetRouteAcceptorCondition(ra, tsapi.RouteAcceptorDataPlaneSupported, dataPlane.status, dataPlane.reason, dataPlane.message, r.clock, logger)

	if reflect.DeepEqual(prevStatus, &ra.Status) {
		return nil
	}

	if err := r.Status().Update(ctx, ra); err != nil {
		return fmt.Errorf("failed to update RouteAcceptor status: %w", err)
	}

	return nil
}

func hasCondition(ra *tsapi.RouteAcceptor, conditionType tsapi.ConditionType, status metav1.ConditionStatus) bool {
	for _, c := range ra.Status.Conditions {
		if c.Type == string(conditionType) {
			return c.Status == status
		}
	}
	return false
}

// nodeStatusFromSecret builds the status of the device on a node from its state Secret, as written by
// containerboot. It returns false if the Secret does not record which node it belongs to.
func nodeStatusFromSecret(s *corev1.Secret) (tsapi.RouteAcceptorNode, bool) {
	node := s.Annotations[annotationNodeName]
	if node == "" {
		return tsapi.RouteAcceptorNode{}, false
	}

	n := tsapi.RouteAcceptorNode{
		Name:     node,
		Hostname: string(s.Data[kubetypes.KeyDeviceFQDN]),
	}
	if raw := s.Data[kubetypes.KeyDeviceIPs]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &n.TailnetIPs); err != nil {
			n.TailnetIPs = nil
		}
	}
	if raw := s.Data[kubetypes.KeyAcceptedRoutes]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &n.AcceptedRoutes); err != nil {
			n.AcceptedRoutes = nil
		}
	}
	n.Ready = len(n.TailnetIPs) > 0
	return n, true
}

// clusterCIDRs returns the IP ranges the cluster is known to use: the Pod CIDRs recorded on the Nodes, the
// ServiceCIDRs if the cluster serves them, and the ranges listed in spec.clusterCIDRs.
func (r *Reconciler) clusterCIDRs(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor, nodes []corev1.Node) []netip.Prefix {
	var cidrs []netip.Prefix
	add := func(s string) {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			cidrs = append(cidrs, pfx.Masked())
		}
	}

	for _, n := range nodes {
		if len(n.Spec.PodCIDRs) == 0 && n.Spec.PodCIDR != "" {
			add(n.Spec.PodCIDR)
		}
		for _, c := range n.Spec.PodCIDRs {
			add(c)
		}
	}

	// ServiceCIDRs are served by Kubernetes 1.33 and newer; older clusters return a "no match" error, which is
	// not worth failing the reconcile over. Read uncached, as the cached client would try to start an informer
	// for a resource type the cluster may not serve.
	var serviceCIDRs networkingv1.ServiceCIDRList
	if err := r.apiReader.List(ctx, &serviceCIDRs); err != nil {
		if !meta.IsNoMatchError(err) {
			logger.Debugf("failed to list ServiceCIDRs, ignoring: %v", err)
		}
	} else {
		for _, sc := range serviceCIDRs.Items {
			for _, c := range sc.Spec.CIDRs {
				add(c)
			}
		}
	}

	for _, c := range ra.Spec.ClusterCIDRs {
		add(string(c))
	}

	return sortedPrefixes(cidrs)
}

// sortedPrefixes sorts prefixes by address and then by length, and removes duplicates. Sorting by address first
// keeps related routes together when displayed.
func sortedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
	return slices.Compact(prefixes)
}

// overlapsCGNAT returns the first of cidrs that overlaps the Tailscale IP range, if any.
func overlapsCGNAT(cidrs []netip.Prefix) (netip.Prefix, bool) {
	for _, c := range cidrs {
		if c.Overlaps(tsaddr.CGNATRange()) {
			return c, true
		}
	}
	return netip.Prefix{}, false
}

// overlappingRoutes returns a description of every pair of an accepted route and a cluster IP range that overlap.
func overlappingRoutes(routes, clusterCIDRs []netip.Prefix) []string {
	var overlapping []string
	for _, route := range routes {
		for _, c := range clusterCIDRs {
			if route.Overlaps(c) {
				overlapping = append(overlapping, fmt.Sprintf("%s overlaps %s", route, c))
			}
		}
	}
	return overlapping
}
