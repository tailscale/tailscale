// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"go.uber.org/zap"
	xslices "golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/set"
)

const tsEgressReadinessGate = "tailscale.com/egress-services"

// egressPodsReconciler is responsible for setting tailscale.com/egress-services condition on egress ProxyGroup Pods.
// The condition is used as a readiness gate for the Pod, meaning that kubelet will not mark the Pod as ready before the
// condition is set. The ProxyGroup StatefulSet updates are rolled out in such a way that no Pod is restarted, before
// the previous Pod is marked as ready, so ensuring that the Pod does not get marked as ready when it is not yet able to
// route traffic for egress service prevents downtime during restarts caused by no available endpoints left because
// every Pod has been recreated and is not yet added to endpoints.
// https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-readiness-gate
type egressPodsReconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	tsNamespace string
	clock       tstime.Clock
}

// Reconcile reconciles an egress ProxyGroup Pods on changes to those Pods and ProxyGroup EndpointSlices. It ensures
// that for each Pod who is ready to route traffic to all egress services for the ProxyGroup, the Pod has a
// tailscale.com/egress-services condition to set, so that kubelet will mark the Pod as ready.
//
// The endpoints for each egress service's ClusterIP Service are configured by the operator itself using custom
// EndpointSlices (egress-eps-reconciler), which only adds a Pod once the Pod's state Secret shows that the proxy has
// set up routing for that egress service. So a Pod is ready once, for every egress service for the ProxyGroup, it is
// an endpoint in the EndpointSlice of each IP family that the proxy reports an address for in its state Secret.
func (er *egressPodsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	lg := er.logger.With("Pod", req.NamespacedName)
	lg.Debugf("starting reconcile")
	defer lg.Debugf("reconcile finished")

	pod := new(corev1.Pod)
	err = er.Get(ctx, req.NamespacedName, pod)
	if apierrors.IsNotFound(err) {
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Pod: %w", err)
	}
	if !pod.DeletionTimestamp.IsZero() {
		lg.Debugf("Pod is being deleted, do nothing")
		return res, nil
	}

	if pod.Labels[LabelParentType] != proxyTypeProxyGroup {
		lg.Warn("reconciler called for a Pod that is not a ProxyGroup Pod")
		return res, nil
	}

	// If the Pod does not have the readiness gate set, there is no need to add the readiness condition. In practice
	// this will happen if the user has configured custom TS_LOCAL_ADDR_PORT, thus disabling the graceful failover.
	if !slices.ContainsFunc(pod.Spec.ReadinessGates, func(r corev1.PodReadinessGate) bool {
		return r.ConditionType == tsEgressReadinessGate
	}) {
		lg.Debug("Pod does not have egress readiness gate set, skipping")
		return res, nil
	}

	proxyGroupName := pod.Labels[LabelParentName]
	pg := new(tsapi.ProxyGroup)
	if err := er.Get(ctx, types.NamespacedName{Name: proxyGroupName}, pg); err != nil {
		return res, fmt.Errorf("error getting ProxyGroup %q: %w", proxyGroupName, err)
	}

	if pg.Spec.Type != typeEgress {
		lg.Warnf("reconciler called for %q ProxyGroup Pod", pg.Spec.Type)
		return res, nil
	}

	// Get all ClusterIP Services for all egress targets exposed to cluster via this ProxyGroup.
	lbls := map[string]string{
		kubetypes.LabelManaged: "true",
		labelProxyGroup:        proxyGroupName,
		labelSvcType:           typeEgress,
	}
	svcs := &corev1.ServiceList{}
	if err := er.List(ctx, svcs, client.InNamespace(er.tsNamespace), client.MatchingLabels(lbls)); err != nil {
		return res, fmt.Errorf("error listing ClusterIP Services")
	}

	idx := xslices.IndexFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool {
		return c.Type == tsEgressReadinessGate
	})
	if idx != -1 {
		lg.Debugf("Pod is already ready, do nothing")
		return res, nil
	}

	epsList := &discoveryv1.EndpointSliceList{}
	if err := er.List(ctx, epsList, client.InNamespace(er.tsNamespace), client.MatchingLabels(lbls)); err != nil {
		return res, fmt.Errorf("failed to list EndpointSlices: %w", err)
	}
	// Each egress service has an EndpointSlice per IP family. A Pod must be an endpoint in the EndpointSlice of
	// every family that the proxy reports, else it can be marked ready while only one family routes to it. A proxy
	// older than v1.102 does not report an IPv6 address, so egress-eps-reconciler never adds it to an IPv6
	// EndpointSlice. Requiring the families that the Pod has addresses for would block such a Pod forever.
	families, err := er.reportedFamilies(ctx, pod)
	if err != nil {
		return res, fmt.Errorf("error determining IP families reported by proxy: %w", err)
	}
	routed := make(set.Set[string])
	missing := make(set.Set[string])
	for _, eps := range epsList.Items {
		svcName := eps.Labels[discoveryv1.LabelServiceName]
		// egress-eps-reconciler sets the endpoint's hostname to the Pod's UID.
		if slices.ContainsFunc(eps.Endpoints, func(ep discoveryv1.Endpoint) bool {
			return ep.Hostname != nil && *ep.Hostname == string(pod.UID)
		}) {
			routed.Add(svcName)
			continue
		}
		if families.Contains(eps.AddressType) {
			missing.Add(svcName)
		}
	}
	var waiting []string
	for _, svc := range svcs.Items {
		if !routed.Contains(svc.Name) || missing.Contains(svc.Name) {
			waiting = append(waiting, svc.Name)
		}
	}
	if len(waiting) > 0 {
		lg.Infof("Pod is not yet added as an endpoint for egress Services %q, waiting...", waiting)
		return reconcile.Result{RequeueAfter: shortRequeue}, nil
	}
	if err := er.setPodReady(ctx, pod, lg); err != nil {
		return res, fmt.Errorf("error setting Pod as ready: %w", err)
	}
	return res, nil
}

// reportedFamilies returns the IP families that the proxy reports addresses for in the egress services status in its
// state Secret. It returns an empty set if the proxy has not yet written the status.
func (er *egressPodsReconciler) reportedFamilies(ctx context.Context, pod *corev1.Pod) (set.Set[discoveryv1.AddressType], error) {
	families := make(set.Set[discoveryv1.AddressType])
	stateS := &corev1.Secret{}
	err := er.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}, stateS)
	switch {
	case apierrors.IsNotFound(err):
		return families, nil
	case err != nil:
		return nil, fmt.Errorf("error retrieving state Secret: %w", err)
	}

	svcStatusBS := stateS.Data[egressservices.KeyEgressServices]
	if len(svcStatusBS) == 0 {
		return families, nil
	}

	svcStatus := &egressservices.Status{}
	if err := json.Unmarshal(svcStatusBS, svcStatus); err != nil {
		return nil, fmt.Errorf("error unmarshalling egress service status: %w", err)
	}
	if svcStatus.PodIPv4 != "" {
		families.Add(discoveryv1.AddressTypeIPv4)
	}
	if svcStatus.PodIPv6 != "" {
		families.Add(discoveryv1.AddressTypeIPv6)
	}
	return families, nil
}

func (er *egressPodsReconciler) setPodReady(ctx context.Context, pod *corev1.Pod, lg *zap.SugaredLogger) error {
	if slices.ContainsFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool {
		return c.Type == tsEgressReadinessGate
	}) {
		return nil
	}
	lg.Infof("Pod is ready to route traffic to all egress targets")
	pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
		Type:               tsEgressReadinessGate,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: er.clock.Now()},
	})
	return er.Status().Update(ctx, pod)
}
