// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstime"
	"tailscale.com/util/set"
)

const (
	reasonReadinessCheckFailed     = "ReadinessCheckFailed"
	reasonClusterResourcesNotReady = "ClusterResourcesNotReady"
	reasonNoProxies                = "NoProxiesConfigured"
	reasonNotReady                 = "NotReadyToRouteTraffic"
	reasonReady                    = "ReadyToRouteTraffic"
	reasonPartiallyReady           = "PartiallyReadyToRouteTraffic"
	msgReadyToRouteTemplate        = "%d out of %d replicas are ready to route traffic"
)

type egressSvcsReadinessReconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	clock       tstime.Clock
	tsNamespace string
}

// Reconcile reconciles an ExternalName Service that defines a tailnet target to be exposed on a ProxyGroup and sets the
// EgressSvcReady condition on it. The condition gets set to true if at least one of the proxies is currently ready to
// route traffic to the target. It compares proxy Pod IPs with the endpoints set on the EndpointSlice for the egress
// service to determine how many replicas are currently able to route traffic.
func (esrr *egressSvcsReadinessReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	lg := esrr.logger.With("Service", req.NamespacedName)
	lg.Debugf("starting reconcile")
	defer lg.Debugf("reconcile finished")

	svc := new(corev1.Service)
	if err = esrr.Get(ctx, req.NamespacedName, svc); apierrors.IsNotFound(err) {
		lg.Debugf("Service not found")
		return res, nil
	} else if err != nil {
		return res, fmt.Errorf("failed to get Service: %w", err)
	}
	var (
		reason, msg string
		st          metav1.ConditionStatus = metav1.ConditionUnknown
	)
	oldStatus := svc.Status.DeepCopy()
	defer func() {
		tsoperator.SetServiceCondition(svc, tsapi.EgressSvcReady, st, reason, msg, esrr.clock, lg)
		if !apiequality.Semantic.DeepEqual(oldStatus, &svc.Status) {
			err = errors.Join(err, esrr.Status().Update(ctx, svc))
		}
	}()

	crl := egressSvcChildResourceLabels(svc)
	epsList := &discoveryv1.EndpointSliceList{}
	if err = esrr.List(ctx, epsList, client.InNamespace(esrr.tsNamespace), client.MatchingLabels(crl)); err != nil {
		err = fmt.Errorf("error listing EndpointSlices: %w", err)
		reason = reasonReadinessCheckFailed
		msg = err.Error()
		return res, err
	}
	if len(epsList.Items) == 0 {
		lg.Infof("EndpointSlices for Service do not yet exist, waiting...")
		reason, msg = reasonClusterResourcesNotReady, reasonClusterResourcesNotReady
		st = metav1.ConditionFalse
		return res, nil
	}
	// If an EndpointSlice for an expected family is missing, we mark the Service as NotReady.
	//
	// Setting the NotReady condition here is also used for best-effort recovery. The
	// egress-svcs-reconciler does not watch EndpointSlices, so a deleted EndpointSlice is only
	// recreated when this status change re-triggers a Service reconcile.
	//
	// TODO(beckypauley): refactor so EndpointSlice recovery is not dependent on Service status.
	clusterIPSvc, err := getSingleObject[corev1.Service](ctx, esrr.Client, esrr.tsNamespace, crl)
	if err != nil {
		err = fmt.Errorf("error retrieving ClusterIP Service: %w", err)
		reason = reasonReadinessCheckFailed
		msg = err.Error()
		return res, err
	}
	if clusterIPSvc == nil {
		lg.Infof("ClusterIP Service for egress Service does not yet exist, waiting...")
		reason, msg = reasonClusterResourcesNotReady, reasonClusterResourcesNotReady
		st = metav1.ConditionFalse
		return res, nil
	}
	gotAddrTypes := make(set.Set[discoveryv1.AddressType], len(epsList.Items))
	for _, eps := range epsList.Items {
		gotAddrTypes.Add(eps.AddressType)
	}
	wantAddrTypes, err := addrTypesForClusterIPSvc(clusterIPSvc)
	if err != nil {
		reason = reasonReadinessCheckFailed
		msg = err.Error()
		return res, err
	}
	for _, wantAddrType := range wantAddrTypes {
		if !gotAddrTypes.Contains(wantAddrType) {
			lg.Infof("EndpointSlice for %s is missing, waiting...", wantAddrType)
			reason, msg = reasonClusterResourcesNotReady, reasonClusterResourcesNotReady
			st = metav1.ConditionFalse
			return res, nil
		}
	}
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: svc.Annotations[AnnotationProxyGroup],
		},
	}
	err = esrr.Get(ctx, client.ObjectKeyFromObject(pg), pg)
	if apierrors.IsNotFound(err) {
		lg.Infof("ProxyGroup for Service does not exist, waiting...")
		reason, msg = reasonClusterResourcesNotReady, reasonClusterResourcesNotReady
		st = metav1.ConditionFalse
		return res, nil
	}
	if err != nil {
		err = fmt.Errorf("error retrieving ProxyGroup: %w", err)
		reason = reasonReadinessCheckFailed
		msg = err.Error()
		return res, err
	}
	if !tsoperator.ProxyGroupAvailable(pg) {
		lg.Infof("ProxyGroup for Service is not ready, waiting...")
		reason, msg = reasonClusterResourcesNotReady, reasonClusterResourcesNotReady
		st = metav1.ConditionFalse
		return res, nil
	}

	replicas := pgReplicas(pg)
	if replicas == 0 {
		lg.Infof("ProxyGroup replicas set to 0")
		reason, msg = reasonNoProxies, reasonNoProxies
		st = metav1.ConditionFalse
		return res, nil
	}
	podLabels := pgLabels(pg.Name, nil)
	var readyReplicas int32
nextReplica:
	for i := range replicas {
		podLabels[appsv1.PodIndexLabel] = fmt.Sprintf("%d", i)
		pod, err := getSingleObject[corev1.Pod](ctx, esrr.Client, esrr.tsNamespace, podLabels)
		if err != nil {
			err = fmt.Errorf("error retrieving ProxyGroup Pod: %w", err)
			reason = reasonReadinessCheckFailed
			msg = err.Error()
			return res, err
		}

		if pod == nil {
			lg.Warnf("ProxyGroup is ready, but replica %d was not found", i)
			reason, msg = reasonClusterResourcesNotReady, reasonClusterResourcesNotReady
			return res, nil
		}

		lg.Debugf("looking at Pod with IPs %v", pod.Status.PodIPs)
		for _, eps := range epsList.Items {
			lg.Debugf("looking at %s EndpointSlice %s", eps.AddressType, eps.Name)
			if !slices.ContainsFunc(eps.Endpoints, func(ep discoveryv1.Endpoint) bool {
				return endpointReadyForPod(&ep, pod, eps.AddressType, lg)
			}) {
				continue nextReplica
			}
		}
		lg.Debugf("endpoint is ready for Pod")
		readyReplicas++
	}
	msg = fmt.Sprintf(msgReadyToRouteTemplate, readyReplicas, replicas)
	if readyReplicas == 0 {
		reason = reasonNotReady
		st = metav1.ConditionFalse
		return res, nil
	}
	st = metav1.ConditionTrue
	if readyReplicas < replicas {
		reason = reasonPartiallyReady
	} else {
		reason = reasonReady
	}
	return res, nil
}

// endpointReadyForPod returns true if the endpoint is for the Pod's address (for the given address family)
// and is ready to serve traffic. Endpoint must not be nil.
func endpointReadyForPod(ep *discoveryv1.Endpoint, pod *corev1.Pod, addrType discoveryv1.AddressType, lg *zap.SugaredLogger) bool {
	podIP, err := podIPForFamily(pod, addrType)
	if err != nil {
		lg.Warnf("error retrieving Pod's %s address: %v", addrType, err)
		return false
	}
	if podIP == "" {
		return false
	}

	// Currently we only ever set a single address on and Endpoint and nothing else is meant to modify this.
	if len(ep.Addresses) != 1 {
		return false
	}
	return strings.EqualFold(ep.Addresses[0], podIP) &&
		*ep.Conditions.Ready &&
		*ep.Conditions.Serving &&
		!*ep.Conditions.Terminating
}
