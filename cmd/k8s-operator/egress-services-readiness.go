// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
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
	l := esrr.logger.With("Service", req.NamespacedName)
	defer l.Info("reconcile finished")

	svc := new(corev1.Service)
	if err = esrr.Get(ctx, req.NamespacedName, svc); apierrors.IsNotFound(err) {
		l.Info("Service not found")
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
		tsoperator.SetServiceCondition(svc, tsapi.EgressSvcReady, st, reason, msg, esrr.clock, l)
		if !apiequality.Semantic.DeepEqual(oldStatus, &svc.Status) {
			err = errors.Join(err, esrr.Status().Update(ctx, svc))
		}
	}()

	crl := egressSvcChildResourceLabels(svc)
	eps, err := getSingleObject[discoveryv1.EndpointSlice](ctx, esrr.Client, esrr.tsNamespace, crl)
	if err != nil {
		err = fmt.Errorf("error getting EndpointSlice: %w", err)
		reason = reasonReadinessCheckFailed
		msg = err.Error()
		return res, err
	}
	if eps == nil {
		l.Infof("EndpointSlice for Service does not yet exist, waiting...")
		reason, msg = reasonClusterResourcesNotReady, reasonClusterResourcesNotReady
		st = metav1.ConditionFalse
		return res, nil
	}
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: svc.Annotations[AnnotationProxyGroup],
		},
	}
	err = esrr.Get(ctx, client.ObjectKeyFromObject(pg), pg)
	if apierrors.IsNotFound(err) {
		l.Infof("ProxyGroup for Service does not exist, waiting...")
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
	if !tsoperator.ProxyGroupIsReady(pg) {
		l.Infof("ProxyGroup for Service is not ready, waiting...")
		reason, msg = reasonClusterResourcesNotReady, reasonClusterResourcesNotReady
		st = metav1.ConditionFalse
		return res, nil
	}

	replicas := pgReplicas(pg)
	if replicas == 0 {
		l.Infof("ProxyGroup replicas set to 0")
		reason, msg = reasonNoProxies, reasonNoProxies
		st = metav1.ConditionFalse
		return res, nil
	}
	podLabels := pgLabels(pg.Name, nil)
	var readyReplicas int32
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
			l.Infof("[unexpected] ProxyGroup is ready, but replica %d was not found", i)
			reason, msg = reasonClusterResourcesNotReady, reasonClusterResourcesNotReady
			return res, nil
		}
		l.Infof("looking at Pod with IPs %v", pod.Status.PodIPs)
		ready := false
		for _, ep := range eps.Endpoints {
			l.Infof("looking at endpoint with addresses %v", ep.Addresses)
			if endpointReadyForPod(&ep, pod, l) {
				l.Infof("endpoint is ready for Pod")
				ready = true
				break
			}
		}
		if ready {
			readyReplicas++
		}
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

// endpointReadyForPod returns true if the endpoint is for the Pod's IPv4 address and is ready to serve traffic.
// Endpoint must not be nil.
func endpointReadyForPod(ep *discoveryv1.Endpoint, pod *corev1.Pod, l *zap.SugaredLogger) bool {
	podIP, err := podIPv4(pod)
	if err != nil {
		l.Infof("[unexpected] error retrieving Pod's IPv4 address: %v", err)
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
