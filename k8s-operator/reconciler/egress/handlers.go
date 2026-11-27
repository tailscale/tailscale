// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package egress

import (
	"context"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
)

// egressSvcsHandler returns accepts a Kubernetes object and returns a reconcile
// request for it , if the object is a Tailscale egress Service meant to be
// exposed on a ProxyGroup.
func egressSvcsHandler(_ context.Context, o client.Object) []reconcile.Request {
	if !isEgressSvcForProxyGroup(o) {
		return nil
	}
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: o.GetNamespace(),
				Name:      o.GetName(),
			},
		},
	}
}

// egressEpsHandler returns accepts an EndpointSlice and, if the EndpointSlice
// is for an egress service, returns a reconcile request for it.
func egressEpsHandler(_ context.Context, o client.Object) []reconcile.Request {
	if typ := o.GetLabels()[labelSvcType]; typ != typeEgress {
		return nil
	}
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: o.GetNamespace(),
				Name:      o.GetName(),
			},
		},
	}
}

func egressPodsHandler(_ context.Context, o client.Object) []reconcile.Request {
	if typ := o.GetLabels()[reconciler.LabelParentType]; typ != reconciler.ParentTypeProxyGroup {
		return nil
	}
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: o.GetNamespace(),
				Name:      o.GetName(),
			},
		},
	}
}

// egressEpsFromEgressPods returns a Pod event handler that checks if Pod is a replica for a ProxyGroup and if it is,
// returns reconciler requests for all egress EndpointSlices for that ProxyGroup.
func egressEpsFromPGPods(cl client.Client, ns string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		// TODO(irbekrm): for now this is good enough as all ProxyGroups are egress. Add a type check once we
		// have ingress ProxyGroups.
		if !reconciler.IsManagedByType(o, reconciler.ParentTypeProxyGroup) {
			return nil
		}
		pg, ok := o.GetLabels()[reconciler.LabelParentName]
		if !ok {
			return nil
		}
		return reconcileRequestsForPG(pg, cl, ns)
	}
}

// egressEpsFromPGStateSecrets returns a Secret event handler that checks if Secret is a state Secret for a ProxyGroup and if it is,
// returns reconciler requests for all egress EndpointSlices for that ProxyGroup.
func egressEpsFromPGStateSecrets(cl client.Client, ns string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		if !reconciler.IsManagedByType(o, reconciler.ParentTypeProxyGroup) {
			return nil
		}
		if secretType := o.GetLabels()[kubetypes.LabelSecretType]; secretType != kubetypes.LabelSecretTypeState {
			return nil
		}
		pg, ok := o.GetLabels()[reconciler.LabelParentName]
		if !ok {
			return nil
		}
		return reconcileRequestsForPG(pg, cl, ns)
	}
}

func reconcileRequestsForPG(pg string, cl client.Client, ns string) []reconcile.Request {
	epsList := discoveryv1.EndpointSliceList{}
	if err := cl.List(context.Background(), &epsList,
		client.InNamespace(ns),
		client.MatchingLabels(map[string]string{reconciler.LabelProxyGroup: pg})); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0)
	for _, ep := range epsList.Items {
		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: ep.Namespace,
				Name:      ep.Name,
			},
		})
	}
	return reqs
}

// egressSvcFromEps is an event handler for EndpointSlices. If an EndpointSlice is for an egress ExternalName Service
// meant to be exposed on a ProxyGroup, returns a reconcile request for the Service.
func egressSvcFromEps(_ context.Context, o client.Object) []reconcile.Request {
	if typ := o.GetLabels()[labelSvcType]; typ != typeEgress {
		return nil
	}
	if v, ok := o.GetLabels()[kubetypes.LabelManaged]; !ok || v != "true" {
		return nil
	}
	svcName, ok := o.GetLabels()[reconciler.LabelParentName]
	if !ok {
		return nil
	}
	svcNs, ok := o.GetLabels()[reconciler.LabelParentNamespace]
	if !ok {
		return nil
	}
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: svcNs,
				Name:      svcName,
			},
		},
	}
}

// egressSvcsFromEgressProxyGroup is an event handler for egress ProxyGroups. It returns reconcile requests for all
// user-created ExternalName Services that should be exposed on this ProxyGroup.
func egressSvcsFromEgressProxyGroup(cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		pg, ok := o.(*tsapi.ProxyGroup)
		if !ok {
			logger.Warn("ProxyGroup handler triggered for an object that is not a ProxyGroup")
			return nil
		}

		if pg.Spec.Type != tsapi.ProxyGroupTypeEgress {
			return nil
		}
		svcList := &corev1.ServiceList{}
		if err := cl.List(ctx, svcList, client.MatchingFields{indexEgressProxyGroup: pg.Name}); err != nil {
			logger.Infof("error listing Services: %v, skipping a reconcile for event on ProxyGroup %s", err, pg.Name)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		for _, svc := range svcList.Items {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: svc.Namespace,
					Name:      svc.Name,
				},
			})
		}
		return reqs
	}
}

// epsFromExternalNameService is an event handler for ExternalName Services that define a Tailscale egress service that
// should be exposed on a ProxyGroup. It returns reconcile requests for EndpointSlices created for this Service.
func epsFromExternalNameService(cl client.Client, logger *zap.SugaredLogger, ns string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		svc, ok := o.(*corev1.Service)
		if !ok {
			logger.Warn("Service handler triggered for an object that is not a Service")
			return nil
		}

		if !isEgressSvcForProxyGroup(svc) {
			return nil
		}
		epsList := &discoveryv1.EndpointSliceList{}
		if err := cl.List(ctx, epsList, client.InNamespace(ns),
			client.MatchingLabels(egressSvcChildResourceLabels(svc))); err != nil {
			logger.Infof("error listing EndpointSlices: %v, skipping a reconcile for event on Service %s", err, svc.Name)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		for _, eps := range epsList.Items {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: eps.Namespace,
					Name:      eps.Name,
				},
			})
		}
		return reqs
	}
}

func podsFromEgressEps(cl client.Client, logger *zap.SugaredLogger, ns string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		eps, ok := o.(*discoveryv1.EndpointSlice)
		if !ok {
			logger.Warn("EndpointSlice handler triggered for an object that is not a EndpointSlice")
			return nil
		}

		if eps.Labels[reconciler.LabelProxyGroup] == "" {
			return nil
		}
		if eps.Labels[labelSvcType] != "egress" {
			return nil
		}
		podLabels := reconciler.ProxyGroupLabels(eps.Labels[reconciler.LabelProxyGroup], nil)
		podList := &corev1.PodList{}
		if err := cl.List(ctx, podList, client.InNamespace(ns),
			client.MatchingLabels(podLabels)); err != nil {
			logger.Infof("error listing EndpointSlices: %v, skipping a reconcile for event on EndpointSlice %s", err, eps.Name)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		for _, pod := range podList.Items {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: pod.Namespace,
					Name:      pod.Name,
				},
			})
		}
		return reqs
	}
}

// indexEgressServices adds a local index to cached Tailscale egress Services meant to be exposed on a ProxyGroup. The
// index is used a list filter.
func indexEgressServices(o client.Object) []string {
	if !isEgressSvcForProxyGroup(o) {
		return nil
	}
	return []string{o.GetAnnotations()[reconciler.AnnotationProxyGroup]}
}
