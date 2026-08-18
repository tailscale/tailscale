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

// IndexProxyGroup is the field index name under which egress Services are indexed by the ProxyGroup they are exposed
// on, so that a ProxyGroup event can enqueue every Service it serves. Reconciler.Register installs it.
const IndexProxyGroup = ".metadata.annotations.egress-proxy-group"

// serviceHandler returns accepts a Kubernetes object and returns a reconcile
// request for it , if the object is a Tailscale egress Service meant to be
// exposed on a ProxyGroup.
func serviceHandler(_ context.Context, o client.Object) []reconcile.Request {
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

// servicesFromProxyGroup is an event handler for egress ProxyGroups. It returns reconcile requests for all
// user-created ExternalName Services that should be exposed on this ProxyGroup.
func servicesFromProxyGroup(cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
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
		if err := cl.List(ctx, svcList, client.MatchingFields{IndexProxyGroup: pg.Name}); err != nil {
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

// serviceFromEndpointSlice is an event handler for EndpointSlices. If an EndpointSlice is for an egress ExternalName Service
// meant to be exposed on a ProxyGroup, returns a reconcile request for the Service.
func serviceFromEndpointSlice(_ context.Context, o client.Object) []reconcile.Request {
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

// endpointSliceHandler returns accepts an EndpointSlice and, if the EndpointSlice
// is for an egress service, returns a reconcile request for it.
func endpointSliceHandler(_ context.Context, o client.Object) []reconcile.Request {
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

// egressEpsFromEgressPods returns a Pod event handler that checks if Pod is a replica for a ProxyGroup and if it is,
// returns reconciler requests for all egress EndpointSlices for that ProxyGroup.
func endpointSlicesFromPods(cl client.Client, ns string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		if v, ok := o.GetLabels()[kubetypes.LabelManaged]; !ok || v != "true" {
			return nil
		}
		// TODO(irbekrm): for now this is good enough as all ProxyGroups are egress. Add a type check once we
		// have ingress ProxyGroups.
		if typ := o.GetLabels()[reconciler.LabelParentType]; typ != "proxygroup" {
			return nil
		}
		pg, ok := o.GetLabels()[reconciler.LabelParentName]
		if !ok {
			return nil
		}
		return endpointSliceRequestsForProxyGroup(ctx, pg, cl, ns)
	}
}

// endpointSlicesFromStateSecrets returns a Secret event handler that checks if Secret is a state Secret for a ProxyGroup and if it is,
// returns reconciler requests for all egress EndpointSlices for that ProxyGroup.
func endpointSlicesFromStateSecrets(cl client.Client, ns string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		if v, ok := o.GetLabels()[kubetypes.LabelManaged]; !ok || v != "true" {
			return nil
		}
		if parentType := o.GetLabels()[reconciler.LabelParentType]; parentType != "proxygroup" {
			return nil
		}
		if secretType := o.GetLabels()[kubetypes.LabelSecretType]; secretType != kubetypes.LabelSecretTypeState {
			return nil
		}
		pg, ok := o.GetLabels()[reconciler.LabelParentName]
		if !ok {
			return nil
		}
		return endpointSliceRequestsForProxyGroup(ctx, pg, cl, ns)
	}
}

// endpointSlicesFromExternalNameService is an event handler for ExternalName Services that define a Tailscale egress service that
// should be exposed on a ProxyGroup. It returns reconcile requests for EndpointSlices created for this Service.
func endpointSlicesFromExternalNameService(cl client.Client, logger *zap.SugaredLogger, ns string) handler.MapFunc {
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
			client.MatchingLabels(childResourceLabels(svc))); err != nil {
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

func podsFromEndpointSlices(cl client.Client, logger *zap.SugaredLogger, ns string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		eps, ok := o.(*discoveryv1.EndpointSlice)
		if !ok {
			logger.Warn("EndpointSlice handler triggered for an object that is not a EndpointSlice")
			return nil
		}

		if eps.Labels[labelProxyGroup] == "" {
			return nil
		}
		if eps.Labels[labelSvcType] != "egress" {
			return nil
		}
		podLabels := map[string]string{
			kubetypes.LabelManaged:     "true",
			reconciler.LabelParentType: "proxygroup",
			reconciler.LabelParentName: eps.Labels[labelProxyGroup],
		}
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

func podHandler(_ context.Context, o client.Object) []reconcile.Request {
	if typ := o.GetLabels()[reconciler.LabelParentType]; typ != proxyTypeProxyGroup {
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

// IndexServices adds a local index to cached Tailscale egress Services meant to be exposed on a ProxyGroup. The
// index is used a list filter.
func IndexServices(o client.Object) []string {
	if !isEgressSvcForProxyGroup(o) {
		return nil
	}
	return []string{o.GetAnnotations()[reconciler.AnnotationProxyGroup]}
}

func endpointSliceRequestsForProxyGroup(ctx context.Context, pg string, cl client.Client, ns string) []reconcile.Request {
	epsList := discoveryv1.EndpointSliceList{}
	if err := cl.List(ctx, &epsList,
		client.InNamespace(ns),
		client.MatchingLabels(map[string]string{labelProxyGroup: pg})); err != nil {
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
