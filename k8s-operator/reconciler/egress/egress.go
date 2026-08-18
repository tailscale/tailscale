// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package egress provides the reconcilers that expose tailnet targets to cluster workloads via an egress ProxyGroup.
//
// A user creates an ExternalName Service annotated with a tailnet target and a ProxyGroup. Four controllers then
// cooperate to make that target reachable:
//
//   - Reconciler owns the user's ExternalName Service. It allocates a container port per Service port, creates a
//     ClusterIP Service holding those portmappings, and writes the egress config the ProxyGroup's proxies read.
//   - EndpointSliceReconciler keeps the ClusterIP Service's EndpointSlices pointing at the proxy Pods that are
//     currently able to route traffic to the target.
//   - ReadinessReconciler surfaces, on the user's Service, whether any proxy is actually ready to route to it.
//   - PodReconciler gates proxy Pod readiness on the Pod having set up routing for its egress services, so that a
//     rolling restart doesn't black-hole traffic.
//
// They are separate controllers rather than one because they watch different resources and must make progress
// independently; they share this package because they read and write the same egress config and labels.
package egress

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
)

const (
	// shortRequeue is how long to wait before retrying a reconcile that is waiting on state it doesn't control, e.g.
	// a proxy Pod finishing its routing setup.
	shortRequeue = 5 * time.Second

	// labelProxyGroup names the ProxyGroup that a managed resource belongs to.
	labelProxyGroup = "tailscale.com/proxy-group"

	// labelSvcType distinguishes ingress from egress managed resources.
	labelSvcType = "tailscale.com/svc-type"
	typeEgress   = "egress"

	// parentTypeSvc is the LabelParentType value used for resources owned by a user-created Service.
	parentTypeSvc = "svc"

	// proxyTypeProxyGroup is the LabelParentType value carried by ProxyGroup-owned Pods.
	proxyTypeProxyGroup = "proxygroup"

	// tsHealthCheckPortName names the port on the ClusterIP Service that proxies serve containerboot's health check
	// endpoint on. It is excluded from the egress config, which only describes user-facing ports.
	tsHealthCheckPortName = "tailscale-health-check"

	// maxPorts is the maximum number of ports that can be exposed on a
	// container. In practice this will be ports in range [10000 - 11000). The
	// high range should make it easier to distinguish container ports from
	// the tailnet target ports for debugging purposes (i.e when reading
	// netfilter rules). The limit of 1000 is somewhat arbitrary, the
	// assumption is that this would not be hit in practice.
	maxPorts = 1000
)

// CMName returns the name of the ConfigMap holding the egress service configs for the named ProxyGroup. The
// ProxyGroup reconciler creates it; the egress reconcilers read and update it.
func CMName(pg string) string {
	return fmt.Sprintf("%s-egress-config", pg)
}

// childResourceLabels returns the labels applied to the ClusterIP Service and EndpointSlices created for the egress
// service backing svc.
//
// TODO(irbekrm): we currently set a bunch of labels based on Kubernetes
// resource names (ProxyGroup, Service). Maximum allowed label length is 63
// chars whilst the maximum allowed resource name length is 253 chars, so we
// should probably validate and truncate (?) the names is they are too long.
func childResourceLabels(svc *corev1.Service) map[string]string {
	return map[string]string{
		kubetypes.LabelManaged:          "true",
		reconciler.LabelParentType:      parentTypeSvc,
		reconciler.LabelParentName:      svc.Name,
		reconciler.LabelParentNamespace: svc.Namespace,
		labelProxyGroup:                 svc.Annotations[reconciler.AnnotationProxyGroup],
		labelSvcType:                    typeEgress,
	}
}

// epsLabels returns the labels for an EndpointSlice created for an egress service, which are the child resource
// labels plus the two labels that make kube-proxy route ClusterIP Service traffic to this slice's endpoints.
func epsLabels(extNSvc, clusterIPSvc *corev1.Service) map[string]string {
	lbls := childResourceLabels(extNSvc)
	// Adding this label is what makes kube proxy set up rules to route traffic sent to the clusterIP Service to the
	// endpoints defined on this EndpointSlice.
	// https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	lbls[discoveryv1.LabelServiceName] = clusterIPSvc.Name
	// Kubernetes recommends setting this label.
	// https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#management
	lbls[discoveryv1.LabelManagedBy] = "tailscale.com"
	return lbls
}

// tailnetSvcName returns the name used to distinguish the tailnet service exposed via extNSvc from the other tailnet
// services exposed to cluster workloads. It keys the egress config.
func tailnetSvcName(extNSvc *corev1.Service) string {
	return fmt.Sprintf("%s-%s", extNSvc.Namespace, extNSvc.Name)
}
