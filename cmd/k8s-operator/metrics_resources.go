// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"

	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
)

func reconcileMetricsResources(ctx context.Context, logger *zap.SugaredLogger, opts *metricsOpts, pc *tsapi.ProxyClass, cl client.Client) error {
	if opts.proxyType == proxyTypeEgress {
		// Metrics are currently not being enabled for standalone egress proxies.
		return nil
	}
	return tailscaled.EnsureMetricsResources(ctx, cl, logger, opts.metricsOptions(), pc)
}

// maybeCleanupMetricsResources ensures that any metrics resources created for a proxy are deleted.
func maybeCleanupMetricsResources(ctx context.Context, opts *metricsOpts, cl client.Client) error {
	return tailscaled.EnsureMetricsResourcesDeleted(ctx, cl, opts.metricsOptions())
}

type metricsOpts struct {
	proxyStsName string            // name of StatefulSet for proxy
	tsNamespace  string            // namespace in which Tailscale is installed
	proxyLabels  map[string]string // labels of the proxy StatefulSet
	proxyType    string
}

// metricsOptions converts opts for the tailscaled metrics helpers.
func (opts *metricsOpts) metricsOptions() tailscaled.MetricsOptions {
	mo := tailscaled.MetricsOptions{
		StatefulSetName: opts.proxyStsName,
		Namespace:       opts.tsNamespace,
		PodLabels:       opts.proxyLabels,
		ProxyType:       opts.proxyType,
		ParentName:      opts.proxyLabels[LabelParentName],
	}
	if isNamespacedProxyType(opts.proxyType) {
		mo.ParentNamespace = opts.proxyLabels[LabelParentNamespace]
	}
	return mo
}

func isNamespacedProxyType(typ string) bool {
	return typ == proxyTypeIngressResource || typ == proxyTypeIngressService
}
