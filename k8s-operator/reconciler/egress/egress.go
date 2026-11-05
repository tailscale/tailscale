// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package egress provides the reconcilers that expose tailnet targets to cluster workloads through an egress
// ProxyGroup.
//
// A user creates an ExternalName Service that is annotated with a tailnet target and a ProxyGroup. Four reconcilers
// then make that target reachable:
//
//   - Reconciler watches the user's ExternalName Service. It allocates a container port for each Service port,
//     creates a ClusterIP Service and EndpointSlices for those ports, and writes the egress service configuration
//     that the ProxyGroup proxies read.
//   - EndpointSliceReconciler keeps the endpoints of those EndpointSlices set to the proxy Pods that can route
//     traffic to the target.
//   - ReadinessReconciler sets the EgressSvcReady condition on the user's Service from the number of proxy Pods that
//     can route traffic to the target.
//   - PodReconciler sets the egress readiness gate condition on a proxy Pod once the Pod can route traffic to all
//     egress services of its ProxyGroup.
package egress

import (
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/tstime"
)

// shortRequeue is how long to wait before a reconcile that waits for a proxy Pod is retried.
const shortRequeue = 5 * time.Second

// ReconcilerOptions contains configuration values for the egress reconcilers. All four reconcilers in this package
// take the same options.
type ReconcilerOptions struct {
	// Client is used to interact with the Kubernetes API.
	Client client.Client
	// Recorder is used to emit Kubernetes events.
	Recorder record.EventRecorder
	// TailscaleNamespace is the namespace the operator is installed in. The ClusterIP Services, EndpointSlices and
	// ProxyGroup resources for egress services are in this namespace.
	TailscaleNamespace string
	// Logger is the logger to use for the reconcilers.
	Logger *zap.SugaredLogger
	// Clock is used to stamp condition transitions. Defaults to a real clock when unset.
	Clock tstime.Clock
}

// clockOrDefault returns clock, or a real clock if clock is nil.
func clockOrDefault(clock tstime.Clock) tstime.Clock {
	if clock == nil {
		return tstime.DefaultClock{}
	}
	return clock
}
