// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

import (
	"context"
	"fmt"
	"net/netip"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/kube/kubetypes"
)

func configSecretName(prName string, idx int32) string {
	return replicaName(prName, idx) + "-config"
}

func peerRelayHostname(pr *tsapi.PeerRelay, idx int32) string {
	prefix := string(pr.Spec.HostnamePrefix)
	if prefix == "" {
		prefix = pr.Name
	}
	return fmt.Sprintf("%s-%d", prefix, idx)
}

func peerRelayTailscaledConfig(pr *tsapi.PeerRelay, idx int32, endpoint *tsapi.PeerRelayEndpoint, authKey *string) ipn.ConfigVAlpha {
	conf := ipn.ConfigVAlpha{
		Version:         "alpha0",
		AcceptDNS:       "false",
		AcceptRoutes:    "false",
		Locked:          "false",
		Hostname:        new(peerRelayHostname(pr, idx)),
		RelayServerPort: new(uint16(servicePort)),
		AuthKey:         authKey,
	}

	if endpoint != nil {
		if addr, err := netip.ParseAddr(endpoint.Address); err == nil {
			conf.RelayServerStaticEndpoints = []netip.AddrPort{
				netip.AddrPortFrom(addr, uint16(endpoint.Port)),
			}
		}
	}

	return conf
}

func (r *Reconciler) peerRelayConfigSecret(pr *tsapi.PeerRelay, idx int32, endpoint *tsapi.PeerRelayEndpoint, authKey *string) (*corev1.Secret, error) {
	labels := peerRelayServiceLabels(pr.Name, idx)
	return tailscaled.NewConfigSecret(tailscaled.ConfigSecretOptions{
		Name:      configSecretName(pr.Name, idx),
		Namespace: r.tailscaleNamespace,
		Labels:    labels,
		Config:    peerRelayTailscaledConfig(pr, idx, endpoint, authKey),
	})
}

func (r *Reconciler) peerRelayStatefulSet(pr *tsapi.PeerRelay, replicas int32, pc *tsapi.ProxyClass) *appsv1.StatefulSet {
	labels := peerRelayLabels(pr.Name)
	ss := tailscaled.NewStatefulSet(tailscaled.StatefulSetOptions{
		Name:               resourceName(pr.Name),
		Namespace:          r.tailscaleNamespace,
		Labels:             labels,
		Image:              r.proxyImage,
		Replicas:           replicas,
		ServiceAccountName: "proxies",
		ConfigSecretNameFunc: func(idx int32) string {
			return configSecretName(pr.Name, idx)
		},
	})

	return tailscaled.ApplyProxyClass(ss, pc, managedLabelKeys, nil)
}

var managedLabelKeys = []string{
	kubetypes.LabelManaged,
	reconciler.LabelParentType,
	reconciler.LabelParentName,
}

func (r *Reconciler) getProxyClass(ctx context.Context, pr *tsapi.PeerRelay) (*tsapi.ProxyClass, error) {
	if pr.Spec.ProxyClass == "" {
		return nil, nil
	}

	var pc tsapi.ProxyClass
	if err := r.Get(ctx, types.NamespacedName{Name: pr.Spec.ProxyClass}, &pc); err != nil {
		return nil, fmt.Errorf("failed to get ProxyClass %q: %w", pr.Spec.ProxyClass, err)
	}
	return &pc, nil
}
