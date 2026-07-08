// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

import (
	"fmt"
	"net/netip"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
)

func configSecretName(prName string, idx int32) string {
	return fmt.Sprintf("%s-%d-config", prName, idx)
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

func (r *Reconciler) peerRelayStatefulSet(pr *tsapi.PeerRelay, replicas int32) *appsv1.StatefulSet {
	labels := peerRelayLabels(pr.Name)
	return tailscaled.NewStatefulSet(tailscaled.StatefulSetOptions{
		Name:      pr.Name,
		Namespace: r.tailscaleNamespace,
		Labels:    labels,
		Image:     r.proxyImage,
		Replicas:  replicas,
		ConfigSecretNameFunc: func(idx int32) string {
			return configSecretName(pr.Name, idx)
		},
	})
}
