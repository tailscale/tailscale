// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

var ClusterConfigKind = "ClusterConfig"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

type ClusterConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// More info:
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec ClusterConfigSpec `json:"spec"`

	// ClusterConfigStatus describes the status of the ClusterConfig. This
	// is set and managed by the Tailscale operator.
	// +optional
	Status ClusterConfigStatus `json:"status"`
}

type ClusterConfigSpec struct {
	// like 'foo.tailbd97a.ts.net' for services like
	// 'my-svc.foo.tailbd97a.ts.net'. Or, should be just 'foo'?
	Domain string `json:"domain"`

	// TODO: number of proxies + cidr should be under a class- different
	// classes should allow for different number of nodes

	// Hardcoded to 4 for this prototype
	// NumProxies int `json:"numProxies"`

	// Hardcoded to 100.64.2.0/24 for this prototype.
	// Question: is there a better way for users to allocate an unused CIDR
	// than forcing IPs for all other nodes to a different CIDR via
	// https://tailscale.com/kb/1304/ip-pool?
	// CIDRv4 string `json:"cidrv4"`

	// TODO: CIDRv6
}

type ClusterConfigStatus struct {
	ProxyNodes []ProxyNode `json:"proxyNodes"`
}

type ProxyNode struct {
	MagicDNSName string   `json:"magicDNSName"`
	TailnetIPs   []string `json:"tailnetIPs"`
	ServiceCIDR  string   `json:"serviceCIDR"`
}

// +kubebuilder:object:root=true

type ClusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterConfig `json:"items"`
}
