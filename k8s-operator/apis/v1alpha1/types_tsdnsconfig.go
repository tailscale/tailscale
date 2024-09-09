// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation-
// they will appear on the DNSConfig CRD i.e if someone runs kubectl explain dnsconfig.

var DNSConfigKind = "DNSConfig"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=dc
// +kubebuilder:printcolumn:name="NameserverIP",type="string",JSONPath=`.status.nameserver.ip`,description="Service IP address of the nameserver"

// DNSConfig can be deployed to cluster to make a subset of Tailscale MagicDNS
// names resolvable by cluster workloads. Use this if: A) you need to refer to
// tailnet services, exposed to cluster via Tailscale Kubernetes operator egress
// proxies by the MagicDNS names of those tailnet services (usually because the
// services run over HTTPS)
// B) you have exposed a cluster workload to the tailnet using Tailscale Ingress
// and you also want to refer to the workload from within the cluster over the
// Ingress's MagicDNS name (usually because you have some callback component
// that needs to use the same URL as that used by a non-cluster client on
// tailnet).
// When a DNSConfig is applied to a cluster, Tailscale Kubernetes operator will
// deploy a nameserver for ts.net DNS names and automatically populate it with records
// for any Tailscale egress or Ingress proxies deployed to that cluster.
// Currently you must manually update your cluster DNS configuration to add the
// IP address of the deployed nameserver as a ts.net stub nameserver.
// Instructions for how to do it:
// https://kubernetes.io/docs/tasks/administer-cluster/dns-custom-nameservers/#configuration-of-stub-domain-and-upstream-nameserver-using-coredns (for CoreDNS),
// https://cloud.google.com/kubernetes-engine/docs/how-to/kube-dns (for kube-dns).
// Tailscale Kubernetes operator will write the address of a Service fronting
// the nameserver to dsnconfig.status.nameserver.ip.
// DNSConfig is a singleton - you must not create more than one.
// NB: if you want cluster workloads to be able to refer to Tailscale Ingress
// using its MagicDNS name, you must also annotate the Ingress resource with
// tailscale.com/experimental-forward-cluster-traffic-via-ingress annotation to
// ensure that the proxy created for the Ingress listens on its Pod IP address.
// NB: Clusters where Pods get assigned IPv6 addresses only are currently not supported.
type DNSConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired DNS configuration.
	// More info:
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec DNSConfigSpec `json:"spec"`

	// Status describes the status of the DNSConfig. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status DNSConfigStatus `json:"status"`
}

// +kubebuilder:object:root=true

type DNSConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []DNSConfig `json:"items"`
}

type DNSConfigSpec struct {
	// Configuration for a nameserver that can resolve ts.net DNS names
	// associated with in-cluster proxies for Tailscale egress Services and
	// Tailscale Ingresses. The operator will always deploy this nameserver
	// when a DNSConfig is applied.
	Nameserver *Nameserver `json:"nameserver"`
}

type Nameserver struct {
	// Nameserver image. Defaults to tailscale/k8s-nameserver:unstable.
	// +optional
	Image *NameserverImage `json:"image,omitempty"`
}

type NameserverImage struct {
	// Repo defaults to tailscale/k8s-nameserver.
	// +optional
	Repo string `json:"repo,omitempty"`
	// Tag defaults to unstable.
	// +optional
	Tag string `json:"tag,omitempty"`
}

type DNSConfigStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions"`
	// Nameserver describes the status of nameserver cluster resources.
	// +optional
	Nameserver *NameserverStatus `json:"nameserver"`
}

type NameserverStatus struct {
	// IP is the ClusterIP of the Service fronting the deployed ts.net nameserver.
	// Currently you must manually update your cluster DNS config to add
	// this address as a stub nameserver for ts.net for cluster workloads to be
	// able to resolve MagicDNS names associated with egress or Ingress
	// proxies.
	// The IP address will change if you delete and recreate the DNSConfig.
	// +optional
	IP string `json:"ip"`
}

// NameserverReady is set to True if the nameserver has been successfully
// deployed to cluster.
const NameserverReady ConditionType = `NameserverReady`
