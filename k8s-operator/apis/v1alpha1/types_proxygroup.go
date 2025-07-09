// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=pg
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "ProxyGroupReady")].reason`,description="Status of the deployed ProxyGroup resources."
// +kubebuilder:printcolumn:name="Type",type="string",JSONPath=`.spec.type`,description="ProxyGroup type."
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ProxyGroup defines a set of Tailscale devices that will act as proxies.
// Currently only egress ProxyGroups are supported.
//
// Use the tailscale.com/proxy-group annotation on a Service to specify that
// the egress proxy should be implemented by a ProxyGroup instead of a single
// dedicated proxy. In addition to running a highly available set of proxies,
// ProxyGroup also allows for serving many annotated Services from a single
// set of proxies to minimise resource consumption.
//
// More info: https://tailscale.com/kb/1438/kubernetes-operator-cluster-egress
type ProxyGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired ProxyGroup instances.
	Spec ProxyGroupSpec `json:"spec"`

	// ProxyGroupStatus describes the status of the ProxyGroup resources. This is
	// set and managed by the Tailscale operator.
	// +optional
	Status ProxyGroupStatus `json:"status"`
}

// +kubebuilder:object:root=true

type ProxyGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ProxyGroup `json:"items"`
}

type ProxyGroupSpec struct {
	// Type of the ProxyGroup proxies. Supported types are egress, ingress, and kube-apiserver.
	// Type is immutable once a ProxyGroup is created.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="ProxyGroup type is immutable"
	Type ProxyGroupType `json:"type"`

	// Tags that the Tailscale devices will be tagged with. Defaults to [tag:k8s].
	// If you specify custom tags here, make sure you also make the operator
	// an owner of these tags.
	// See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.
	// Tags cannot be changed once a ProxyGroup device has been created.
	// Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$.
	// +optional
	Tags Tags `json:"tags,omitempty"`

	// Replicas specifies how many replicas to create the StatefulSet with.
	// Defaults to 2.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Replicas *int32 `json:"replicas,omitempty"`

	// HostnamePrefix is the hostname prefix to use for tailnet devices created
	// by the ProxyGroup. Each device will have the integer number from its
	// StatefulSet pod appended to this prefix to form the full hostname.
	// HostnamePrefix can contain lower case letters, numbers and dashes, it
	// must not start with a dash and must be between 1 and 62 characters long.
	// +optional
	HostnamePrefix HostnamePrefix `json:"hostnamePrefix,omitempty"`

	// ProxyClass is the name of the ProxyClass custom resource that contains
	// configuration options that should be applied to the resources created
	// for this ProxyGroup. If unset, and there is no default ProxyClass
	// configured, the operator will create resources with the default
	// configuration.
	// +optional
	ProxyClass string `json:"proxyClass,omitempty"`

	// KubeAPIServer contains configuration specific to the kube-apiserver
	// ProxyGroup type. This field is only used when Type is set to "kube-apiserver".
	// +optional
	KubeAPIServer *KubeAPIServerConfig `json:"kubeAPIServer,omitempty"`
}

type ProxyGroupStatus struct {
	// List of status conditions to indicate the status of the ProxyGroup
	// resources. Known condition types are `ProxyGroupReady`, `ProxyGroupAvailable`.
	// `ProxyGroupReady` indicates all ProxyGroup resources are fully reconciled
	// and ready. `ProxyGroupAvailable` indicates that at least one proxy is
	// ready to serve traffic.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// List of tailnet devices associated with the ProxyGroup StatefulSet.
	// +listType=map
	// +listMapKey=hostname
	// +optional
	Devices []TailnetDevice `json:"devices,omitempty"`
}

type TailnetDevice struct {
	// Hostname is the fully qualified domain name of the device.
	// If MagicDNS is enabled in your tailnet, it is the MagicDNS name of the
	// node.
	Hostname string `json:"hostname"`

	// TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)
	// assigned to the device.
	// +optional
	TailnetIPs []string `json:"tailnetIPs,omitempty"`

	// StaticEndpoints are user configured, 'static' endpoints by which tailnet peers can reach this device.
	// +optional
	StaticEndpoints []string `json:"staticEndpoints,omitempty"`
}

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Enum=egress;ingress;kube-apiserver
type ProxyGroupType string

const (
	ProxyGroupTypeEgress              ProxyGroupType = "egress"
	ProxyGroupTypeIngress             ProxyGroupType = "ingress"
	ProxyGroupTypeKubernetesAPIServer ProxyGroupType = "kube-apiserver"
)

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Enum=auth;noauth
type APIServerProxyMode string

const (
	APIServerProxyModeAuth   APIServerProxyMode = "auth"
	APIServerProxyModeNoAuth APIServerProxyMode = "noauth"
)

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9-]{0,61}$`
type HostnamePrefix string

// KubeAPIServerConfig contains configuration specific to the kube-apiserver ProxyGroup type.
type KubeAPIServerConfig struct {
	// Mode to run the API server proxy in. Supported modes are auth and noauth.
	// In auth mode, requests from the tailnet proxied over to the Kubernetes
	// API server are additionally impersonated using the sender's tailnet identity.
	// If not specified, defaults to auth mode.
	// +optional
	Mode *APIServerProxyMode `json:"mode,omitempty"`
}
