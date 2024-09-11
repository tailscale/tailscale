// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation-
// they will appear on the Connector CRD i.e if someone runs kubectl explain connector.

var ConnectorKind = "Connector"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cn
// +kubebuilder:printcolumn:name="SubnetRoutes",type="string",JSONPath=`.status.subnetRoutes`,description="CIDR ranges exposed to tailnet by a subnet router defined via this Connector instance."
// +kubebuilder:printcolumn:name="IsExitNode",type="string",JSONPath=`.status.isExitNode`,description="Whether this Connector instance defines an exit node."
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "ConnectorReady")].reason`,description="Status of the deployed Connector resources."

// Connector defines a Tailscale node that will be deployed in the cluster. The
// node can be configured to act as a Tailscale subnet router and/or a Tailscale
// exit node.
// Connector is a cluster-scoped resource.
// More info:
// https://tailscale.com/kb/1236/kubernetes-operator#deploying-exit-nodes-and-subnet-routers-on-kubernetes-using-connector-custom-resource
type Connector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// ConnectorSpec describes the desired Tailscale component.
	// More info:
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec ConnectorSpec `json:"spec"`

	// ConnectorStatus describes the status of the Connector. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status ConnectorStatus `json:"status"`
}

// +kubebuilder:object:root=true

type ConnectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Connector `json:"items"`
}

// ConnectorSpec describes a Tailscale node to be deployed in the cluster.
// +kubebuilder:validation:XValidation:rule="has(self.subnetRouter) || self.exitNode == true",message="A Connector needs to be either an exit node or a subnet router, or both."
type ConnectorSpec struct {
	// Tags that the Tailscale node will be tagged with.
	// Defaults to [tag:k8s].
	// To autoapprove the subnet routes or exit node defined by a Connector,
	// you can configure Tailscale ACLs to give these tags the necessary
	// permissions.
	// See https://tailscale.com/kb/1018/acls/#auto-approvers-for-routes-and-exit-nodes.
	// If you specify custom tags here, you must also make the operator an owner of these tags.
	// See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.
	// Tags cannot be changed once a Connector node has been created.
	// Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$.
	// +optional
	Tags Tags `json:"tags,omitempty"`
	// Hostname is the tailnet hostname that should be assigned to the
	// Connector node. If unset, hostname defaults to <connector
	// name>-connector. Hostname can contain lower case letters, numbers and
	// dashes, it must not start or end with a dash and must be between 2
	// and 63 characters long.
	// +optional
	Hostname Hostname `json:"hostname,omitempty"`
	// ProxyClass is the name of the ProxyClass custom resource that
	// contains configuration options that should be applied to the
	// resources created for this Connector. If unset, the operator will
	// create resources with the default configuration.
	// +optional
	ProxyClass string `json:"proxyClass,omitempty"`
	// SubnetRouter defines subnet routes that the Connector node should
	// expose to tailnet. If unset, none are exposed.
	// https://tailscale.com/kb/1019/subnets/
	// +optional
	SubnetRouter *SubnetRouter `json:"subnetRouter"`
	// ExitNode defines whether the Connector node should act as a
	// Tailscale exit node. Defaults to false.
	// https://tailscale.com/kb/1103/exit-nodes
	// +optional
	ExitNode bool `json:"exitNode"`
}

// SubnetRouter defines subnet routes that should be exposed to tailnet via a
// Connector node.
type SubnetRouter struct {
	// AdvertiseRoutes refer to CIDRs that the subnet router should make
	// available. Route values must be strings that represent a valid IPv4
	// or IPv6 CIDR range. Values can be Tailscale 4via6 subnet routes.
	// https://tailscale.com/kb/1201/4via6-subnets/
	AdvertiseRoutes Routes `json:"advertiseRoutes"`
}

type Tags []Tag

func (tags Tags) Stringify() []string {
	stringTags := make([]string, len(tags))
	for i, t := range tags {
		stringTags[i] = string(t)
	}
	return stringTags
}

// +kubebuilder:validation:MinItems=1
type Routes []Route

func (routes Routes) Stringify() string {
	if len(routes) < 1 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(string(routes[0]))
	for _, r := range routes[1:] {
		sb.WriteString(fmt.Sprintf(",%s", r))
	}
	return sb.String()
}

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=cidr
type Route string

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Pattern=`^tag:[a-zA-Z][a-zA-Z0-9-]*$`
type Tag string

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`
type Hostname string

// ConnectorStatus defines the observed state of the Connector.
type ConnectorStatus struct {
	// List of status conditions to indicate the status of the Connector.
	// Known condition types are `ConnectorReady`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions"`
	// SubnetRoutes are the routes currently exposed to tailnet via this
	// Connector instance.
	// +optional
	SubnetRoutes string `json:"subnetRoutes"`
	// IsExitNode is set to true if the Connector acts as an exit node.
	// +optional
	IsExitNode bool `json:"isExitNode"`
	// TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)
	// assigned to the Connector node.
	// +optional
	TailnetIPs []string `json:"tailnetIPs,omitempty"`
	// Hostname is the fully qualified domain name of the Connector node.
	// If MagicDNS is enabled in your tailnet, it is the MagicDNS name of the
	// node.
	// +optional
	Hostname string `json:"hostname,omitempty"`
}

type ConditionType string

const (
	ConnectorReady  ConditionType = `ConnectorReady`
	ProxyClassready ConditionType = `ProxyClassReady`
	ProxyReady      ConditionType = `TailscaleProxyReady` // a Tailscale-specific condition type for corev1.Service
	RecorderReady   ConditionType = `RecorderReady`
)
