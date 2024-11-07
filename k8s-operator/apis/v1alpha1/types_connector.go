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
// +kubebuilder:printcolumn:name="IsAppConnector",type="string",JSONPath=`.status.isAppConnector`,description="Whether this Connector instance is an app connector."
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "ConnectorReady")].reason`,description="Status of the deployed Connector resources."

// Connector defines a Tailscale node that will be deployed in the cluster. The
// node can be configured to act as a Tailscale subnet router and/or a Tailscale
// exit node.
// Connector is a cluster-scoped resource.
// More info:
// https://tailscale.com/kb/1441/kubernetes-operator-connector
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
// +kubebuilder:validation:XValidation:rule="has(self.subnetRouter) || (has(self.exitNode) && self.exitNode == true) || has(self.appConnector)",message="A Connector needs to have at least one of exit node, subnet router or app connector configured."
// +kubebuilder:validation:XValidation:rule="!((has(self.subnetRouter) || (has(self.exitNode)  && self.exitNode == true)) && has(self.appConnector))",message="The appConnector field is mutually exclusive with exitNode and subnetRouter fields."
type ConnectorSpec struct {
	// Tags that the Tailscale node will be tagged with.
	// Defaults to [tag:k8s].
	// To autoapprove the subnet routes or exit node defined by a Connector,
	// you can configure Tailscale ACLs to give these tags the necessary
	// permissions.
	// See https://tailscale.com/kb/1337/acl-syntax#autoapprovers.
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
	// SubnetRouter defines subnet routes that the Connector device should
	// expose to tailnet as a Tailscale subnet router.
	// https://tailscale.com/kb/1019/subnets/
	// If this field is unset, the device does not get configured as a Tailscale subnet router.
	// This field is mutually exclusive with the appConnector field.
	// +optional
	SubnetRouter *SubnetRouter `json:"subnetRouter,omitempty"`
	// AppConnector defines whether the Connector device should act as a Tailscale app connector. A Connector that is
	// configured as an app connector cannot be a subnet router or an exit node. If this field is unset, the
	// Connector does not act as an app connector.
	// Note that you will need to manually configure the permissions and the domains for the app connector via the
	// Admin panel.
	// Note also that the main tested and supported use case of this config option is to deploy an app connector on
	// Kubernetes to access SaaS applications available on the public internet. Using the app connector to expose
	// cluster workloads or other internal workloads to tailnet might work, but this is not a use case that we have
	// tested or optimised for.
	// If you are using the app connector to access SaaS applications because you need a predictable egress IP that
	// can be whitelisted, it is also your responsibility to ensure that cluster traffic from the connector flows
	// via that predictable IP, for example by enforcing that cluster egress traffic is routed via an egress NAT
	// device with a static IP address.
	// https://tailscale.com/kb/1281/app-connectors
	// +optional
	AppConnector *AppConnector `json:"appConnector,omitempty"`
	// ExitNode defines whether the Connector device should act as a Tailscale exit node. Defaults to false.
	// This field is mutually exclusive with the appConnector field.
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

// AppConnector defines a Tailscale app connector node configured via Connector.
type AppConnector struct {
	// Routes are optional preconfigured routes for the domains routed via the app connector.
	// If not set, routes for the domains will be discovered dynamically.
	// If set, the app connector will immediately be able to route traffic using the preconfigured routes, but may
	// also dynamically discover other routes.
	// https://tailscale.com/kb/1332/apps-best-practices#preconfiguration
	// +optional
	Routes Routes `json:"routes"`
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
	// IsAppConnector is set to true if the Connector acts as an app connector.
	// +optional
	IsAppConnector bool `json:"isAppConnector"`
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
	ProxyClassReady ConditionType = `ProxyClassReady`
	ProxyGroupReady ConditionType = `ProxyGroupReady`
	ProxyReady      ConditionType = `TailscaleProxyReady` // a Tailscale-specific condition type for corev1.Service
	RecorderReady   ConditionType = `RecorderReady`
	// EgressSvcValid gets set on a user configured ExternalName Service that defines a tailnet target to be exposed
	// on a ProxyGroup.
	// Set to true if the user provided configuration is valid.
	EgressSvcValid ConditionType = `TailscaleEgressSvcValid`
	// EgressSvcConfigured gets set on a user configured ExternalName Service that defines a tailnet target to be exposed
	// on a ProxyGroup.
	// Set to true if the cluster resources for the service have been successfully configured.
	EgressSvcConfigured ConditionType = `TailscaleEgressSvcConfigured`
	// EgressSvcReady gets set on a user configured ExternalName Service that defines a tailnet target to be exposed
	// on a ProxyGroup.
	// Set to true if the service is ready to route cluster traffic.
	EgressSvcReady ConditionType = `TailscaleEgressSvcReady`
)
