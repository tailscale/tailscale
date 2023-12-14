// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation-
// they will appear on the Connector CRD i.e if someone runs kubectl explain connector.

var ConnectorKind = "Connector"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cn
// +kubebuilder:printcolumn:name="SubnetRoutes",type="string",JSONPath=`.status.subnetRouter.routes`,description="Cluster CIDR ranges exposed to tailnet via subnet router"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "ConnectorReady")].reason`,description="Status of the components deployed by the connector"

type Connector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Desired state of the Connector resource.
	Spec ConnectorSpec `json:"spec"`

	// Status of the Connector. This is set and managed by the Tailscale operator.
	// +optional
	Status ConnectorStatus `json:"status"`
}

// +kubebuilder:object:root=true

type ConnectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Connector `json:"items"`
}

// ConnectorSpec defines the desired state of a ConnectorSpec.
type ConnectorSpec struct {
	// SubnetRouter configures a Tailscale subnet router to be deployed in
	// the cluster. If unset no subnet router will be deployed.
	// https://tailscale.com/kb/1019/subnets/
	SubnetRouter *SubnetRouter `json:"subnetRouter"`
}

// SubnetRouter describes a subnet router.
// +kubebuilder:validation:XValidation:rule="has(self.tags) == has(oldSelf.tags)",message="Subnetrouter tags cannot be changed. Delete and redeploy the Connector if you need to change it."
type SubnetRouter struct {
	// Routes refer to in-cluster CIDRs that the subnet router should make
	// available. Route values must be strings that represent a valid IPv4
	// or IPv6 CIDR range. Values can be Tailscale 4via6 subnet routes.
	// https://tailscale.com/kb/1201/4via6-subnets/
	Routes []Route `json:"routes"`
	// Tags that the Tailscale node will be tagged with. If you want the
	// subnet router to be autoapproved, you can configure Tailscale ACLs to
	// autoapprove the subnetrouter's CIDRs for these tags.
	// See https://tailscale.com/kb/1018/acls/#auto-approvers-for-routes-and-exit-nodes
	// Defaults to tag:k8s.
	// If you specify custom tags here, you must also make tag:k8s-operator owner of the custom tag.
	// See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.
	// Tags cannot be changed once a Connector has been created.
	// Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$.
	// +optional
	Tags []Tag `json:"tags,omitempty"`
	// Hostname is the tailnet hostname that should be assigned to the
	// subnet router node. If unset hostname is defaulted to <connector
	// name>-subnetrouter. Hostname can contain lower case letters, numbers
	// and dashes, it must not start or end with a dash and must be between
	// 2 and 63 characters long.
	// +optional
	Hostname Hostname `json:"hostname,omitempty"`
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
	Conditions []ConnectorCondition `json:"conditions"`
	// SubnetRouter status is the current status of a subnet router
	// +optional
	SubnetRouter *SubnetRouterStatus `json:"subnetRouter"`
}

// SubnetRouter status is the current status of a subnet router if deployed
type SubnetRouterStatus struct {
	// Routes are the CIDRs currently exposed via subnet router
	Routes string `json:"routes"`
	// Ready is the ready status of the subnet router
	Ready metav1.ConditionStatus `json:"ready"`
	// Reason is the reason for the subnet router status
	Reason string `json:"reason"`
	// Message is a more verbose reason for the current subnet router status
	Message string `json:"message"`
}

// ConnectorCondition contains condition information for a Connector.
type ConnectorCondition struct {
	// Type of the condition, known values are (`SubnetRouterReady`).
	Type ConnectorConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status metav1.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`

	// If set, this represents the .metadata.generation that the condition was
	// set based upon.
	// For instance, if .metadata.generation is currently 12, but the
	// .status.condition[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the Connector.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ConnectorConditionType represents a Connector condition type
type ConnectorConditionType string

const (
	ConnectorReady ConnectorConditionType = `ConnectorReady`
)
