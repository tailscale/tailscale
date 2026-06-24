// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation-
// they will appear on the PeerRelay CRD i.e. if someone runs kubectl explain peerrelay.

var PeerRelayKind = "PeerRelay"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=pr
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "PeerRelayReady")].reason`,description="Status of the deployed PeerRelay resources."

type PeerRelay struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// Spec describes the desired state of the PeerRelay.
	// More info:
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec PeerRelaySpec `json:"spec"`

	// Status describes the status of the PeerRelay. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status PeerRelayStatus `json:"status"`
}

// +kubebuilder:object:root=true

type PeerRelayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []PeerRelay `json:"items"`
}

type PeerRelaySpec struct {
	// Tags that the Tailscale node will be tagged with.
	// Defaults to [tag:k8s].
	// To autoapprove the device defined by a PeerRelay,
	// you can configure Tailscale ACLs to give these tags the necessary
	// permissions.
	// See https://tailscale.com/kb/1337/acl-syntax#autoapprovers.
	// If you specify custom tags here, you must also make the operator an owner of these tags.
	// See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.
	// Tags cannot be changed once a PeerRelay node has been created.
	// Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$.
	// +optional
	Tags Tags `json:"tags,omitempty"`

	// HostnamePrefix specifies the hostname prefix for each
	// replica. Each device will have the integer number
	// from its StatefulSet pod appended to this prefix to form the full hostname.
	// HostnamePrefix can contain lower case letters, numbers and dashes, it
	// must not start with a dash and must be between 1 and 62 characters long.
	// +optional
	HostnamePrefix HostnamePrefix `json:"hostnamePrefix,omitzero"`

	// ProxyClass is the name of the ProxyClass custom resource that
	// contains configuration options that should be applied to the
	// resources created for this PeerRelay. If unset, the operator will
	// create resources with the default configuration.
	// +optional
	ProxyClass string `json:"proxyClass,omitempty"`

	// Replicas specifies how many devices to create. Set this to enable
	// high availability for peer relays.
	// https://tailscale.com/kb/1115/high-availability. Defaults to 1.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Replicas *int32 `json:"replicas,omitzero"`

	// Tailnet specifies the tailnet this PeerRelay should join. If blank, the default tailnet is used. When set, this
	// name must match that of a valid Tailnet resource. This field is immutable and cannot be changed once set.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="PeerRelay tailnet is immutable"
	Tailnet string `json:"tailnet,omitempty"`

	// Service contains configuration values to modify the LoadBalancer service used to expose the peer relay.
	// +optional
	Service *PeerRelayService `json:"service,omitzero"`
}

type PeerRelayService struct {
	// Annotations to apply to the LoadBalancer service. Any annotations that conflict with those used by known
	// cloud providers to ensure IP addresses rather than DNS names are ignored.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

type PeerRelayStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions"`
}

// PeerRelayReady is set to True if the PeerRelay is available for use by operator workloads.
const PeerRelayReady ConditionType = `PeerRelayReady`
