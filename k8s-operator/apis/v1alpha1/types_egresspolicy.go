// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ep

type EgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec contains a list of sources which should be able to access the tailscale devices via the ProxyGroup Pods.
	// Items in this list are combined using a logical OR operation.
	// If this field is present and contains at least one item, this rule
	// allows traffic only if the traffic matches at least one item in the from list.
	// +listType=atomic
	Spec []networkingv1.NetworkPolicyPeer `json:"spec"`

	// +optional
	// Status of the EgressPolicy. This is set and managed automatically.
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Status EgressPolicyStatus `json:"status"`
}

// +kubebuilder:object:root=true
type EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []EgressPolicy `json:"items"`
}

type EgressPolicyStatus struct {
	// Service to port mapping
	// +optional
	ServicePortMapping map[string]networkingv1.NetworkPolicyPort `json:"servicePortMapping,omitempty"`
}
