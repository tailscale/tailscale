// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation-
// they will appear on the ProxyGroupPolicy CRD i.e. if someone runs kubectl explain tailnet.

var ProxyGroupPolicyKind = "ProxyGroupPolicy"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=pgp
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

type ProxyGroupPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// Spec describes the desired state of the ProxyGroupPolicy.
	// More info:
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec ProxyGroupPolicySpec `json:"spec"`

	// Status describes the status of the ProxyGroupPolicy. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status ProxyGroupPolicyStatus `json:"status"`
}

// +kubebuilder:object:root=true

type ProxyGroupPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ProxyGroupPolicy `json:"items"`
}

type ProxyGroupPolicySpec struct {
	// Names of ProxyGroup resources that can be used by Ingress resources within this namespace. An empty list
	// denotes that no ingress via ProxyGroups is allowed within this namespace.
	// +optional
	Ingress []string `json:"ingress,omitempty"`

	// Names of ProxyGroup resources that can be used by Service resources within this namespace. An empty list
	// denotes that no egress via ProxyGroups is allowed within this namespace.
	// +optional
	Egress []string `json:"egress,omitempty"`
}

type ProxyGroupPolicyStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions"`
}
