// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation;
// they will appear on the ACLPolicy CRD.

var ACLPolicyKind = "ACLPolicy"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=acl
// +kubebuilder:printcolumn:name="Tailnet",type=string,JSONPath=`.spec.tailnetRef`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[?(@.type == "ACLPolicySynced")].reason`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ACLPolicy defines the desired Tailnet ACL (policy file) to be applied to a Tailnet.
// The operator syncs the policy from this resource to the Tailscale API using the
// Tailnet's OAuth credentials. The Tailnet's Secret must have OAuth scopes
// policy_file:read and policy_file.
//
// Only one ACLPolicy should target a given Tailnet. The policy can be provided
// inline (spec.policy) or from a ConfigMap/Secret (spec.policyFrom).
// See https://tailscale.com/kb/1018/acls and the Tailscale API policy file docs.
type ACLPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ACLPolicySpec   `json:"spec"`
	Status ACLPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type ACLPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ACLPolicy `json:"items"`
}

type ACLPolicySpec struct {
	// TailnetRef is the name of the Tailnet custom resource whose credentials
	// are used to get and set the ACL. The Tailnet must exist and be ready.
	TailnetRef string `json:"tailnetRef"`

	// Policy is the policy file content as JSON or HuJSON. Either Policy or
	// PolicyFrom must be set.
	// +optional
	Policy string `json:"policy,omitempty"`

	// PolicyFrom references a ConfigMap or Secret key containing the policy
	// file (JSON or HuJSON). The referenced object must exist in the same
	// namespace as the operator (Tailscale namespace).
	// +optional
	PolicyFrom *PolicySource `json:"policyFrom,omitempty"`
}

// PolicySource references a key in a ConfigMap or Secret.
type PolicySource struct {
	ConfigMapKeyRef *corev1.ConfigMapKeySelector `json:"configMapKeyRef,omitempty"`
	SecretKeyRef    *corev1.SecretKeySelector   `json:"secretKeyRef,omitempty"`
}

type ACLPolicyStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions"`

	// ETag is the last ETag returned by the Tailscale API for the policy file.
	// Used for safe updates (If-Match).
	// +optional
	ETag string `json:"etag,omitempty"`

	// LastSyncTime is the last time the policy was successfully synced.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
}

// ACLPolicySynced is set to True when the policy has been successfully applied to the Tailnet.
const ACLPolicySynced ConditionType = `ACLPolicySynced`
