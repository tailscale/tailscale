// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation-
// they will appear on the Tailnet CRD i.e. if someone runs kubectl explain tailnet.

var TailnetKind = "Tailnet"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=tn
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "TailnetReady")].reason`,description="Status of the deployed Tailnet resources."

type Tailnet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// Spec describes the desired state of the Tailnet.
	// More info:
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec TailnetSpec `json:"spec"`

	// Status describes the status of the Tailnet. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status TailnetStatus `json:"status"`
}

// +kubebuilder:object:root=true

type TailnetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Tailnet `json:"items"`
}

type TailnetSpec struct {
	// URL of the control plane to be used by all resources managed by the operator using this Tailnet.
	// +optional
	LoginURL string `json:"loginUrl,omitempty"`
	// Denotes the location of the credentials to use for authenticating with this Tailnet.
	Credentials TailnetCredentials `json:"credentials"`
}

type TailnetCredentials struct {
	// The name of the secret containing the credentials used to authenticate with this Tailnet. The secret must always
	// contain a "client_id" field. To authenticate with a static OAuth client, also set "client_secret". To authenticate
	// via workload identity federation, set "audience" to the audience value expected by the Tailscale OAuth
	// client; the operator will mint a ServiceAccount token for itself with that audience and exchange it for an API
	// token. "client_secret" and "audience" are mutually exclusive.
	SecretName string `json:"secretName"`
}

type TailnetStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions"`
}

// TailnetReady is set to True if the Tailnet is available for use by operator workloads.
const TailnetReady ConditionType = `TailnetReady`
