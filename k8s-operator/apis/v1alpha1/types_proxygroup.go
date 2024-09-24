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

type ProxyGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired ProxyGroup instances.
	Spec ProxyGroupSpec `json:"spec"`

	// ProxyGroupStatus describes the status of the ProxyGroup pods. This is
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
	Replicas int `json:"replicas,omitempty"`

	// ProxyClass is the name of the ProxyClass custom resource that
	// contains configuration options that should be applied to the
	// resources created for this ProxyGroup. If unset, the operator will
	// create resources with the default configuration.
	// +optional
	ProxyClass string `json:"proxyClass,omitempty"`
}

type ProxyGroupStatus struct {
	// List of status conditions to indicate the status of the ProxyGroup pods.
	// Known condition types are `ProxyGroupReady`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// List of tailnet devices associated with the ProxyGroup statefulset.
	// +listType=map
	// +listMapKey=hostname
	// +optional
	Devices []TailnetDevice `json:"devices,omitempty"`
}
