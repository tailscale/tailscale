// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ProxyClassKind = "ProxyClass"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=pc

type ProxyClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ProxyClassSpec `json:"spec"`

	// This would need status if we do any validation in operator. Ideally I
	// would like to validate with kubebuilder annots/CEL only
	// +optional
	// Status ProxyClassStatus `json:"status"`
}

// +kubebuilder:object:root=true

type ProxyClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ProxyClass `json:"items"`
}

type ProxyClassSpec struct {
	// +optional
	Service `json:"service,omitempty"`
	// +optional
	StatefulSet *StatefulSet `json:"statefulSet,omitempty"`
}

// Configuration for the headless Service, not actually used in this prototype,
// but is here to better illustrate the API structure
type Service struct {
	Labels map[string]string `json:"labels,omitempty"`
}

type StatefulSet struct {
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
	// +optional
	Pod *Pod `json:"pod,omitempty"`
}

type Pod struct {
	// Or should we just sync statefulset.labels, statefulset.annotations?
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
	// I don't want to embed the full PodTemplate as that contains a bunch
	// of fields that shouldn't be touched (namespace, type meta etc)
	// Here do a bunch of CEL validations (Host namespace should not be set etc)
	// merge containers?
	// merge init containers?
	// +optional
	Spec *corev1.PodSpec `json:"spec,omitempty"`
}
