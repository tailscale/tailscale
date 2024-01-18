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

	// This would need status if we do any validation in operator.
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
	Annotations            map[string]string             `json:"annotations,omitempty"`
	TailscaleContainer     *Container                    `json:"tailscaleContainer,omitempty"`
	TailscaleInitContainer *Container                    `json:"tailscaleInitContainer,omitempty"`
	PodSecurityContext     *corev1.PodSecurityContext    `json:"podSecurityContext,omitempty"`
	ImagePullSecrets       []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	NodeName               string                        `json:"nodeName,omitempty"`
	NodeSelector           map[string]string             `json:"nodeSelector,omitempty"`
	Tolerations            []corev1.Toleration           `json:"tolerations,omitempty"`
	Patches                []Patch                       `json:"patches,omitempty"`
}

type Container struct {
	SecurityContext *corev1.SecurityContext     `json:"securityContext,omitempty"`
	Resources       corev1.ResourceRequirements `json:"resources,omitempty"`
}

// RFC 6902 JSON patch
type Patch struct {
	Path string `json:"path"`
	// +optional
	Value string `json:"value,omitempty"`
	Op    string `json:"op"`
}
