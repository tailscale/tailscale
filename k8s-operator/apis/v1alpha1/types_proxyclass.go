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
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "ProxyClassReady")].reason`,description="Status of the ProxyClass."

type ProxyClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ProxyClassSpec `json:"spec"`

	// +optional
	Status ProxyClassStatus `json:"status"`
}

// +kubebuilder:object:root=true
type ProxyClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ProxyClass `json:"items"`
}

type ProxyClassSpec struct {
	// Proxy's StatefulSet spec.
	StatefulSet *StatefulSet `json:"statefulSet"`
}

type StatefulSet struct {
	// Labels that will be added to the StatefulSet created for the proxy.
	// Any labels specified here will be merged with the default labels
	// applied to the StatefulSet by the Tailscale Kubernetes operator as
	// well as any other labels that might have been applied by other
	// actors.
	// Label keys and values must be valid Kubernetes label keys and values.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations that will be added to the StatefulSet created for the proxy.
	// Any Annotations specified here will be merged with the default annotations
	// applied to the StatefulSet by the Tailscale Kubernetes operator as
	// well as any other annotations that might have been applied by other
	// actors.
	// Annotations must be valid Kubernetes annotations.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
	// Configuration for the proxy Pod.
	// +optional
	Pod *Pod `json:"pod,omitempty"`
}

type Pod struct {
	// Labels that will be added to the proxy Pod.
	// Any labels specified here will be merged with the default labels
	// applied to the Pod by the Tailscale Kubernetes operator.
	// Label keys and values must be valid Kubernetes label keys and values.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations that will be added to the proxy Pod.
	// Any annotations specified here will be merged with the default
	// annotations applied to the Pod by the Tailscale Kubernetes operator.
	// Annotations must be valid Kubernetes annotations.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
	// Configuration for the proxy container running tailscale.
	// +optional
	TailscaleContainer *Container `json:"tailscaleContainer,omitempty"`
	// Configuration for the proxy init container that enables forwarding.
	// +optional
	TailscaleInitContainer *Container `json:"tailscaleInitContainer,omitempty"`
	// Proxy Pod's security context.
	// By default Tailscale Kubernetes operator does not apply any Pod
	// security context.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context-2
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`
	// Proxy Pod's image pull Secrets.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#PodSpec
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// Proxy Pod's node name.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	NodeName string `json:"nodeName,omitempty"`
	// Proxy Pod's node selector.
	// By default Tailscale Kubernetes operator does not apply any node
	// selector.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Proxy Pod's tolerations.
	// By default Tailscale Kubernetes operator does not apply any
	// tolerations.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

type Container struct {
	// Container security context.
	// Security context specified here will override the security context by the operator.
	// By default the operator:
	// - sets 'privileged: true' for the init container
	// - set NET_ADMIN capability for tailscale container for proxies that
	// are created for Services or Connector.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context
	// +optional
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`
	// Container resource requirements.
	// By default Tailscale Kubernetes operator does not apply any resource
	// requirements. The amount of resources required wil depend on the
	// amount of resources the operator needs to parse, usage patterns and
	// cluster size.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#resources
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// List of environment variables to set in the container.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#environment-variables
	// Note that environment variables provided here will take precedence
	// over Tailscale-specific environment variables set by the operator,
	// however running proxies with custom values for Tailscale environment
	// variables (i.e TS_USERSPACE) is not recommended and might break in
	// the future.
	// +optional
	Env []Env `json:"env,omitempty"`
}

type Env struct {
	// Name of the environment variable. Must be a C_IDENTIFIER.
	Name Name `json:"name"`
	// Variable references $(VAR_NAME) are expanded using the previously defined
	//  environment variables in the container and any service environment
	// variables. If a variable cannot be resolved, the reference in the input
	// string will be unchanged. Double $$ are reduced to a single $, which
	// allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will
	// produce the string literal "$(VAR_NAME)". Escaped references will never
	// be expanded, regardless of whether the variable exists or not. Defaults
	// to "".
	// +optional
	Value string `json:"value,omitempty"`
}

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Pattern=`^[-._a-zA-Z][-._a-zA-Z0-9]*$`
type Name string

type ProxyClassStatus struct {
	// List of status conditions to indicate the status of the ProxyClass.
	// Known condition types are `ProxyClassReady`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []ConnectorCondition `json:"conditions,omitempty"`
}
