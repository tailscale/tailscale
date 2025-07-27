// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=idp
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "IDPReady")].reason`,description="Status of the deployed IDP resources."
// +kubebuilder:printcolumn:name="URL",type="string",JSONPath=`.status.url`,description="URL where the OIDC provider is accessible."
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// IDP defines a Tailscale OpenID Connect Identity Provider instance.
// IDP is a cluster-scoped resource.
type IDP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired IDP instance.
	Spec IDPSpec `json:"spec"`

	// IDPStatus describes the status of the IDP. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status IDPStatus `json:"status"`
}

// +kubebuilder:object:root=true

type IDPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []IDP `json:"items"`
}

type IDPSpec struct {
	// Configuration parameters for the IDP's StatefulSet. The operator
	// deploys a StatefulSet for each IDP resource.
	// +optional
	StatefulSet IDPStatefulSet `json:"statefulSet"`

	// Tags that the Tailscale device will be tagged with. Defaults to [tag:k8s].
	// If you specify custom tags here, make sure you also make the operator
	// an owner of these tags.
	// See https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.
	// Tags cannot be changed once an IDP node has been created.
	// Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$.
	// +optional
	Tags Tags `json:"tags,omitempty"`

	// Hostname for the IDP instance. Defaults to "idp".
	// This will be used as the MagicDNS hostname.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	// +optional
	Hostname string `json:"hostname,omitempty"`

	// Enable Tailscale Funnel to make IDP available on the public internet.
	// When enabled, the IDP will be accessible via a public HTTPS URL.
	// Requires appropriate ACL configuration in your tailnet.
	// Cannot be used with custom ports.
	// Defaults to false.
	// +optional
	EnableFunnel bool `json:"enableFunnel,omitempty"`

	// Port to listen on for HTTPS traffic. Defaults to 443.
	// Must be 443 if EnableFunnel is true.
	// Common values: 443 (standard HTTPS), 8443 (alternative HTTPS).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`

	// LocalPort to listen on for HTTP traffic from localhost.
	// This can be useful for debugging or local client access.
	// The IDP will serve unencrypted HTTP on this port, accessible only from
	// the pod itself (localhost/127.0.0.1).
	// If not set, local access is disabled.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	LocalPort *int32 `json:"localPort,omitempty"`
}

type IDPStatefulSet struct {
	// Labels that will be added to the StatefulSet created for IDP.
	// Any labels specified here will be merged with the default labels applied
	// to the StatefulSet by the operator.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations that will be added to the StatefulSet created for IDP.
	// Any Annotations specified here will be merged with the default annotations
	// applied to the StatefulSet by the operator.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Configuration for pods created by the IDP's StatefulSet.
	// +optional
	Pod IDPPod `json:"pod,omitempty"`
}

type IDPPod struct {
	// Labels that will be added to IDP Pods. Any labels specified here
	// will be merged with the default labels applied to the Pod by the operator.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations that will be added to IDP Pods. Any annotations
	// specified here will be merged with the default annotations applied to
	// the Pod by the operator.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Affinity rules for IDP Pods. By default, the operator does not
	// apply any affinity rules.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#affinity
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// Configuration for the IDP container.
	// +optional
	Container IDPContainer `json:"container,omitempty"`

	// Security context for IDP Pods. By default, the operator does not
	// apply any Pod security context.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context-2
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// Image pull Secrets for IDP Pods.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#PodSpec
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Node selector rules for IDP Pods. By default, the operator does
	// not apply any node selector rules.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for IDP Pods. By default, the operator does not apply
	// any tolerations.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Config for the ServiceAccount to create for the IDP's StatefulSet.
	// By default, the operator will create a ServiceAccount with the same
	// name as the IDP resource.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#service-account
	// +optional
	ServiceAccount IDPServiceAccount `json:"serviceAccount,omitempty"`
}

type IDPServiceAccount struct {
	// Name of the ServiceAccount to create. Defaults to the name of the
	// IDP resource.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#service-account
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-.]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Name string `json:"name,omitempty"`

	// Annotations to add to the ServiceAccount.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

type IDPContainer struct {
	// List of environment variables to set in the container.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#environment-variables
	// Note that environment variables provided here will take precedence
	// over Tailscale-specific environment variables set by the operator.
	// +optional
	Env []Env `json:"env,omitempty"`

	// Container image name including tag. Defaults to the tsidp image
	// from the same source as the operator.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image
	// +optional
	Image string `json:"image,omitempty"`

	// Image pull policy. One of Always, Never, IfNotPresent. Defaults to Always.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image
	// +kubebuilder:validation:Enum=Always;Never;IfNotPresent
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// Container resource requirements.
	// By default, the operator does not apply any resource requirements.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#resources
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Container security context. By default, the operator does not apply any
	// container security context.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context
	// +optional
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`
}

type IDPStatus struct {
	// List of status conditions to indicate the status of IDP.
	// Known condition types are `IDPReady`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// URL where the OIDC provider is accessible.
	// This will be an HTTPS MagicDNS URL, or a public URL if Funnel is enabled.
	// +optional
	URL string `json:"url,omitempty"`

	// Hostname is the fully qualified domain name of the IDP device.
	// If MagicDNS is enabled in your tailnet, it is the MagicDNS name.
	// +optional
	Hostname string `json:"hostname,omitempty"`

	// TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)
	// assigned to the IDP device.
	// +optional
	TailnetIPs []string `json:"tailnetIPs,omitempty"`

	// ObservedGeneration is the last observed generation of the IDP resource.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}
