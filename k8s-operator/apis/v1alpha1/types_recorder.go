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
// +kubebuilder:resource:scope=Cluster,shortName=rec
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "RecorderReady")].reason`,description="Status of the deployed Recorder resources."
// +kubebuilder:printcolumn:name="URL",type="string",JSONPath=`.status.devices[?(@.url != "")].url`,description="URL on which the UI is exposed if enabled."

type Recorder struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired recorder instance.
	Spec RecorderSpec `json:"spec"`

	// RecorderStatus describes the status of the recorder. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status RecorderStatus `json:"status"`
}

// +kubebuilder:object:root=true

type RecorderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Recorder `json:"items"`
}

type RecorderSpec struct {
	// Configuration parameters for the Recorder's StatefulSet. The operator
	// deploys a StatefulSet for each Recorder resource.
	// +optional
	StatefulSet RecorderStatefulSet `json:"statefulSet"`

	// Tags that the Tailscale device will be tagged with. Defaults to [tag:k8s].
	// If you specify custom tags here, make sure you also make the operator
	// an owner of these tags.
	// See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.
	// Tags cannot be changed once a Recorder node has been created.
	// Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$.
	// +optional
	Tags Tags `json:"tags,omitempty"`

	// TODO(tomhjp): Support a hostname or hostname prefix field, depending on
	// the plan for multiple replicas.

	// Set to true to enable the Recorder UI. The UI lists and plays recorded sessions.
	// The UI will be served at <MagicDNS name of the recorder>:443. Defaults to false.
	// Corresponds to --ui tsrecorder flag https://tailscale.com/kb/1246/tailscale-ssh-session-recording#deploy-a-recorder-node.
	// Required if S3 storage is not set up, to ensure that recordings are accessible.
	// +optional
	EnableUI bool `json:"enableUI,omitempty"`

	// Configure where to store session recordings. By default, recordings will
	// be stored in a local ephemeral volume, and will not be persisted past the
	// lifetime of a specific pod.
	// +optional
	Storage Storage `json:"storage,omitempty"`
}

type RecorderStatefulSet struct {
	// Labels that will be added to the StatefulSet created for the Recorder.
	// Any labels specified here will be merged with the default labels applied
	// to the StatefulSet by the operator.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations that will be added to the StatefulSet created for the Recorder.
	// Any Annotations specified here will be merged with the default annotations
	// applied to the StatefulSet by the operator.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Configuration for pods created by the Recorder's StatefulSet.
	// +optional
	Pod RecorderPod `json:"pod,omitempty"`
}

type RecorderPod struct {
	// Labels that will be added to Recorder Pods. Any labels specified here
	// will be merged with the default labels applied to the Pod by the operator.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations that will be added to Recorder Pods. Any annotations
	// specified here will be merged with the default annotations applied to
	// the Pod by the operator.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Affinity rules for Recorder Pods. By default, the operator does not
	// apply any affinity rules.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#affinity
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// Configuration for the Recorder container running tailscale.
	// +optional
	Container RecorderContainer `json:"container,omitempty"`

	// Security context for Recorder Pods. By default, the operator does not
	// apply any Pod security context.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context-2
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// Image pull Secrets for Recorder Pods.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#PodSpec
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Node selector rules for Recorder Pods. By default, the operator does
	// not apply any node selector rules.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for Recorder Pods. By default, the operator does not apply
	// any tolerations.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

type RecorderContainer struct {
	// List of environment variables to set in the container.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#environment-variables
	// Note that environment variables provided here will take precedence
	// over Tailscale-specific environment variables set by the operator,
	// however running proxies with custom values for Tailscale environment
	// variables (i.e TS_USERSPACE) is not recommended and might break in
	// the future.
	// +optional
	Env []Env `json:"env,omitempty"`

	// Container image name including tag. Defaults to docker.io/tailscale/tsrecorder
	// with the same tag as the operator, but the official images are also
	// available at ghcr.io/tailscale/tsrecorder.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image
	// +optional
	Image string `json:"image,omitempty"`

	// Image pull policy. One of Always, Never, IfNotPresent. Defaults to Always.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image
	// +kubebuilder:validation:Enum=Always;Never;IfNotPresent
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// Container resource requirements.
	// By default, the operator does not apply any resource requirements. The
	// amount of resources required wil depend on the volume of recordings sent.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#resources
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Container security context. By default, the operator does not apply any
	// container security context.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context
	// +optional
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`
}

type Storage struct {
	// Configure an S3-compatible API for storage. Required if the UI is not
	// enabled, to ensure that recordings are accessible.
	// +optional
	S3 *S3 `json:"s3,omitempty"`
}

type S3 struct {
	// S3-compatible endpoint, e.g. s3.us-east-1.amazonaws.com.
	Endpoint string `json:"endpoint,omitempty"`

	// Bucket name to write to. The bucket is expected to be used solely for
	// recordings, as there is no stable prefix for written object names.
	Bucket string `json:"bucket,omitempty"`

	// Configure environment variable credentials for managing objects in the
	// configured bucket. If not set, tsrecorder will try to acquire credentials
	// first from the file system and then the STS API.
	// +optional
	Credentials S3Credentials `json:"credentials,omitempty"`
}

type S3Credentials struct {
	// Use a Kubernetes Secret from the operator's namespace as the source of
	// credentials.
	// +optional
	Secret S3Secret `json:"secret,omitempty"`
}

type S3Secret struct {
	// The name of a Kubernetes Secret in the operator's namespace that contains
	// credentials for writing to the configured bucket. Each key-value pair
	// from the secret's data will be mounted as an environment variable. It
	// should include keys for AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY if
	// using a static access key.
	//+optional
	Name string `json:"name,omitempty"`
}

type RecorderStatus struct {
	// List of status conditions to indicate the status of the Recorder.
	// Known condition types are `RecorderReady`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// List of tailnet devices associated with the Recorder statefulset.
	// +listType=map
	// +listMapKey=hostname
	// +optional
	Devices []TailnetDevice `json:"devices,omitempty"`
}

type TailnetDevice struct {
	// Hostname is the fully qualified domain name of the device.
	// If MagicDNS is enabled in your tailnet, it is the MagicDNS name of the
	// node.
	Hostname string `json:"hostname"`

	// TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)
	// assigned to the device.
	// +optional
	TailnetIPs []string `json:"tailnetIPs,omitempty"`

	// URL where the UI is available if enabled for replaying recordings. This
	// will be an HTTPS MagicDNS URL. You must be connected to the same tailnet
	// as the recorder to access it.
	// +optional
	URL string `json:"url,omitempty"`
}
