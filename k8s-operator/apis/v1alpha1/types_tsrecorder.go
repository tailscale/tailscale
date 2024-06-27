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
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "RecorderReady")].reason`,description="Status of the deployed TSRecorder resources."

type TSRecorder struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired recorder instance.
	Spec TSRecorderSpec `json:"spec"`

	// TSRecorderStatus describes the status of the recorder. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status TSRecorderStatus `json:"status"`
}

// +kubebuilder:object:root=true

type TSRecorderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []TSRecorder `json:"items"`
}

type TSRecorderSpec struct {
	// Tags that the Tailscale node will be tagged with. Defaults to [tag:k8s-recorder].
	// If you specify custom tags here, make sure you also make the operator
	// an owner of these tags.
	// See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.
	// Tags cannot be changed once a TSRecorder node has been created.
	// Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$.
	// +optional
	Tags Tags `json:"tags,omitempty"`

	// TODO(tomhjp): Support a hostname or hostname prefix field, depending on
	// the plan for multiple replicas.

	// TSRecorder image. Defaults to tailscale/tsrecorder, with the same tag as
	// the operator.
	// +optional
	Image Image `json:"image,omitempty"`

	// If enabled, TSRecorder will serve the UI with HTTPS on its MagicDNS hostname.
	// See --ui flag for more details: https://tailscale.com/kb/1246/tailscale-ssh-session-recording#deploy-a-recorder-node.
	// +optional
	EnableUI bool `json:"enableUI,omitempty"`

	// Additional volumes for the pod spec. May be useful if you want to use a
	// local file path for storage. For more details, see --dst flag:
	// https://tailscale.com/kb/1246/tailscale-ssh-session-recording#deploy-a-recorder-node.
	// +optional
	ExtraVolumes []corev1.Volume `json:"extraVolumes,omitempty"`

	// Additional volume mounts for the tsrecorder container. May be useful if
	// you want to use a local file path for storage. For more details, see
	// --dst flag: https://tailscale.com/kb/1246/tailscale-ssh-session-recording#deploy-a-recorder-node.
	// +optional
	ExtraVolumeMounts []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`

	// Configure where to store session recordings. Exactly one destination must
	// be configured.
	Storage Storage `json:"storage"`
}

type Storage struct {
	// TODO(tomhjp): S3 support

	// Configure a local file system storage destination. For more details, see
	// --dst flag: https://tailscale.com/kb/1246/tailscale-ssh-session-recording#deploy-a-recorder-node.
	// +optional
	File File `json:"file,omitempty"`
}

// File configures a local file system storage location for writing recordings to.
type File struct {
	// Directory specifies the directory on disk to write recordings to.
	// +optional
	Directory string `json:"directory,omitempty"`
}

type TSRecorderStatus struct {
	// List of status conditions to indicate the status of the TSRecorder.
	// Known condition types are `RecorderReady`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// List of tailnet devices associated with the TSRecorder statefulset.
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
}
