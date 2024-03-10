// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation-
// they will appear on the DNSConfig CRD i.e if someone runs kubectl explain dnsconfig.

var DNSConfigKind = "DNSConfig"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=dc
// +kubebuilder:printcolumn:name="NameserverIP",type="string",JSONPath=`.status.nameserverStatus.ip`,description="Service IP address of the nameserver"

type DNSConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DNSConfigSpec `json:"spec"`

	// +optional
	Status DNSConfigStatus `json:"status"`
}

// +kubebuilder:object:root=true

type DNSConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []DNSConfig `json:"items"`
}

type DNSConfigSpec struct {
	Nameserver *Nameserver `json:"nameserver"`
}

type Nameserver struct {
	// +optional
	Image *Image `json:"image,omitempty"`
}

type Image struct {
	// +optional
	Repo string `json:"repo,omitempty"`
	// +optional
	Tag string `json:"tag,omitempty"`
}

type DNSConfigStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []ConnectorCondition `json:"conditions"`
	// +optional
	NameserverStatus *NameserverStatus `json:"nameserverStatus"`
}

type NameserverStatus struct {
	// +optional
	IP string `json:"ip"`
}

const NameserverReady ConnectorConditionType = `NameserverReady`
