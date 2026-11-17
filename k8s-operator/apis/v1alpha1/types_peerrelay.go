// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation-
// they will appear on the PeerRelay CRD i.e. if someone runs kubectl explain peerrelay.

var PeerRelayKind = "PeerRelay"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=pr
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "PeerRelayReady")].reason`,description="Status of the deployed PeerRelay resources."
// +kubebuilder:printcolumn:name="Endpoints",type="string",JSONPath=`.status.endpoints[*].address`,description="Public addresses the peer relay replicas are reachable on."

type PeerRelay struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// Spec describes the desired state of the PeerRelay.
	// More info:
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec PeerRelaySpec `json:"spec"`

	// Status describes the status of the PeerRelay. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status PeerRelayStatus `json:"status"`
}

// +kubebuilder:object:root=true

type PeerRelayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []PeerRelay `json:"items"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.aws) || !has(self.aws.elasticIPs) || self.aws.elasticIPs.size() >= self.replicas",message="spec.aws.elasticIPs must contain at least one entry per replica"
type PeerRelaySpec struct {
	// Tags to apply to each peer relay device. Defaults to [tag:k8s]. If you set custom tags, the operator must
	// be an owner of each tag. You cannot change the tags after the operator creates the device. Each tag must
	// match ^tag:[a-zA-Z][a-zA-Z0-9-]*$. See https://tailscale.com/docs/kubernetes-operator/peer-relay.
	// +optional
	Tags Tags `json:"tags,omitempty"`

	// HostnamePrefix is the hostname prefix for each replica. The operator appends the replica index to form
	// the full hostname, for example my-relay-0. If unset, the operator uses the PeerRelay name. The prefix can
	// contain lowercase letters, numbers, and dashes. It must not start with a dash and must be 1 to 62
	// characters long.
	// +optional
	HostnamePrefix HostnamePrefix `json:"hostnamePrefix,omitzero"`

	// ProxyClass is the name of a ProxyClass to apply to the resources the operator creates for this PeerRelay.
	// If unset, the operator uses the default configuration.
	// +optional
	ProxyClass string `json:"proxyClass,omitempty"`

	// Replicas is the number of peer relay devices to run. Run more than one for high availability. Defaults
	// to 1. See https://tailscale.com/kb/1115/high-availability.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=1
	Replicas *int32 `json:"replicas,omitzero"`

	// Tailnet is the name of the Tailnet resource for the tailnet this PeerRelay joins. If unset, the operator
	// uses the default tailnet. You cannot change this field after you set it.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="PeerRelay tailnet is immutable"
	Tailnet string `json:"tailnet,omitempty"`

	// Service configures the LoadBalancer Service that the operator creates for each replica.
	// +optional
	Service *PeerRelayService `json:"service,omitzero"`

	// StaticEndpoints lists extra address:port pairs where every replica is reachable from outside the
	// cluster, for example the public side of a NAT or firewall. The operator adds each entry to every replica
	// in status.endpoints and advertises it to peers. If an entry has the same address as a load balancer, the
	// port of the entry replaces the port of the load balancer. An address can appear in only one entry. Write
	// each entry as an IP address and port, for example 203.0.113.1:41641. Put IPv6 addresses in brackets, for
	// example [2001:db8::1]:41641.
	// +optional
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-fA-F:.]+\]):\d{1,5}$`
	StaticEndpoints []string `json:"staticEndpoints,omitempty"`

	// AWS pins each replica to an AWS Elastic IP and subnet. It applies only on EKS with the AWS Load Balancer
	// Controller. Leave it unset unless the peer relays must be reachable on addresses you control. When set,
	// you must also pin the pods to one availability zone, as ElasticIPs describes. If unset, each load
	// balancer spans every zone the controller finds, and the replica is reachable in any zone. See
	// https://tailscale.com/docs/kubernetes-operator/peer-relay.
	// +optional
	AWS *PeerRelayAWS `json:"aws,omitzero"`
}

type PeerRelayService struct {
	// Annotations to apply to the LoadBalancer Service. The operator sets some cloud provider annotations so
	// that the Service gets a public IP address. These annotations override any conflicting value set here.
	//
	// The operator sets service.beta.kubernetes.io/aws-load-balancer-ip-address-type to ipv4 unless it is set
	// here. Set it to dualstack on an IPv6 EKS cluster. When it is dualstack, the operator also sets
	// service.beta.kubernetes.io/aws-load-balancer-enable-prefix-for-ipv6-source-nat to on unless it is set here.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Port is the UDP port that each replica listens on and that its LoadBalancer Service exposes. The two
	// ports are always equal because the relay advertises address:port to peers. Changing the port briefly
	// interrupts relay traffic while the load balancer updates. Defaults to 41641.
	// +optional
	// +kubebuilder:default=41641
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *uint16 `json:"port,omitzero"`

	// IPFamilyPolicy sets spec.ipFamilyPolicy on each LoadBalancer Service. If unset, the cluster default
	// applies. Set RequireDualStack on a dual-stack cluster to get a load balancer with both IPv4 and IPv6
	// addresses. On EKS, use the service.beta.kubernetes.io/aws-load-balancer-ip-address-type annotation
	// instead.
	// +optional
	// +kubebuilder:validation:Enum=SingleStack;PreferDualStack;RequireDualStack
	IPFamilyPolicy *corev1.IPFamilyPolicy `json:"ipFamilyPolicy,omitzero"`

	// IPFamilies sets spec.ipFamilies on each LoadBalancer Service. If unset, the cluster default applies. The
	// value must agree with IPFamilyPolicy.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=2
	// +kubebuilder:validation:items:Enum=IPv4;IPv6
	IPFamilies []corev1.IPFamily `json:"ipFamilies,omitempty"`
}

// PeerRelayAWS contains AWS-specific configuration for a PeerRelay.
type PeerRelayAWS struct {
	// ElasticIPs lists one Elastic IP allocation and subnet for each replica. Replica N uses entry N. The list
	// must have at least spec.replicas entries. Extra entries are allowed so that a scale-up does not fail
	// validation.
	//
	// A load balancer only forwards to pods in the availability zone of its subnet. A pod scheduled into
	// another zone, for example after a reschedule, is unreachable on its Elastic IP but still appears healthy.
	// To prevent this, use subnets in one zone. Then pin the pods to that zone with a ProxyClass that sets
	// spec.statefulSet.pod.nodeSelector to topology.kubernetes.io/zone. A ProxyClass applies to every replica,
	// so this removes the zone redundancy of multiple replicas.
	//
	// These values override the service.beta.kubernetes.io/aws-load-balancer-eip-allocations and
	// service.beta.kubernetes.io/aws-load-balancer-subnets annotations in spec.service.annotations.
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	ElasticIPs []PeerRelayAWSElasticIP `json:"elasticIPs"`
}

// PeerRelayAWSElasticIP pairs an EIP allocation with the subnet it is attached to.
type PeerRelayAWSElasticIP struct {
	// AllocationID is the AWS Elastic IP allocation ID for this replica, for example eipalloc-0123abcd. The
	// operator sets it as the service.beta.kubernetes.io/aws-load-balancer-eip-allocations annotation on the
	// Service of the replica.
	// +kubebuilder:validation:Pattern=`^eipalloc-[0-9a-f]+$`
	AllocationID string `json:"allocationID"`

	// SubnetID is the public AWS subnet for the load balancer of this replica, for example subnet-0123abcd. The
	// Elastic IP takes the availability zone of this subnet. The operator sets it as the
	// service.beta.kubernetes.io/aws-load-balancer-subnets annotation on the Service of the replica.
	// +kubebuilder:validation:Pattern=`^subnet-[0-9a-f]+$`
	SubnetID string `json:"subnetID"`
}

type PeerRelayStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions"`

	// Endpoints lists the public address:port pairs where each replica is reachable. The operator adds entries
	// as the cloud provisions each Service. A replica has one entry for each address of its load balancer. A
	// load balancer has more than one address when it spans several availability zones or both address
	// families. Every replica also has one entry for each entry in spec.staticEndpoints.
	// +listType=map
	// +listMapKey=replica
	// +listMapKey=address
	// +optional
	Endpoints []PeerRelayEndpoint `json:"endpoints,omitempty"`
}

type PeerRelayEndpoint struct {
	// Replica is the zero-based index of the peer relay replica this endpoint targets.
	Replica int32 `json:"replica"`

	// Address is a public IP address of the load balancer for this replica, or an address from
	// spec.staticEndpoints. Peers connect to Address:Port over UDP.
	Address string `json:"address"`

	// Port is the UDP port the peer relay listens on.
	Port int32 `json:"port"`
}

// PeerRelayReady is set to True if the PeerRelay is available for use by operator workloads.
const PeerRelayReady ConditionType = `PeerRelayReady`
