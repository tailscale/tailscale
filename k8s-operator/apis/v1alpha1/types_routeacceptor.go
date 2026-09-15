// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Code comments on these types should be treated as user facing documentation-
// they will appear on the RouteAcceptor CRD i.e. if someone runs kubectl explain routeacceptor.

var RouteAcceptorKind = "RouteAcceptor"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ra
// +kubebuilder:printcolumn:name="AcceptedRoutes",type="string",JSONPath=`.status.acceptedRoutes`,description="Subnet routes currently accepted from the tailnet and routable from the cluster."
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=`.status.readyNodes`,description="Number of nodes on which the route acceptor is ready."
// +kubebuilder:printcolumn:name="Desired",type="integer",JSONPath=`.status.desiredNodes`,description="Number of nodes selected to run the route acceptor."
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "RouteAcceptorReady")].reason`,description="Status of the deployed RouteAcceptor resources."
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// RouteAcceptor makes subnet routes advertised to the tailnet routable from
// every Pod in the cluster, without a per-destination egress Service.
//
// The operator runs a tailscaled device in the host network namespace of every
// selected node (a DaemonSet), configured to accept routes. The subnet routes
// that the tailnet approves for those devices are installed in each node's
// routing table, so traffic from Pods on that node to those subnets is
// forwarded through the tailnet, with the node's tailnet IP as its source.
// Because the devices route all tailnet addresses via the tailnet as well, Pods
// can also reach any tailnet peer that the devices' tags are allowed to reach.
//
// Requirements:
//   - The nodes must not already run tailscaled.
//   - The cluster's CNI must route Pod traffic to destinations outside the
//     cluster through the node's network stack, which is the case for most
//     CNIs (Calico, Flannel, kindnet and the cloud providers' CNIs), but not
//     for Cilium's default eBPF host routing: set bpf.hostLegacyRouting=true
//     there.
//   - The devices run privileged (or with NET_ADMIN and /dev/net/tun), see
//     ProxyClass for reducing their permissions.
//   - Tailscale ACLs must allow the devices' tags to access the subnets, and
//     the subnet routers' routes must be approved.
//   - The Pod and Service CIDRs of the cluster must not overlap
//     100.64.0.0/10, see spec.unsafeAllowCGNATClusterCIDR.
//
// The devices are named after the nodes they run on. Their identity is
// persisted per node, so a device survives restarts of its Pod.
//
// RouteAcceptor is a cluster-scoped resource.
type RouteAcceptor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// Spec describes the desired state of the RouteAcceptor.
	// More info:
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec RouteAcceptorSpec `json:"spec"`

	// Status describes the status of the RouteAcceptor. This is set
	// and managed by the Tailscale operator.
	// +optional
	Status RouteAcceptorStatus `json:"status"`
}

// +kubebuilder:object:root=true

type RouteAcceptorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []RouteAcceptor `json:"items"`
}

type RouteAcceptorSpec struct {
	// Tags that the Tailscale devices will be tagged with.
	// Defaults to [tag:k8s].
	// Configure Tailscale ACLs to allow these tags to access the subnets that
	// should be reachable from the cluster.
	// If you specify custom tags here, you must also make the operator an owner of these tags.
	// See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.
	// Tags cannot be changed once the devices have been created.
	// Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$.
	// +optional
	Tags Tags `json:"tags,omitempty"`

	// ProxyClass is the name of the ProxyClass custom resource that
	// contains configuration options that should be applied to the
	// resources created for this RouteAcceptor. The ProxyClass's statefulSet
	// section applies to the DaemonSet and its Pods in the same way; use its
	// pod.nodeSelector, pod.tolerations and pod.affinity to select the nodes
	// that should run a route acceptor device. If unset, the operator will
	// create resources with the default configuration, on every node.
	// +optional
	ProxyClass string `json:"proxyClass,omitempty"`

	// Tailnet specifies the tailnet the devices should join. If blank, the default tailnet is used. When set, this
	// name must match that of a valid Tailnet resource. This field is immutable and cannot be changed once set.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="RouteAcceptor tailnet is immutable"
	Tailnet string `json:"tailnet,omitempty"`

	// ClusterCIDRs are additional IP ranges used by the cluster, such as its
	// Pod and Service CIDRs, that the operator cannot discover on its own.
	// The operator discovers the Pod CIDRs recorded on the Nodes and the
	// ServiceCIDR resources, if the cluster has them; add ranges here if your
	// CNI does not record Pod CIDRs on the Nodes. The ranges are only used to
	// warn, via the RouteAcceptorRoutesValid condition, when an accepted
	// route overlaps them, as tailscaled would then route cluster traffic
	// into the tailnet.
	// +optional
	ClusterCIDRs Routes `json:"clusterCIDRs,omitempty"`

	// UnsafeAllowCGNATClusterCIDR allows the route acceptor to be deployed
	// even if a cluster IP range overlaps the Tailscale IP range
	// 100.64.0.0/10. By default the operator refuses to do so, because
	// tailscaled drops traffic from that range that does not arrive via the
	// tailnet, which would break traffic from Pods to the nodes. Set this only
	// if the tailnet grants the devices' tags the disable-linux-cgnat-drop-rule
	// node attribute.
	// +optional
	UnsafeAllowCGNATClusterCIDR bool `json:"unsafeAllowCGNATClusterCIDR,omitempty"`
}

type RouteAcceptorStatus struct {
	// List of status conditions to indicate the status of the RouteAcceptor.
	// Known condition types are RouteAcceptorReady and
	// RouteAcceptorRoutesValid.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions"`

	// AcceptedRoutes is the union of the subnet routes that the devices
	// currently accept from the tailnet, i.e. the routes that are routable
	// from Pods on the nodes that run a ready device.
	// +listType=atomic
	// +optional
	AcceptedRoutes []string `json:"acceptedRoutes,omitempty"`

	// DesiredNodes is the number of nodes selected to run a route acceptor
	// device.
	// +optional
	DesiredNodes int32 `json:"desiredNodes"`

	// ReadyNodes is the number of nodes on which the route acceptor device is
	// ready.
	// +optional
	ReadyNodes int32 `json:"readyNodes"`

	// Nodes describes the device on each node.
	// +listType=map
	// +listMapKey=name
	// +optional
	Nodes []RouteAcceptorNode `json:"nodes,omitempty"`
}

// RouteAcceptorNode describes the route acceptor device running on a node.
type RouteAcceptorNode struct {
	// Name is the name of the Kubernetes node.
	Name string `json:"name"`

	// Hostname is the fully qualified domain name of the device on the node.
	// If MagicDNS is enabled in your tailnet, it is the MagicDNS name of the
	// device.
	// +optional
	Hostname string `json:"hostname,omitempty"`

	// TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)
	// assigned to the device on the node.
	// +optional
	TailnetIPs []string `json:"tailnetIPs,omitempty"`

	// AcceptedRoutes are the subnet routes that the device on the node
	// currently accepts from the tailnet.
	// +listType=atomic
	// +optional
	AcceptedRoutes []string `json:"acceptedRoutes,omitempty"`

	// Ready is true if the device on the node has joined the tailnet.
	Ready bool `json:"ready"`
}

const (
	// RouteAcceptorReady is set to True once the route acceptor device is ready on every selected node.
	RouteAcceptorReady ConditionType = `RouteAcceptorReady`
	// RouteAcceptorRoutesValid is set to False if a route accepted from the tailnet overlaps an IP range used by the
	// cluster.
	RouteAcceptorRoutesValid ConditionType = `RouteAcceptorRoutesValid`
)
