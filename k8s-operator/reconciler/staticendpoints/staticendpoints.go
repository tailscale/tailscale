// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package staticendpoints provisions the cluster resources needed to expose
// proxies to the tailnet on 'static' endpoints (ProxyClass
// spec.staticEndpoints): a NodePort Service is created for each replica of
// the proxy's StatefulSet, and the ExternalIPs of the selected Nodes combined
// with the allocated NodePorts are advertised as static endpoints in each
// replica's tailscaled config. The logic is shared between parent resource
// types that support static endpoints (ProxyGroups and Connectors).
package staticendpoints

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/util/set"
)

// MaxAddrs is the maximum number of static endpoints to advertise per proxy
// replica.
const MaxAddrs = 2

const (
	tailscaledPortMax = 65535
	tailscaledPortMin = 1024
)

// getRandomPort returns a random port for tailscaled to listen on. The PORT
// environment variable is chosen to match what the Linux systemd unit uses.
func getRandomPort() uint16 {
	return uint16(rand.IntN(tailscaledPortMax-tailscaledPortMin+1) + tailscaledPortMin)
}

// AllocatePortsError is returned by EnsureNodePortServices when the
// ProxyClass's configured port ranges do not contain enough free ports to
// allocate a NodePort for every replica.
type AllocatePortsError struct {
	msg string
}

func (e *AllocatePortsError) Error() string {
	return e.msg
}

// FindEndpointsError is returned by FindEndpoints when no static endpoints
// could be derived from the Nodes matching the ProxyClass's selector.
type FindEndpointsError struct {
	msg string
}

func (e *FindEndpointsError) Error() string {
	return e.msg
}

// parentTypeDisplayName returns the user-facing name of a parent resource
// type for use in error messages and events.
func parentTypeDisplayName(parentType string) string {
	switch parentType {
	case "proxygroup":
		return "ProxyGroup"
	case "connector":
		return "Connector"
	}
	return parentType
}

// NodePortServiceName returns the name of the static endpoints NodePort
// Service for the given replica of a parent resource (ProxyGroup or
// Connector).
func NodePortServiceName(parentName string, replica int32) string {
	return fmt.Sprintf("%s-%d-nodeport", parentName, replica)
}

// Config describes the static endpoints NodePort Services of a parent
// resource (ProxyGroup or Connector).
type Config struct {
	// Namespace is the namespace the operator creates the NodePort Services
	// in (the operator's own namespace).
	Namespace string
	// ParentType is the parent resource type label value, e.g. "proxygroup"
	// or "connector".
	ParentType string
	// ParentName is the name of the parent resource.
	ParentName string
	// ProxyClassName is the name of the ProxyClass that configures the
	// static endpoints, used in error messages.
	ProxyClassName string
	// Replicas is the parent resource's replica count; one NodePort Service
	// is created per replica.
	Replicas int32
	// PortRanges are the port ranges NodePorts get allocated from.
	PortRanges tsapi.PortRanges
	// MakeService returns the base Service definition, including a single
	// port, for the given replica ordinal and Service name;
	// EnsureNodePortServices fills in the port numbers.
	MakeService func(ordinal int32, name string) *corev1.Service
}

// getServicePorts returns a map of static endpoints Service names for parent
// resources of the given type to their NodePorts, and a set of all allocated
// NodePorts for quick occupancy checking. All NodePort Services managed by
// the operator contribute to the occupied set as they share the cluster's
// NodePort space, regardless of parent type.
func getServicePorts(ctx context.Context, c client.Client, cfg Config) (map[string]uint16, set.Set[uint16], error) {
	svcs := new(corev1.ServiceList)
	matchingLabels := client.MatchingLabels(map[string]string{
		kubetypes.LabelManaged: "true",
	})

	err := c.List(ctx, svcs, matchingLabels, client.InNamespace(cfg.Namespace))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list Services: %w", err)
	}

	svcToNodePorts := map[string]uint16{}
	usedPorts := set.Set[uint16]{}
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if len(svc.Spec.Ports) == 1 && svc.Spec.Ports[0].NodePort != 0 {
			p := uint16(svc.Spec.Ports[0].NodePort)
			if cfg.PortRanges.Contains(p) {
				if reconciler.IsManagedByType(svc, cfg.ParentType) {
					svcToNodePorts[svc.Name] = p
				}
				usedPorts.Add(p)
			}
		}
	}

	return svcToNodePorts, usedPorts, nil
}

// allocatePorts allocates NodePorts from the configured port ranges for each
// replica of the parent resource, reusing the ports of any existing static
// endpoints Services. It returns an *AllocatePortsError if the port ranges do
// not contain enough free ports for all replicas.
func allocatePorts(ctx context.Context, c client.Client, cfg Config) (map[string]uint16, error) {
	svcToNodePorts, usedPorts, err := getServicePorts(ctx, c, cfg)
	if err != nil {
		return nil, &AllocatePortsError{msg: fmt.Sprintf("failed to find ports for existing NodePort Services: %s", err.Error())}
	}

	replicasAllocated := 0
	for i := range cfg.Replicas {
		if _, ok := svcToNodePorts[NodePortServiceName(cfg.ParentName, i)]; !ok {
			svcToNodePorts[NodePortServiceName(cfg.ParentName, i)] = 0
		} else {
			replicasAllocated++
		}
	}

	for replica, port := range svcToNodePorts {
		if port == 0 {
			for p := range cfg.PortRanges.All() {
				if !usedPorts.Contains(p) {
					svcToNodePorts[replica] = p
					usedPorts.Add(p)
					replicasAllocated++
					break
				}
			}
		}
	}

	if replicasAllocated < int(cfg.Replicas) {
		return nil, &AllocatePortsError{msg: fmt.Sprintf("not enough available ports to allocate all replicas (needed %d, got %d). Field 'spec.staticEndpoints.nodePort.ports' on ProxyClass %q must have bigger range allocated", cfg.Replicas, usedPorts.Len(), cfg.ProxyClassName)}
	}

	return svcToNodePorts, nil
}

// EnsureNodePortServices creates or updates a static endpoints NodePort
// Service for each replica of the parent resource described by cfg. It
// returns a map of Service names to their allocated NodePorts, and the port
// that tailscaled should listen on (the target port shared by all the
// Services).
func EnsureNodePortServices(ctx context.Context, c client.Client, cfg Config) (map[string]uint16, *uint16, error) {
	// NOTE: (ChaosInTheCRD) we want the same TargetPort for every static endpoint NodePort Service for the proxy.
	tailscaledPort := getRandomPort()
	svcs := []*corev1.Service{}
	for i := range cfg.Replicas {
		nodePortSvcName := NodePortServiceName(cfg.ParentName, i)

		svc := &corev1.Service{}
		err := c.Get(ctx, types.NamespacedName{Name: nodePortSvcName, Namespace: cfg.Namespace}, svc)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("error getting Kubernetes Service %q: %w", nodePortSvcName, err)
		}
		if apierrors.IsNotFound(err) {
			svcs = append(svcs, cfg.MakeService(i, nodePortSvcName))
		} else {
			// NOTE: if we can we want to recover the random port used for tailscaled,
			// as well as the NodePort previously used for that Service
			if len(svc.Spec.Ports) == 1 {
				if svc.Spec.Ports[0].Port != 0 {
					tailscaledPort = uint16(svc.Spec.Ports[0].Port)
				}
			}
			svcs = append(svcs, svc)
		}
	}

	svcToNodePorts, err := allocatePorts(ctx, c, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to allocate NodePorts to %s Services: %w", parentTypeDisplayName(cfg.ParentType), err)
	}

	for _, svc := range svcs {
		// NOTE: we know that every service is going to have 1 port here
		svc.Spec.Ports[0].Port = int32(tailscaledPort)
		svc.Spec.Ports[0].TargetPort = intstr.FromInt(int(tailscaledPort))
		svc.Spec.Ports[0].NodePort = int32(svcToNodePorts[svc.Name])

		_, err = reconciler.CreateOrUpdate(ctx, c, cfg.Namespace, svc, func(s *corev1.Service) {
			s.ObjectMeta.Labels = svc.ObjectMeta.Labels
			s.ObjectMeta.Annotations = svc.ObjectMeta.Annotations
			s.ObjectMeta.OwnerReferences = svc.ObjectMeta.OwnerReferences
			s.Spec.Selector = svc.Spec.Selector
			s.Spec.Ports = svc.Spec.Ports
		})
		if err != nil {
			return nil, nil, fmt.Errorf("error creating/updating Kubernetes NodePort Service %q: %w", svc.Name, err)
		}
	}

	return svcToNodePorts, new(tailscaledPort), nil
}

// FindEndpoints returns up to MaxAddrs `netip.AddrPort` entries, derived from
// the ExternalIPs of Nodes that match the `proxyClass`'s selector within the
// StaticEndpoints configuration. The port is set to the replica's NodePort
// Service Port. currAddrs is the set of endpoints previously advertised in
// the replica's tailscaled config, if any; the currently used addresses are
// preferred, and kept in their existing order, over newly discovered ones.
func FindEndpoints(ctx context.Context, c client.Client, currAddrs []netip.AddrPort, proxyClass *tsapi.ProxyClass, port uint16, logger *zap.SugaredLogger) ([]netip.AddrPort, error) {
	nodes := new(corev1.NodeList)
	selectors := client.MatchingLabels(proxyClass.Spec.StaticEndpoints.NodePort.Selector)

	err := c.List(ctx, nodes, selectors)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	if len(nodes.Items) == 0 {
		return nil, &FindEndpointsError{msg: fmt.Sprintf("failed to match nodes to configured Selectors on `spec.staticEndpoints.nodePort.selectors` field for ProxyClass %q", proxyClass.Name)}
	}

	endpoints := []netip.AddrPort{}

	// NOTE(ChaosInTheCRD): Setting a hard limit of two static endpoints.
	newAddrs := []netip.AddrPort{}
	for _, n := range nodes.Items {
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeExternalIP {
				addr := getStaticEndpointAddress(&a, port)
				if addr == nil {
					logger.Debugf("failed to parse %q address on node %q: %q", corev1.NodeExternalIP, n.Name, a.Address)
					continue
				}

				// we want to add the currently used IPs first before
				// adding new ones.
				if currAddrs != nil && slices.Contains(currAddrs, *addr) {
					endpoints = append(endpoints, *addr)
				} else {
					newAddrs = append(newAddrs, *addr)
				}
			}

			if len(endpoints) == MaxAddrs {
				break
			}
		}
	}

	// if the MaxAddrs endpoints limit hasn't been reached, we
	// can start adding newIPs.
	if len(endpoints) < MaxAddrs {
		for _, a := range newAddrs {
			endpoints = append(endpoints, a)
			if len(endpoints) == MaxAddrs {
				break
			}
		}
	}

	if len(endpoints) == 0 {
		return nil, &FindEndpointsError{msg: fmt.Sprintf("failed to find any `status.addresses` of type %q on nodes using configured Selectors on `spec.staticEndpoints.nodePort.selectors` for ProxyClass %q", corev1.NodeExternalIP, proxyClass.Name)}
	}

	// If we ended up selecting the same set of addresses already in use, keep
	// the existing order. nodes.Items from the List call is not guaranteed to
	// be in a stable order across calls, so without this the slice can permute
	// on each reconcile, making the marshalled config Secret differ
	// byte-for-byte even though nothing has effectively changed. That trips
	// the DeepEqual check on the config Secret, which writes the Secret, which
	// fires a watch event, which re-enqueues the parent resource, and so on.
	if len(currAddrs) > 0 && sameAddrPortSet(endpoints, currAddrs) {
		return currAddrs, nil
	}

	return endpoints, nil
}

// sameAddrPortSet reports whether a and b contain the same AddrPorts,
// ignoring order. Both slices are assumed to be free of duplicates, which
// holds for callers of FindEndpoints.
func sameAddrPortSet(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

func getStaticEndpointAddress(a *corev1.NodeAddress, port uint16) *netip.AddrPort {
	addr, err := netip.ParseAddr(a.Address)
	if err != nil {
		return nil
	}

	return new(netip.AddrPortFrom(addr, port))
}
