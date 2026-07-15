// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/util/set"
)

// staticEndpointsMaxAddrs is the maximum number of static endpoints that can be
// advertised by a single proxy.
const staticEndpointsMaxAddrs = 2

// allocatePortsErr is returned when there are not enough NodePorts available in
// the configured port ranges to allocate one per replica.
type allocatePortsErr struct {
	msg string
}

func (e *allocatePortsErr) Error() string {
	return e.msg
}

// FindStaticEndpointErr is returned when no nodes matching the static endpoint
// selector are found, or when matching nodes have no ExternalIP addresses.
type FindStaticEndpointErr struct {
	msg string
}

func (e *FindStaticEndpointErr) Error() string {
	return e.msg
}

// nodePortServiceName returns the name of the NodePort Service for the given
// parent resource name and replica ordinal.
func nodePortServiceName(parentName string, replica int32) string {
	return fmt.Sprintf("%s-%d-nodeport", parentName, replica)
}

// getServicePorts lists existing NodePort Services matching the given parent
// type and returns a map of Service name to NodePort, plus a set of all
// allocated NodePorts for quick occupancy checking.
func getServicePorts(ctx context.Context, c client.Client, namespace, parentType string, portRanges tsapi.PortRanges) (map[string]uint16, set.Set[uint16], error) {
	svcs := new(corev1.ServiceList)
	matchingLabels := client.MatchingLabels(map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentType:        parentType,
	})

	err := c.List(ctx, svcs, matchingLabels, client.InNamespace(namespace))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list %s Services: %w", parentType, err)
	}

	svcToNodePorts := map[string]uint16{}
	usedPorts := set.Set[uint16]{}
	for _, svc := range svcs.Items {
		if len(svc.Spec.Ports) == 1 && svc.Spec.Ports[0].NodePort != 0 {
			p := uint16(svc.Spec.Ports[0].NodePort)
			if portRanges.Contains(p) {
				svcToNodePorts[svc.Name] = p
				usedPorts.Add(p)
			}
		}
	}

	return svcToNodePorts, usedPorts, nil
}

// allocatePorts allocates a NodePort from the given port ranges for each
// replica of a parent resource. It reuses existing allocations where possible.
func allocatePorts(ctx context.Context, c client.Client, namespace, parentType, parentName string, replicas int32, proxyClassName string, portRanges tsapi.PortRanges) (map[string]uint16, error) {
	svcToNodePorts, usedPorts, err := getServicePorts(ctx, c, namespace, parentType, portRanges)
	if err != nil {
		return nil, &allocatePortsErr{msg: fmt.Sprintf("failed to find ports for existing %s NodePort Services: %s", parentType, err.Error())}
	}

	replicasAllocated := 0
	for i := range replicas {
		svcName := nodePortServiceName(parentName, i)
		if _, ok := svcToNodePorts[svcName]; !ok {
			svcToNodePorts[svcName] = 0
		} else {
			replicasAllocated++
		}
	}

	for svc, port := range svcToNodePorts {
		if port == 0 {
			for p := range portRanges.All() {
				if !usedPorts.Contains(p) {
					svcToNodePorts[svc] = p
					usedPorts.Add(p)
					replicasAllocated++
					break
				}
			}
		}
	}

	if replicasAllocated < int(replicas) {
		return nil, &allocatePortsErr{msg: fmt.Sprintf("not enough available ports to allocate all replicas (needed %d, got %d). Field 'spec.staticEndpoints.nodePort.ports' on ProxyClass %q must have bigger range allocated", replicas, usedPorts.Len(), proxyClassName)}
	}

	return svcToNodePorts, nil
}

// makeNodePortServiceFunc is a callback that returns a fresh NodePort Service
// spec for the given replica ordinal. The Service name and namespace are
// provided by the caller; the callback fills in labels, owner references, and
// the pod selector (which differ between ProxyGroup and Connector).
type makeNodePortServiceFunc func(replica int32, name, namespace string) *corev1.Service

// ensureNodePortServices creates or updates NodePort Services for each replica
// of a parent resource. makeService provides the per-replica Service spec
// (labels, selector, owner refs). The port allocation and tailscaled target
// port logic is shared. Returns a map of Service name to allocated NodePort
// and the tailscaled port that NodePorts forward to.
func ensureNodePortServices(
	ctx context.Context,
	c client.Client,
	namespace, parentType, parentName string,
	replicas int32,
	proxyClassName string,
	portRanges tsapi.PortRanges,
	makeService makeNodePortServiceFunc,
) (map[string]uint16, *uint16, error) {
	tailscaledPort := getRandomPort()
	svcs := []*corev1.Service{}
	for i := range replicas {
		svcName := nodePortServiceName(parentName, i)

		svc := &corev1.Service{}
		err := c.Get(ctx, client.ObjectKey{Name: svcName, Namespace: namespace}, svc)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("error getting Kubernetes Service %q: %w", svcName, err)
		}
		if apierrors.IsNotFound(err) {
			svcs = append(svcs, makeService(i, svcName, namespace))
		} else {
			if len(svc.Spec.Ports) == 1 && svc.Spec.Ports[0].Port != 0 {
				tailscaledPort = uint16(svc.Spec.Ports[0].Port)
			}
			svcs = append(svcs, svc)
		}
	}

	svcToNodePorts, err := allocatePorts(ctx, c, namespace, parentType, parentName, replicas, proxyClassName, portRanges)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to allocate NodePorts to Services: %w", err)
	}

	for _, svc := range svcs {
		svc.Spec.Ports[0].Port = int32(tailscaledPort)
		svc.Spec.Ports[0].TargetPort = intstr.FromInt(int(tailscaledPort))
		svc.Spec.Ports[0].NodePort = int32(svcToNodePorts[svc.Name])

		_, err = createOrUpdate(ctx, c, namespace, svc, func(s *corev1.Service) {
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

	return svcToNodePorts, &tailscaledPort, nil
}

// findStaticEndpoints returns up to two netip.AddrPort entries, derived from the
// ExternalIPs of Nodes that match the ProxyClass's staticEndpoints.nodePort.selector.
// The port is set to the replica's NodePort Service port.
func findStaticEndpoints(ctx context.Context, c client.Client, existingCfgSecret *corev1.Secret, proxyClass *tsapi.ProxyClass, port uint16, logger *zap.SugaredLogger) ([]netip.AddrPort, error) {
	var currAddrs []netip.AddrPort
	if existingCfgSecret != nil {
		oldConfB := existingCfgSecret.Data[tsoperator.TailscaledConfigFileName(106)]
		if len(oldConfB) > 0 {
			var oldConf ipn.ConfigVAlpha
			if err := json.Unmarshal(oldConfB, &oldConf); err == nil {
				currAddrs = oldConf.StaticEndpoints
			} else {
				logger.Debugf("failed to unmarshal tailscaled config from secret %q: %v", existingCfgSecret.Name, err)
			}
		} else {
			logger.Debugf("failed to get tailscaled config from secret %q: empty data", existingCfgSecret.Name)
		}
	}

	nodes := new(corev1.NodeList)
	selectors := client.MatchingLabels(proxyClass.Spec.StaticEndpoints.NodePort.Selector)

	err := c.List(ctx, nodes, selectors)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	if len(nodes.Items) == 0 {
		return nil, &FindStaticEndpointErr{msg: fmt.Sprintf("failed to match nodes to configured Selectors on `spec.staticEndpoints.nodePort.selectors` field for ProxyClass %q", proxyClass.Name)}
	}

	endpoints := []netip.AddrPort{}
	newAddrs := []netip.AddrPort{}
	for _, n := range nodes.Items {
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeExternalIP {
				addr := getStaticEndpointAddress(&a, port)
				if addr == nil {
					logger.Debugf("failed to parse %q address on node %q: %q", corev1.NodeExternalIP, n.Name, a.Address)
					continue
				}

				if currAddrs != nil && slices.Contains(currAddrs, *addr) {
					endpoints = append(endpoints, *addr)
				} else {
					newAddrs = append(newAddrs, *addr)
				}
			}

			if len(endpoints) == staticEndpointsMaxAddrs {
				break
			}
		}
	}

	if len(endpoints) < staticEndpointsMaxAddrs {
		for _, a := range newAddrs {
			endpoints = append(endpoints, a)
			if len(endpoints) == staticEndpointsMaxAddrs {
				break
			}
		}
	}

	if len(endpoints) == 0 {
		return nil, &FindStaticEndpointErr{msg: fmt.Sprintf("failed to find any `status.addresses` of type %q on nodes using configured Selectors on `spec.staticEndpoints.nodePort.selectors` for ProxyClass %q", corev1.NodeExternalIP, proxyClass.Name)}
	}

	if len(currAddrs) > 0 && sameAddrPortSet(endpoints, currAddrs) {
		return currAddrs, nil
	}

	return endpoints, nil
}

// sameAddrPortSet reports whether a and b contain the same AddrPorts,
// ignoring order. Both slices are assumed to be free of duplicates.
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

// deleteNodePortServices deletes all NodePort Services for the given parent
// resource. Used during cleanup when static endpoints are removed or the parent
// resource is deleted.
func deleteNodePortServices(ctx context.Context, c client.Client, namespace, parentType, parentName string) error {
	labels := map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentType:        parentType,
		LabelParentName:        parentName,
	}
	if err := c.DeleteAllOf(ctx, &corev1.Service{}, client.InNamespace(namespace), client.MatchingLabels(labels)); err != nil {
		return fmt.Errorf("error deleting Kubernetes Services for static endpoints: %w", err)
	}
	return nil
}
