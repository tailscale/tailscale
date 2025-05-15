// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8soperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
)

const (
	tailscaledPortMax = 65535
	tailscaledPortMin = 1024
	testSvcName       = "test-node-port-range"

	invalidSvcNodePort = 777777
)

// getServicesNodePortRange is a hacky function that attempts to determine Service NodePort range by
// creating a deliberately invalid Service with a NodePort that is too large and parsing the returned
// validation error. Returns nil if unable to determine port range.
// https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport
func getServicesNodePortRange(ctx context.Context, c client.Client, tsNamespace string, logger *zap.SugaredLogger) *tsapi.PortRange {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testSvcName,
			Namespace: tsNamespace,
			Labels: map[string]string{
				kubetypes.LabelManaged: "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Name:       testSvcName,
					Port:       8080,
					TargetPort: intstr.FromInt32(8080),
					Protocol:   corev1.ProtocolUDP,
					NodePort:   invalidSvcNodePort,
				},
			},
		},
	}

	// NOTE(ChaosInTheCRD): ideally this would be a server side dry-run but could not get it working
	err := c.Create(ctx, svc)
	if err == nil {
		return nil
	}

	if validPorts := getServicesNodePortRangeFromErr(err.Error()); validPorts != "" {
		pr, err := parseServicesNodePortRange(validPorts)
		if err != nil {
			logger.Debugf("failed to parse NodePort range set for Kubernetes Cluster: %w", err)
			return nil
		}

		return pr
	}

	return nil
}

func getServicesNodePortRangeFromErr(err string) string {
	reg := regexp.MustCompile(`\d{1,5}-\d{1,5}`)
	matches := reg.FindAllString(err, -1)
	if len(matches) != 1 {
		return ""
	}

	return matches[0]
}

// parseServicesNodePortRange converts the `ValidPorts` string field in the Kubernetes PortAllocator error and converts it to
// PortRange
func parseServicesNodePortRange(p string) (*tsapi.PortRange, error) {
	parts := strings.Split(p, "-")
	s, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to parse string as uint16: %w", err)
	}

	var e uint64
	switch len(parts) {
	case 1:
		e = uint64(s)
	case 2:
		e, err = strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to parse string as uint16: %w", err)
		}
	default:
		return nil, fmt.Errorf("failed to parse port range %q", p)
	}

	portRange := &tsapi.PortRange{Port: uint16(s), EndPort: uint16(e)}
	if !portRange.IsValid() {
		return nil, fmt.Errorf("port range %q is not valid", portRange.String())
	}

	return portRange, nil
}

// validateNodePortRanges checks that the port range specified is valid. It also ensures that the specified ranges
// lie within the NodePort Service port range specified for the Kubernetes API Server.
func validateNodePortRanges(ctx context.Context, c client.Client, kubeRange *tsapi.PortRange, pc *tsapi.ProxyClass) error {
	if pc.Spec.StaticEndpoints == nil {
		return nil
	}

	portRanges := pc.Spec.StaticEndpoints.NodePort.Ports

	if kubeRange != nil {
		for _, pr := range portRanges {
			if !kubeRange.Contains(pr.Port) || (pr.EndPort != 0 && !kubeRange.Contains(pr.EndPort)) {
				return fmt.Errorf("range %q is not within Cluster configured range %q", pr.String(), kubeRange.String())
			}
		}
	}

	for _, r := range portRanges {
		if !r.IsValid() {
			return fmt.Errorf("port range %q is invalid", r.String())
		}
	}

	// TODO(ChaosInTheCRD): if a ProxyClass that made another invalid (due to port range clash) is deleted,
	// the invalid ProxyClass doesn't get reconciled on, and therefore will not go valid. We should fix this.
	proxyClassRanges, err := getPortsForProxyClasses(ctx, c)
	if err != nil {
		return fmt.Errorf("failed to get port ranges for ProxyClasses: %w", err)
	}

	for _, r := range portRanges {
		for pcName, pcr := range proxyClassRanges {
			if pcName == pc.Name {
				continue
			}
			if pcr.ClashesWith(r) {
				return fmt.Errorf("port ranges for ProxyClass %q clash with existing ProxyClass %q", pc.Name, pcName)
			}
		}
	}

	if len(portRanges) == 1 {
		return nil
	}

	sort.Slice(portRanges, func(i, j int) bool {
		return portRanges[i].Port < portRanges[j].Port
	})

	for i := 1; i < len(portRanges); i++ {
		prev := portRanges[i-1]
		curr := portRanges[i]
		if curr.Port <= prev.Port || curr.Port <= prev.EndPort {
			return fmt.Errorf("overlapping ranges: %q and %q", prev.String(), curr.String())
		}
	}

	return nil
}

// getPortsForProxyClasses gets the port ranges for all the other existing ProxyClasses
func getPortsForProxyClasses(ctx context.Context, c client.Client) (map[string]tsapi.PortRanges, error) {
	pcs := new(tsapi.ProxyClassList)

	err := c.List(ctx, pcs)
	if err != nil {
		return nil, fmt.Errorf("failed to list ProxyClasses: %w", err)
	}

	portRanges := make(map[string]tsapi.PortRanges)
	for _, i := range pcs.Items {
		if !k8soperator.ProxyClassIsReady(&i) {
			continue
		}
		if se := i.Spec.StaticEndpoints; se != nil && se.NodePort != nil {
			portRanges[i.Name] = se.NodePort.Ports
		}
	}

	return portRanges, nil
}

func getRandomPort() uint16 {
	return uint16(rand.IntN(tailscaledPortMax-tailscaledPortMin+1) + tailscaledPortMin)
}
