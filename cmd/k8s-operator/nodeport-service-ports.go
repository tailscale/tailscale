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
					NodePort:   int32(invalidSvcNodePort),
				},
			},
		},
	}

	// NOTE (ChaosInTheCRD): ideally this would be a server side dry-run but could not get it working
	// This _could_ lead to an orphaned service.
	err := c.Create(ctx, svc)
	if err == nil {
		c.Delete(ctx, svc)
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
func validateNodePortRanges(ctx context.Context, client client.Client, tsNamespace string, portRanges []tsapi.PortRange, logger *zap.SugaredLogger) error {
	kubeRange := getServicesNodePortRange(ctx, client, tsNamespace, logger)
	if kubeRange == nil {
		logger.Warnf("Unable to determine NodePort range for the Kubernetes API server; skipping Kubernetes NodePort range validation.")
	}

	if kubeRange != nil {
		for _, pr := range portRanges {
			if !kubeRange.Contains(pr.Port) || (pr.EndPort != 0 && !kubeRange.Contains(pr.EndPort)) {
				return fmt.Errorf("range %q is not within Cluster configured range %q", pr.String(), kubeRange.String())
			}
		}
	}

	for _, r := range portRanges {
		if r.EndPort != 0 && r.EndPort < r.Port {
			return fmt.Errorf("endPort '%d' cannot be less than port '%d'", r.EndPort, r.Port)
		}
	}

	if len(portRanges) == 1 {
		return nil
	}

	sort.Slice(portRanges, func(i, j int) bool {
		return portRanges[i].Port < portRanges[j].EndPort
	})

	for i := 1; i < len(portRanges); i++ {
		prev := portRanges[i-1]
		curr := portRanges[i]
		if (curr.Port <= prev.EndPort) || (prev.EndPort == 0 && curr.Contains(prev.Port)) {
			return fmt.Errorf("overlapping ranges: %q and %q", prev.String(), curr.String())
		}
	}

	return nil
}

func getRandomPort() uint16 {
	return uint16(rand.IntN(tailscaledPortMax-tailscaledPortMin+1) + tailscaledPortMin)
}
