// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"tailscale.com/kube/kubetypes"
)

const (
	invalidSvcName     = "invalid-service"
	invalidSvcNodePort = 777777
)

var kubePortRangeErr = fmt.Sprintf("Service \"%s\" is invalid: spec.ports[0].nodePort: Invalid value: %d: provided port is not in the valid range. The range of valid ports is ", invalidSvcName, invalidSvcNodePort)

type portRange struct {
	Start  int
	End    int
	String string
}

func validateRange(s int, e int) error {
	if s < 0 || s > 65535 {
		return fmt.Errorf("invalid port value: %q", s)
	}
	if e < 0 || e > 65535 {
		return fmt.Errorf("invalid port value: %q", e)
	}
	if s > e {
		return fmt.Errorf("invalid port range: '%d-%d'", s, e)
	}

	return nil
}

// getKubeRange is a hacky function that attempts to create a deliberately invalid
// Service with a NodePort that is too large. This gives us back an error message
// which contains the configured NodePort Range set on the cluster.
// We don't return an error here, if this validation doesn't work we don't perform it
func getKubeRange(ctx context.Context, c client.Client, tsNamespace string) *portRange {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      invalidSvcName,
			Namespace: tsNamespace,
			Labels: map[string]string{
				kubetypes.LabelManaged: "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Name:       "invalid",
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

	// github.com/kubernetes/kubernetes/blob/master/pkg/registry/core/service/portallocator/allocator.go#L51-L53
	r, found := strings.CutPrefix(err.Error(), kubePortRangeErr)
	if !found {
		return nil
	}

	pr, _ := parseRange(r)

	return pr
}

func parseRange(p string) (*portRange, error) {
	parts := strings.Split(p, "-")
	switch len(parts) {
	case 1:
		s, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse port range %q: %w", p, err)
		}
		e := s

		err = validateRange(s, e)
		if err != nil {
			return nil, err
		}

		return &portRange{Start: s, End: e, String: p}, nil
	case 2:
		s, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse port range %q: %w", p, err)
		}
		e, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to parse port range %q: %w", p, err)
		}

		err = validateRange(s, e)
		if err != nil {
			return nil, err
		}

		return &portRange{Start: s, End: e, String: p}, nil
	default:
		return nil, fmt.Errorf("failed to parse port range %q", p)
	}
}

func validatePortRanges(ctx context.Context, client client.Client, tsNamespace string, pr []string, logger *zap.SugaredLogger) ([]portRange, error) {
	kubeRange := getKubeRange(ctx, client, tsNamespace)
	if kubeRange == nil {
		logger.Warnf("Unable to determine NodePort range for the Kubernetes API server; skipping Kubernetes NodePort range validation.")
	}

	ranges := []portRange{}
	for _, p := range pr {
		r, err := parseRange(p)
		if err != nil {
			return nil, fmt.Errorf("failed to parse port range: %w", err)
		}

		if kubeRange != nil {
			if r.Start < kubeRange.Start {
				return nil, fmt.Errorf("range %q is not within Cluster configured range %q", r.String, kubeRange.String)
			}
			if r.End > kubeRange.End {
				return nil, fmt.Errorf("range %q is not within Cluster configured range %q", r.String, kubeRange.String)
			}
		}

		ranges = append(ranges, *r)
	}

	if len(ranges) < 2 {
		return ranges, nil
	}

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].Start < ranges[j].Start
	})

	for i := 1; i < len(ranges); i++ {
		prev := ranges[i-1]
		curr := ranges[i]
		if curr.Start <= prev.End {
			return nil, fmt.Errorf("overlapping ranges: %q and %q", prev.String, curr.String)
		}
	}

	return ranges, nil
}

func getRandomPort() int32 {
	return int32(rand.IntN(portMax-portMin+1) + portMin)
}
