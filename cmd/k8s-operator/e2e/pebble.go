// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/types/ptr"
)

func applyPebbleResources(ctx context.Context, cl client.Client) error {
	owner := client.FieldOwner("k8s-test")

	if err := cl.Patch(ctx, pebbleDeployment(pebbleTag), client.Apply, owner); err != nil {
		return fmt.Errorf("failed to apply pebble Deployment: %w", err)
	}
	if err := cl.Patch(ctx, pebbleService(), client.Apply, owner); err != nil {
		return fmt.Errorf("failed to apply pebble Service: %w", err)
	}
	if err := cl.Patch(ctx, tailscaleNamespace(), client.Apply, owner); err != nil {
		return fmt.Errorf("failed to apply tailscale Namespace: %w", err)
	}
	if err := cl.Patch(ctx, pebbleExternalNameService(), client.Apply, owner); err != nil {
		return fmt.Errorf("failed to apply pebble ExternalName Service: %w", err)
	}

	return nil
}

func pebbleDeployment(tag string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pebble",
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "pebble",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "pebble",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            "pebble",
							Image:           fmt.Sprintf("ghcr.io/letsencrypt/pebble:%s", tag),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args: []string{
								"-dnsserver=localhost:8053",
								"-strict",
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "acme",
									ContainerPort: 14000,
								},
								{
									Name:          "pebble-api",
									ContainerPort: 15000,
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "PEBBLE_VA_NOSLEEP",
									Value: "1",
								},
							},
						},
						{
							Name:            "challtestsrv",
							Image:           fmt.Sprintf("ghcr.io/letsencrypt/pebble-challtestsrv:%s", tag),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args:            []string{"-defaultIPv6="},
							Ports: []corev1.ContainerPort{
								{
									Name:          "mgmt-api",
									ContainerPort: 8055,
								},
							},
						},
					},
				},
			},
		},
	}
}

func pebbleService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pebble",
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app": "pebble",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "acme",
					Port:       14000,
					TargetPort: intstr.FromInt(14000),
				},
				{
					Name:       "pebble-api",
					Port:       15000,
					TargetPort: intstr.FromInt(15000),
				},
				{
					Name:       "mgmt-api",
					Port:       8055,
					TargetPort: intstr.FromInt(8055),
				},
			},
		},
	}
}

func tailscaleNamespace() *corev1.Namespace {
	return &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tailscale",
		},
	}
}

// pebbleExternalNameService ensures the operator in the tailscale namespace
// can reach pebble on a DNS name (pebble) that matches its TLS cert.
func pebbleExternalNameService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pebble",
			Namespace: "tailscale",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeExternalName,
			Selector: map[string]string{
				"app": "pebble",
			},
			ExternalName: "pebble.default.svc.cluster.local",
		},
	}
}
