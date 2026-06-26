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
)

func applyPebbleResources(ctx context.Context, cl client.Client) error {
	owner := client.FieldOwner("k8s-test")
	resources := []client.Object{
		pebbleConfigMap(),
		pebbleDeployment(pebbleTag),
		pebbleService(),
		tailscaleNamespace(),
		pebbleExternalNameService(),
	}
	for _, r := range resources {
		if err := cl.Patch(ctx, r, client.Apply, owner); err != nil {
			return fmt.Errorf("apply %T %s/%s: %w", r, r.GetNamespace(), r.GetName(), err)
		}
	}
	return nil
}

// pebbleConfigJSON tells Pebble to issue short-lived certs so the cascade
// renewal subtest can observe a renewal cycle within ~2 minutes (cert
// hits 2/3 lifetime at 120s). v2.8+ ignores the deprecated
// certificateValidityPeriod field; validity goes on the profile.
const pebbleConfigJSON = `{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "profiles": {
      "default": {
        "description": "Short-lived for cascade e2e",
        "validityPeriod": 180
      }
    }
  }
}`

func pebbleConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pebble-config",
			Namespace: ns,
		},
		Data: map[string]string{"pebble-config.json": pebbleConfigJSON},
	}
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
			Replicas: new(int32(1)),
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
					Volumes: []corev1.Volume{{
						Name: "pebble-config",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "pebble-config",
								},
							},
						},
					}},
					Containers: []corev1.Container{
						{
							Name:            "pebble",
							Image:           fmt.Sprintf("ghcr.io/letsencrypt/pebble:%s", tag),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args: []string{
								"-dnsserver=localhost:8053",
								"-config=/etc/pebble/pebble-config.json",
								"-strict",
							},
							VolumeMounts: []corev1.VolumeMount{{
								Name:      "pebble-config",
								MountPath: "/etc/pebble",
								ReadOnly:  true,
							}},
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
								{
									// Don't reuse authz; renewal subtest
									// reissues immediately after issuance.
									Name:  "PEBBLE_AUTHZREUSE",
									Value: "0",
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

// pebbleExternalNameService gives tailscaled in the tailscale namespace a
// "pebble" hostname that matches Pebble's TLS cert SAN. The cascade test
// points the alias at the acme-ratelimit proxy in the default namespace so
// new-order POSTs can be intercepted before they reach Pebble.
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
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "acme-ratelimit.default.svc.cluster.local",
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
