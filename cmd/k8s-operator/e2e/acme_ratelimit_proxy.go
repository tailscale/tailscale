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

// applyACMERatelimitProxyResources deploys the rate-limit proxy.
// Called after the image is built and loaded so the pod can come up
// without an ImagePullBackOff stall.
func applyACMERatelimitProxyResources(ctx context.Context, cl client.Client, tag string) error {
	owner := client.FieldOwner("k8s-test")
	for _, r := range []client.Object{
		acmeRateLimitProxyDeployment(tag),
		acmeRateLimitProxyService(),
	} {
		if err := cl.Patch(ctx, r, client.Apply, owner); err != nil {
			return fmt.Errorf("apply %T %s/%s: %w", r, r.GetNamespace(), r.GetName(), err)
		}
	}
	return nil
}

func acmeRateLimitProxyDeployment(tag string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "acme-ratelimit",
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "acme-ratelimit"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "acme-ratelimit"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:            "proxy",
						Image:           "local/acmeratelimitproxy:" + tag,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Ports: []corev1.ContainerPort{
							{Name: "acme", ContainerPort: 14000},
							{Name: "admin", ContainerPort: 14999},
						},
					}},
				},
			},
		},
	}
}

func acmeRateLimitProxyService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "acme-ratelimit",
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: map[string]string{"app": "acme-ratelimit"},
			Ports: []corev1.ServicePort{
				{Name: "acme", Port: 14000, TargetPort: intstr.FromInt(14000)},
				{Name: "admin", Port: 14999, TargetPort: intstr.FromInt(14999)},
			},
		},
	}
}
