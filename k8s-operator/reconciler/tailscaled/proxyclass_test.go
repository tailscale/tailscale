// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailscaled_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
)

func TestApplyProxyClass_Env(t *testing.T) {
	t.Parallel()

	ss := &appsv1.StatefulSet{}
	ss.Spec.Template.Spec.Containers = []corev1.Container{{
		Name: "tailscaled",
		Env: []corev1.EnvVar{
			{Name: "TS_KUBE_SECRET", Value: "$(POD_NAME)"},
			{Name: "TS_ENABLE_HEALTH_CHECK", Value: "true"},
		},
	}}

	pc := &tsapi.ProxyClass{
		Spec: tsapi.ProxyClassSpec{
			Metrics: &tsapi.Metrics{Enable: true},
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleContainer: &tsapi.Container{
						Env: []tsapi.Env{
							{Name: "TS_ENABLE_METRICS", Value: "false"},
							{Name: "TS_ENABLE_HEALTH_CHECK", Value: "false"},
							{Name: "TS_DEBUG_FIREWALL_MODE", Value: "auto"},
						},
					},
				},
			},
		},
	}

	// ProxyClass env replaces the operator's entries of the same name, so each name appears once.
	want := []corev1.EnvVar{
		{Name: "TS_KUBE_SECRET", Value: "$(POD_NAME)"},
		{Name: "TS_ENABLE_HEALTH_CHECK", Value: "false"},
		{Name: "TS_ENABLE_METRICS", Value: "false"},
		{Name: "TS_DEBUG_FIREWALL_MODE", Value: "auto"},
	}

	got := tailscaled.ApplyProxyClass(ss, pc, nil, nil).Spec.Template.Spec.Containers[0].Env
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("container env mismatch (-want +got):\n%s", diff)
	}
}
