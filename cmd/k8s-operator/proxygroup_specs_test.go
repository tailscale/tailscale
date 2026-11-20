// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

func TestKubeAPIServerRestrictedPodSecurity(t *testing.T) {
	restricted := &corev1.SecurityContext{
		AllowPrivilegeEscalation: new(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		ReadOnlyRootFilesystem:   new(true),
		RunAsNonRoot:             new(true),
		RunAsUser:                new(int64(65532)),
		RunAsGroup:               new(int64(65532)),
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	custom := &corev1.SecurityContext{RunAsUser: new(int64(1000))}
	podFieldsOnly := &tsapi.ProxyClass{Spec: tsapi.ProxyClassSpec{StatefulSet: &tsapi.StatefulSet{
		Pod: &tsapi.Pod{NodeSelector: map[string]string{"kubernetes.io/os": "linux"}},
	}}}

	tests := []struct {
		name       string
		restricted bool
		pc         *tsapi.ProxyClass
		want       *corev1.SecurityContext
	}{
		{
			name: "off_by_default",
			pc:   podFieldsOnly,
		},
		{
			name:       "on",
			restricted: true,
			want:       restricted,
		},
		{
			// A ProxyClass Pod override must not drop the container context.
			name:       "on_with_proxyclass_pod_fields",
			restricted: true,
			pc:         podFieldsOnly,
			want:       restricted,
		},
		{
			name:       "on_proxyclass_container_security_context_wins",
			restricted: true,
			pc: &tsapi.ProxyClass{Spec: tsapi.ProxyClassSpec{StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{TailscaleContainer: &tsapi.Container{SecurityContext: custom}},
			}}},
			want: custom,
		},
	}

	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver"},
		Spec:       tsapi.ProxyGroupSpec{Type: tsapi.ProxyGroupTypeKubernetesAPIServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss, err := pgStatefulSet(pg, "tailscale", "tailscale/k8s-proxy:test", "", nil, tt.pc, false)
			if err != nil {
				t.Fatal(err)
			}
			// ProxyClass applies last, as in ProxyGroupReconciler.
			if tt.restricted {
				applyRestrictedPodSecurity(ss)
			}
			ss = applyProxyClassToStatefulSet(tt.pc, ss, nil, zl.Sugar())

			c := ss.Spec.Template.Spec.Containers[0]
			if diff := cmp.Diff(tt.want, c.SecurityContext); diff != "" {
				t.Errorf("k8s-proxy container security context (-want +got):\n%s", diff)
			}

			// tsnet needs a writable state dir.
			var (
				wantEnv    bool
				wantMounts []corev1.VolumeMount
				wantVols   []corev1.Volume
			)
			if tt.restricted {
				wantEnv = true
				wantMounts = []corev1.VolumeMount{{Name: "tmp", MountPath: "/tmp"}}
				wantVols = []corev1.Volume{{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
			}
			if got := hasEnv(c.Env, "XDG_CONFIG_HOME", "/tmp"); got != wantEnv {
				t.Errorf("XDG_CONFIG_HOME=/tmp set = %v, want %v", got, wantEnv)
			}
			if diff := cmp.Diff(wantMounts, c.VolumeMounts); diff != "" {
				t.Errorf("k8s-proxy volume mounts (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(wantVols, ss.Spec.Template.Spec.Volumes); diff != "" {
				t.Errorf("k8s-proxy volumes (-want +got):\n%s", diff)
			}
		})
	}
}

func hasEnv(env []corev1.EnvVar, name, value string) bool {
	for _, e := range env {
		if e.Name == name && e.Value == value {
			return true
		}
	}
	return false
}
