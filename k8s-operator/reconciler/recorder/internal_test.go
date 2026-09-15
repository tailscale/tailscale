// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package recorder

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

const (
	tsNamespace   = "tailscale"
	tsLoginServer = "example.tailscale.com"
)

func TestRecorderSpecs(t *testing.T) {
	t.Run("spec-fields-passthrough", func(t *testing.T) {
		tsr := &tsapi.Recorder{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
			Spec: tsapi.RecorderSpec{
				Replicas: new(int32(3)),
				StatefulSet: tsapi.RecorderStatefulSet{
					Labels: map[string]string{
						"ss-label-key": "ss-label-value",
					},
					Annotations: map[string]string{
						"ss-annotation-key": "ss-annotation-value",
					},
					Pod: tsapi.RecorderPod{
						Labels: map[string]string{
							"pod-label-key": "pod-label-value",
						},
						Annotations: map[string]string{
							"pod-annotation-key": "pod-annotation-value",
						},
						Affinity: &corev1.Affinity{
							PodAffinity: &corev1.PodAffinity{
								RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"match-label": "match-value",
										},
									}},
								},
							},
						},
						SecurityContext: &corev1.PodSecurityContext{
							RunAsUser: new(int64(1000)),
						},
						ImagePullSecrets: []corev1.LocalObjectReference{{
							Name: "img-pull",
						}},
						NodeSelector: map[string]string{
							"some-node": "selector",
						},
						Tolerations: []corev1.Toleration{{
							Key:               "key",
							Value:             "value",
							TolerationSeconds: new(int64(60)),
						}},
						Container: tsapi.RecorderContainer{
							Env: []tsapi.Env{{
								Name:  "some_env",
								Value: "env_value",
							}},
							Image:           "custom-image",
							ImagePullPolicy: corev1.PullAlways,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"NET_ADMIN",
									},
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU: resource.MustParse("100m"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU: resource.MustParse("50m"),
								},
							},
						},
					},
				},
			},
		}

		ss := tsrStatefulSet(tsr, tsNamespace, tsLoginServer)

		// StatefulSet-level.
		if diff := cmp.Diff(ss.Annotations, tsr.Spec.StatefulSet.Annotations); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Annotations, tsr.Spec.StatefulSet.Pod.Annotations); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}

		// Pod-level.
		if diff := cmp.Diff(ss.Labels, tsrLabels("recorder", "test", tsr.Spec.StatefulSet.Labels)); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Labels, tsrLabels("recorder", "test", tsr.Spec.StatefulSet.Pod.Labels)); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Spec.Affinity, tsr.Spec.StatefulSet.Pod.Affinity); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Spec.SecurityContext, tsr.Spec.StatefulSet.Pod.SecurityContext); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Spec.ImagePullSecrets, tsr.Spec.StatefulSet.Pod.ImagePullSecrets); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Spec.NodeSelector, tsr.Spec.StatefulSet.Pod.NodeSelector); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Spec.Tolerations, tsr.Spec.StatefulSet.Pod.Tolerations); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}

		// Container-level.
		if diff := cmp.Diff(ss.Spec.Template.Spec.Containers[0].Env, tsrEnv(tsr, tsLoginServer)); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Spec.Containers[0].Image, tsr.Spec.StatefulSet.Pod.Container.Image); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Spec.Containers[0].ImagePullPolicy, tsr.Spec.StatefulSet.Pod.Container.ImagePullPolicy); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Spec.Containers[0].SecurityContext, tsr.Spec.StatefulSet.Pod.Container.SecurityContext); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
		if diff := cmp.Diff(ss.Spec.Template.Spec.Containers[0].Resources, tsr.Spec.StatefulSet.Pod.Container.Resources); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}

		if *ss.Spec.Replicas != *tsr.Spec.Replicas {
			t.Errorf("expected %d replicas, got %d", *tsr.Spec.Replicas, *ss.Spec.Replicas)
		}

		if len(ss.Spec.Template.Spec.Volumes) != int(*tsr.Spec.Replicas)+1 {
			t.Errorf("expected %d volumes, got %d", *tsr.Spec.Replicas+1, len(ss.Spec.Template.Spec.Volumes))
		}

		if len(ss.Spec.Template.Spec.Containers[0].VolumeMounts) != int(*tsr.Spec.Replicas)+1 {
			t.Errorf("expected %d volume mounts, got %d", *tsr.Spec.Replicas+1, len(ss.Spec.Template.Spec.Containers[0].VolumeMounts))
		}
	})

	t.Run("role-grants-access-to-every-replica-secret", func(t *testing.T) {
		tsr := &tsapi.Recorder{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec:       tsapi.RecorderSpec{Replicas: new(int32(2))},
		}

		// The replica needs get/patch/update on its own state and auth Secrets so containerboot can persist
		// device state, plus event creation so it can report problems against itself.
		want := []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				Verbs:         []string{"get", "patch", "update"},
				ResourceNames: []string{"test-0", "test-auth-0", "test-1", "test-auth-1"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"get", "create", "patch"},
			},
		}
		if diff := cmp.Diff(tsrRole(tsr, tsNamespace).Rules, want); diff != "" {
			t.Errorf("(-got +want):\n%s", diff)
		}
	})

	t.Run("service-account-name-defaults-to-recorder-name", func(t *testing.T) {
		tsr := &tsapi.Recorder{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
		if got := tsrServiceAccountName(tsr); got != "test" {
			t.Errorf("got %q, want %q", got, "test")
		}

		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = "custom"
		if got := tsrServiceAccountName(tsr); got != "custom" {
			t.Errorf("got %q, want %q", got, "custom")
		}
	})
}
