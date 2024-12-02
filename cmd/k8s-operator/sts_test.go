// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	_ "embed"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/types/ptr"
)

// Test_statefulSetNameBase tests that parent name portion in a StatefulSet name
// base will be truncated if the parent name is longer than 43 chars to ensure
// that the total does not exceed 52 chars.
// How many chars need to be cut off parent name depends on an internal var in
// kube name generation code that can change at which point this test will break
// and need to be changed. This is okay as we do not rely on that value in
// code whilst being aware when it changes might still be useful.
// https://github.com/kubernetes/kubernetes/blob/v1.28.4/staging/src/k8s.io/apiserver/pkg/storage/names/generate.go#L45.
// https://github.com/kubernetes/kubernetes/pull/116430
func Test_statefulSetNameBase(t *testing.T) {
	// Service name lengths can be 1 - 63 chars, be paranoid and test them all.
	var b strings.Builder
	for b.Len() < 63 {
		if _, err := b.WriteString("a"); err != nil {
			t.Fatalf("error writing to string builder: %v", err)
		}
		baseLength := b.Len()
		if baseLength > 43 {
			baseLength = 43 // currently 43 is the max base length
		}
		wantsNameR := regexp.MustCompile(`^ts-a{` + fmt.Sprint(baseLength) + `}-$`) // to match a string like ts-aaaa-
		gotName := statefulSetNameBase(b.String())
		if !wantsNameR.MatchString(gotName) {
			t.Fatalf("expected string %s to match regex %s ", gotName, wantsNameR.String()) // fatal rather than error as this test is called 63 times
		}
	}
}

func Test_applyProxyClassToStatefulSet(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	// Setup
	proxyClassAllOpts := &tsapi.ProxyClass{
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Labels:      map[string]string{"foo": "bar"},
				Annotations: map[string]string{"foo.io/bar": "foo"},
				Pod: &tsapi.Pod{
					Labels:      map[string]string{"bar": "foo"},
					Annotations: map[string]string{"bar.io/foo": "foo"},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser: ptr.To(int64(0)),
					},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "docker-creds"}},
					NodeName:         "some-node",
					NodeSelector:     map[string]string{"beta.kubernetes.io/os": "linux"},
					Affinity:         &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{}}},
					Tolerations:      []corev1.Toleration{{Key: "", Operator: "Exists"}},
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
						{
							WhenUnsatisfiable: "DoNotSchedule",
							TopologyKey:       "kubernetes.io/hostname",
							MaxSkew:           3,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					TailscaleContainer: &tsapi.Container{
						SecurityContext: &corev1.SecurityContext{
							Privileged: ptr.To(true),
						},
						Resources: corev1.ResourceRequirements{
							Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1000m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
						},
						Env:             []tsapi.Env{{Name: "foo", Value: "bar"}, {Name: "TS_USERSPACE", Value: "true"}, {Name: "bar"}},
						ImagePullPolicy: "IfNotPresent",
						Image:           "ghcr.io/my-repo/tailscale:v0.01testsomething",
					},
					TailscaleInitContainer: &tsapi.Container{
						SecurityContext: &corev1.SecurityContext{
							Privileged: ptr.To(true),
							RunAsUser:  ptr.To(int64(0)),
						},
						Resources: corev1.ResourceRequirements{
							Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1000m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
						},
						Env:             []tsapi.Env{{Name: "foo", Value: "bar"}, {Name: "TS_USERSPACE", Value: "true"}, {Name: "bar"}},
						ImagePullPolicy: "IfNotPresent",
						Image:           "ghcr.io/my-repo/tailscale:v0.01testsomething",
					},
				},
			},
		},
	}
	proxyClassJustLabels := &tsapi.ProxyClass{
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Labels:      map[string]string{"foo": "bar"},
				Annotations: map[string]string{"foo.io/bar": "foo"},
				Pod: &tsapi.Pod{
					Labels:      map[string]string{"bar": "foo"},
					Annotations: map[string]string{"bar.io/foo": "foo"},
				},
			},
		},
	}

	proxyClassWithMetricsDebug := func(metrics bool, debug *bool) *tsapi.ProxyClass {
		return &tsapi.ProxyClass{
			Spec: tsapi.ProxyClassSpec{
				Metrics: &tsapi.Metrics{Enable: metrics},
				StatefulSet: func() *tsapi.StatefulSet {
					if debug == nil {
						return nil
					}

					return &tsapi.StatefulSet{
						Pod: &tsapi.Pod{
							TailscaleContainer: &tsapi.Container{
								Debug: &tsapi.Debug{Enable: *debug},
							},
						},
					}
				}(),
			},
		}
	}

	var userspaceProxySS, nonUserspaceProxySS appsv1.StatefulSet
	if err := yaml.Unmarshal(userspaceProxyYaml, &userspaceProxySS); err != nil {
		t.Fatalf("unmarshaling userspace proxy template: %v", err)
	}
	if err := yaml.Unmarshal(proxyYaml, &nonUserspaceProxySS); err != nil {
		t.Fatalf("unmarshaling non-userspace proxy template: %v", err)
	}
	// Set a couple additional fields so we can test that we don't
	// mistakenly override those.
	labels := map[string]string{
		LabelManaged:    "true",
		LabelParentName: "foo",
	}
	annots := map[string]string{
		podAnnotationLastSetClusterIP: "1.2.3.4",
	}
	env := []corev1.EnvVar{{Name: "TS_HOSTNAME", Value: "nginx"}}
	userspaceProxySS.Labels = labels
	userspaceProxySS.Annotations = annots
	userspaceProxySS.Spec.Template.Spec.Containers[0].Image = "tailscale/tailscale:v0.0.1"
	userspaceProxySS.Spec.Template.Spec.Containers[0].Env = env
	nonUserspaceProxySS.ObjectMeta.Labels = labels
	nonUserspaceProxySS.ObjectMeta.Annotations = annots
	nonUserspaceProxySS.Spec.Template.Spec.Containers[0].Env = env
	nonUserspaceProxySS.Spec.Template.Spec.InitContainers[0].Image = "tailscale/tailscale:v0.0.1"

	// 1. Test that a ProxyClass with all fields set gets correctly applied
	// to a Statefulset built from non-userspace proxy template.
	wantSS := nonUserspaceProxySS.DeepCopy()
	wantSS.ObjectMeta.Labels = mergeMapKeys(wantSS.ObjectMeta.Labels, proxyClassAllOpts.Spec.StatefulSet.Labels)
	wantSS.ObjectMeta.Annotations = mergeMapKeys(wantSS.ObjectMeta.Annotations, proxyClassAllOpts.Spec.StatefulSet.Annotations)
	wantSS.Spec.Template.Labels = proxyClassAllOpts.Spec.StatefulSet.Pod.Labels
	wantSS.Spec.Template.Annotations = proxyClassAllOpts.Spec.StatefulSet.Pod.Annotations
	wantSS.Spec.Template.Spec.SecurityContext = proxyClassAllOpts.Spec.StatefulSet.Pod.SecurityContext
	wantSS.Spec.Template.Spec.ImagePullSecrets = proxyClassAllOpts.Spec.StatefulSet.Pod.ImagePullSecrets
	wantSS.Spec.Template.Spec.NodeName = proxyClassAllOpts.Spec.StatefulSet.Pod.NodeName
	wantSS.Spec.Template.Spec.NodeSelector = proxyClassAllOpts.Spec.StatefulSet.Pod.NodeSelector
	wantSS.Spec.Template.Spec.Affinity = proxyClassAllOpts.Spec.StatefulSet.Pod.Affinity
	wantSS.Spec.Template.Spec.Tolerations = proxyClassAllOpts.Spec.StatefulSet.Pod.Tolerations
	wantSS.Spec.Template.Spec.TopologySpreadConstraints = proxyClassAllOpts.Spec.StatefulSet.Pod.TopologySpreadConstraints
	wantSS.Spec.Template.Spec.Containers[0].SecurityContext = proxyClassAllOpts.Spec.StatefulSet.Pod.TailscaleContainer.SecurityContext
	wantSS.Spec.Template.Spec.InitContainers[0].SecurityContext = proxyClassAllOpts.Spec.StatefulSet.Pod.TailscaleInitContainer.SecurityContext
	wantSS.Spec.Template.Spec.Containers[0].Resources = proxyClassAllOpts.Spec.StatefulSet.Pod.TailscaleContainer.Resources
	wantSS.Spec.Template.Spec.InitContainers[0].Resources = proxyClassAllOpts.Spec.StatefulSet.Pod.TailscaleInitContainer.Resources
	wantSS.Spec.Template.Spec.InitContainers[0].Env = append(wantSS.Spec.Template.Spec.InitContainers[0].Env, []corev1.EnvVar{{Name: "foo", Value: "bar"}, {Name: "TS_USERSPACE", Value: "true"}, {Name: "bar"}}...)
	wantSS.Spec.Template.Spec.Containers[0].Env = append(wantSS.Spec.Template.Spec.Containers[0].Env, []corev1.EnvVar{{Name: "foo", Value: "bar"}, {Name: "TS_USERSPACE", Value: "true"}, {Name: "bar"}}...)
	wantSS.Spec.Template.Spec.Containers[0].Image = "ghcr.io/my-repo/tailscale:v0.01testsomething"
	wantSS.Spec.Template.Spec.Containers[0].ImagePullPolicy = "IfNotPresent"
	wantSS.Spec.Template.Spec.InitContainers[0].Image = "ghcr.io/my-repo/tailscale:v0.01testsomething"
	wantSS.Spec.Template.Spec.InitContainers[0].ImagePullPolicy = "IfNotPresent"

	gotSS := applyProxyClassToStatefulSet(proxyClassAllOpts, nonUserspaceProxySS.DeepCopy(), new(tailscaleSTSConfig), zl.Sugar())
	if diff := cmp.Diff(gotSS, wantSS); diff != "" {
		t.Errorf("Unexpected result applying ProxyClass with all fields set to a StatefulSet for non-userspace proxy (-got +want):\n%s", diff)
	}

	// 2. Test that a ProxyClass with custom labels and annotations for
	// StatefulSet and Pod set gets correctly applied to a Statefulset built
	// from non-userspace proxy template.
	wantSS = nonUserspaceProxySS.DeepCopy()
	wantSS.ObjectMeta.Labels = mergeMapKeys(wantSS.ObjectMeta.Labels, proxyClassJustLabels.Spec.StatefulSet.Labels)
	wantSS.ObjectMeta.Annotations = mergeMapKeys(wantSS.ObjectMeta.Annotations, proxyClassJustLabels.Spec.StatefulSet.Annotations)
	wantSS.Spec.Template.Labels = proxyClassJustLabels.Spec.StatefulSet.Pod.Labels
	wantSS.Spec.Template.Annotations = proxyClassJustLabels.Spec.StatefulSet.Pod.Annotations
	gotSS = applyProxyClassToStatefulSet(proxyClassJustLabels, nonUserspaceProxySS.DeepCopy(), new(tailscaleSTSConfig), zl.Sugar())
	if diff := cmp.Diff(gotSS, wantSS); diff != "" {
		t.Errorf("Unexpected result applying ProxyClass with custom labels and annotations to a StatefulSet for non-userspace proxy (-got +want):\n%s", diff)
	}

	// 3. Test that a ProxyClass with all fields set gets correctly applied
	// to a Statefulset built from a userspace proxy template.
	wantSS = userspaceProxySS.DeepCopy()
	wantSS.ObjectMeta.Labels = mergeMapKeys(wantSS.ObjectMeta.Labels, proxyClassAllOpts.Spec.StatefulSet.Labels)
	wantSS.ObjectMeta.Annotations = mergeMapKeys(wantSS.ObjectMeta.Annotations, proxyClassAllOpts.Spec.StatefulSet.Annotations)
	wantSS.Spec.Template.Labels = proxyClassAllOpts.Spec.StatefulSet.Pod.Labels
	wantSS.Spec.Template.Annotations = proxyClassAllOpts.Spec.StatefulSet.Pod.Annotations
	wantSS.Spec.Template.Spec.SecurityContext = proxyClassAllOpts.Spec.StatefulSet.Pod.SecurityContext
	wantSS.Spec.Template.Spec.ImagePullSecrets = proxyClassAllOpts.Spec.StatefulSet.Pod.ImagePullSecrets
	wantSS.Spec.Template.Spec.NodeName = proxyClassAllOpts.Spec.StatefulSet.Pod.NodeName
	wantSS.Spec.Template.Spec.NodeSelector = proxyClassAllOpts.Spec.StatefulSet.Pod.NodeSelector
	wantSS.Spec.Template.Spec.Affinity = proxyClassAllOpts.Spec.StatefulSet.Pod.Affinity
	wantSS.Spec.Template.Spec.Tolerations = proxyClassAllOpts.Spec.StatefulSet.Pod.Tolerations
	wantSS.Spec.Template.Spec.TopologySpreadConstraints = proxyClassAllOpts.Spec.StatefulSet.Pod.TopologySpreadConstraints
	wantSS.Spec.Template.Spec.Containers[0].SecurityContext = proxyClassAllOpts.Spec.StatefulSet.Pod.TailscaleContainer.SecurityContext
	wantSS.Spec.Template.Spec.Containers[0].Resources = proxyClassAllOpts.Spec.StatefulSet.Pod.TailscaleContainer.Resources
	wantSS.Spec.Template.Spec.Containers[0].Env = append(wantSS.Spec.Template.Spec.Containers[0].Env, []corev1.EnvVar{{Name: "foo", Value: "bar"}, {Name: "TS_USERSPACE", Value: "true"}, {Name: "bar"}}...)
	wantSS.Spec.Template.Spec.Containers[0].ImagePullPolicy = "IfNotPresent"
	wantSS.Spec.Template.Spec.Containers[0].Image = "ghcr.io/my-repo/tailscale:v0.01testsomething"
	gotSS = applyProxyClassToStatefulSet(proxyClassAllOpts, userspaceProxySS.DeepCopy(), new(tailscaleSTSConfig), zl.Sugar())
	if diff := cmp.Diff(gotSS, wantSS); diff != "" {
		t.Errorf("Unexpected result applying ProxyClass with all options to a StatefulSet for a userspace proxy (-got +want):\n%s", diff)
	}

	// 4. Test that a ProxyClass with custom labels and annotations gets correctly applied
	// to a Statefulset built from a userspace proxy template.
	wantSS = userspaceProxySS.DeepCopy()
	wantSS.ObjectMeta.Labels = mergeMapKeys(wantSS.ObjectMeta.Labels, proxyClassJustLabels.Spec.StatefulSet.Labels)
	wantSS.ObjectMeta.Annotations = mergeMapKeys(wantSS.ObjectMeta.Annotations, proxyClassJustLabels.Spec.StatefulSet.Annotations)
	wantSS.Spec.Template.Labels = proxyClassJustLabels.Spec.StatefulSet.Pod.Labels
	wantSS.Spec.Template.Annotations = proxyClassJustLabels.Spec.StatefulSet.Pod.Annotations
	gotSS = applyProxyClassToStatefulSet(proxyClassJustLabels, userspaceProxySS.DeepCopy(), new(tailscaleSTSConfig), zl.Sugar())
	if diff := cmp.Diff(gotSS, wantSS); diff != "" {
		t.Errorf("Unexpected result applying ProxyClass with custom labels and annotations to a StatefulSet for a userspace proxy (-got +want):\n%s", diff)
	}

	// 5. Metrics enabled defaults to enabling both metrics and debug.
	wantSS = nonUserspaceProxySS.DeepCopy()
	wantSS.Spec.Template.Spec.Containers[0].Env = append(wantSS.Spec.Template.Spec.Containers[0].Env,
		corev1.EnvVar{Name: "TS_DEBUG_ADDR_PORT", Value: "$(POD_IP):9001"},
		corev1.EnvVar{Name: "TS_TAILSCALED_EXTRA_ARGS", Value: "--debug=$(TS_DEBUG_ADDR_PORT)"},
		corev1.EnvVar{Name: "TS_LOCAL_ADDR_PORT", Value: "$(POD_IP):9002"},
		corev1.EnvVar{Name: "TS_ENABLE_METRICS", Value: "true"},
	)
	wantSS.Spec.Template.Spec.Containers[0].Ports = []corev1.ContainerPort{
		{Name: "debug", Protocol: "TCP", ContainerPort: 9001},
		{Name: "metrics", Protocol: "TCP", ContainerPort: 9002},
	}
	gotSS = applyProxyClassToStatefulSet(proxyClassWithMetricsDebug(true, nil), nonUserspaceProxySS.DeepCopy(), new(tailscaleSTSConfig), zl.Sugar())
	if diff := cmp.Diff(gotSS, wantSS); diff != "" {
		t.Errorf("Unexpected result applying ProxyClass with metrics enabled to a StatefulSet (-got +want):\n%s", diff)
	}

	// 6. Enable _just_ metrics by explicitly disabling debug.
	wantSS = nonUserspaceProxySS.DeepCopy()
	wantSS.Spec.Template.Spec.Containers[0].Env = append(wantSS.Spec.Template.Spec.Containers[0].Env,
		corev1.EnvVar{Name: "TS_LOCAL_ADDR_PORT", Value: "$(POD_IP):9002"},
		corev1.EnvVar{Name: "TS_ENABLE_METRICS", Value: "true"},
	)
	wantSS.Spec.Template.Spec.Containers[0].Ports = []corev1.ContainerPort{{Name: "metrics", Protocol: "TCP", ContainerPort: 9002}}
	gotSS = applyProxyClassToStatefulSet(proxyClassWithMetricsDebug(true, ptr.To(false)), nonUserspaceProxySS.DeepCopy(), new(tailscaleSTSConfig), zl.Sugar())
	if diff := cmp.Diff(gotSS, wantSS); diff != "" {
		t.Errorf("Unexpected result applying ProxyClass with metrics enabled to a StatefulSet (-got +want):\n%s", diff)
	}

	// 7. Enable _just_ debug without metrics.
	wantSS = nonUserspaceProxySS.DeepCopy()
	wantSS.Spec.Template.Spec.Containers[0].Env = append(wantSS.Spec.Template.Spec.Containers[0].Env,
		corev1.EnvVar{Name: "TS_DEBUG_ADDR_PORT", Value: "$(POD_IP):9001"},
		corev1.EnvVar{Name: "TS_TAILSCALED_EXTRA_ARGS", Value: "--debug=$(TS_DEBUG_ADDR_PORT)"},
	)
	wantSS.Spec.Template.Spec.Containers[0].Ports = []corev1.ContainerPort{{Name: "debug", Protocol: "TCP", ContainerPort: 9001}}
	gotSS = applyProxyClassToStatefulSet(proxyClassWithMetricsDebug(false, ptr.To(true)), nonUserspaceProxySS.DeepCopy(), new(tailscaleSTSConfig), zl.Sugar())
	if diff := cmp.Diff(gotSS, wantSS); diff != "" {
		t.Errorf("Unexpected result applying ProxyClass with metrics enabled to a StatefulSet (-got +want):\n%s", diff)
	}
}

func mergeMapKeys(a, b map[string]string) map[string]string {
	for key, val := range b {
		a[key] = val
	}
	return a
}

func Test_mergeStatefulSetLabelsOrAnnots(t *testing.T) {
	tests := []struct {
		name    string
		current map[string]string
		custom  map[string]string
		managed []string
		want    map[string]string
	}{
		{
			name:    "no custom labels specified and none present in current labels, return current labels",
			current: map[string]string{LabelManaged: "true", LabelParentName: "foo", LabelParentType: "svc", LabelParentNamespace: "foo"},
			want:    map[string]string{LabelManaged: "true", LabelParentName: "foo", LabelParentType: "svc", LabelParentNamespace: "foo"},
			managed: tailscaleManagedLabels,
		},
		{
			name:    "no custom labels specified, but some present in current labels, return tailscale managed labels only from the current labels",
			current: map[string]string{"foo": "bar", "something.io/foo": "bar", LabelManaged: "true", LabelParentName: "foo", LabelParentType: "svc", LabelParentNamespace: "foo"},
			want:    map[string]string{LabelManaged: "true", LabelParentName: "foo", LabelParentType: "svc", LabelParentNamespace: "foo"},
			managed: tailscaleManagedLabels,
		},
		{
			name:    "custom labels specified, current labels only contain tailscale managed labels, return a union of both",
			current: map[string]string{LabelManaged: "true", LabelParentName: "foo", LabelParentType: "svc", LabelParentNamespace: "foo"},
			custom:  map[string]string{"foo": "bar", "something.io/foo": "bar"},
			want:    map[string]string{"foo": "bar", "something.io/foo": "bar", LabelManaged: "true", LabelParentName: "foo", LabelParentType: "svc", LabelParentNamespace: "foo"},
			managed: tailscaleManagedLabels,
		},
		{
			name:    "custom labels specified, current labels contain tailscale managed labels and custom labels, some of which re not present in the new custom labels, return a union of managed labels and the desired custom labels",
			current: map[string]string{"foo": "bar", "bar": "baz", "app": "1234", LabelManaged: "true", LabelParentName: "foo", LabelParentType: "svc", LabelParentNamespace: "foo"},
			custom:  map[string]string{"foo": "bar", "something.io/foo": "bar"},
			want:    map[string]string{"foo": "bar", "something.io/foo": "bar", "app": "1234", LabelManaged: "true", LabelParentName: "foo", LabelParentType: "svc", LabelParentNamespace: "foo"},
			managed: tailscaleManagedLabels,
		},
		{
			name:    "no current labels present, return custom labels only",
			custom:  map[string]string{"foo": "bar", "something.io/foo": "bar"},
			want:    map[string]string{"foo": "bar", "something.io/foo": "bar"},
			managed: tailscaleManagedLabels,
		},
		{
			name:    "no current labels present, no custom labels specified, return empty map",
			want:    map[string]string{},
			managed: tailscaleManagedLabels,
		},
		{
			name:    "no custom annots specified and none present in current annots, return current annots",
			current: map[string]string{podAnnotationLastSetClusterIP: "1.2.3.4"},
			want:    map[string]string{podAnnotationLastSetClusterIP: "1.2.3.4"},
			managed: tailscaleManagedAnnotations,
		},
		{
			name:    "no custom annots specified, but some present in current annots, return tailscale managed annots only from the current annots",
			current: map[string]string{"foo": "bar", "something.io/foo": "bar", podAnnotationLastSetClusterIP: "1.2.3.4"},
			want:    map[string]string{podAnnotationLastSetClusterIP: "1.2.3.4"},
			managed: tailscaleManagedAnnotations,
		},
		{
			name:    "custom annots specified, current annots only contain tailscale managed annots, return a union of both",
			current: map[string]string{podAnnotationLastSetClusterIP: "1.2.3.4"},
			custom:  map[string]string{"foo": "bar", "something.io/foo": "bar"},
			want:    map[string]string{"foo": "bar", "something.io/foo": "bar", podAnnotationLastSetClusterIP: "1.2.3.4"},
			managed: tailscaleManagedAnnotations,
		},
		{
			name:    "custom annots specified, current annots contain tailscale managed annots and custom annots, some of which are not present in the new custom annots, return a union of managed annots and the desired custom annots",
			current: map[string]string{"foo": "bar", "something.io/foo": "bar", podAnnotationLastSetClusterIP: "1.2.3.4"},
			custom:  map[string]string{"something.io/foo": "bar"},
			want:    map[string]string{"something.io/foo": "bar", podAnnotationLastSetClusterIP: "1.2.3.4"},
			managed: tailscaleManagedAnnotations,
		},
		{
			name:    "no current annots present, return custom annots only",
			custom:  map[string]string{"foo": "bar", "something.io/foo": "bar"},
			want:    map[string]string{"foo": "bar", "something.io/foo": "bar"},
			managed: tailscaleManagedAnnotations,
		},
		{
			name:    "no current labels present, no custom labels specified, return empty map",
			want:    map[string]string{},
			managed: tailscaleManagedAnnotations,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeStatefulSetLabelsOrAnnots(tt.current, tt.custom, tt.managed); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeStatefulSetLabels() = %v, want %v", got, tt.want)
			}
		})
	}
}
