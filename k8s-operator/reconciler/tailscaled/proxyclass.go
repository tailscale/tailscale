// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailscaled

import (
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

// ApplyProxyClass overlays the settings in pc onto ss. It's the generic slice of ProxyClass application used by
// any reconciler that produces a tailscaled StatefulSet (peer relay, connector, proxy group, etc).
func ApplyProxyClass(ss *appsv1.StatefulSet, pc *tsapi.ProxyClass, managedLabels, managedAnnotations []string) *appsv1.StatefulSet {
	if pc == nil || ss == nil {
		return ss
	}
	applyProxyClass(&ss.ObjectMeta, &ss.Spec.Template, pc, managedLabels, managedAnnotations, true)
	return ss
}

// ApplyProxyClassToDaemonSet overlays the settings in pc onto ds. The ProxyClass's statefulSet section applies to
// the DaemonSet and its pod template in the same way as to a StatefulSet, except that pod.nodeName is ignored as
// it would pin every pod of the DaemonSet to a single node.
func ApplyProxyClassToDaemonSet(ds *appsv1.DaemonSet, pc *tsapi.ProxyClass, managedLabels, managedAnnotations []string) *appsv1.DaemonSet {
	if pc == nil || ds == nil {
		return ds
	}
	applyProxyClass(&ds.ObjectMeta, &ds.Spec.Template, pc, managedLabels, managedAnnotations, false)
	return ds
}

// applyProxyClass overlays the settings in pc onto the workload with the given object meta and pod template.
func applyProxyClass(meta *metav1.ObjectMeta, tmpl *corev1.PodTemplateSpec, pc *tsapi.ProxyClass, managedLabels, managedAnnotations []string, applyNodeName bool) {
	if pc.Spec.StatefulSet == nil {
		return
	}

	if wantsLabels := pc.Spec.StatefulSet.Labels.Parse(); len(wantsLabels) > 0 {
		meta.Labels = mergeProtected(meta.Labels, wantsLabels, managedLabels)
	}

	if wantsAnnots := pc.Spec.StatefulSet.Annotations; len(wantsAnnots) > 0 {
		meta.Annotations = mergeProtected(meta.Annotations, wantsAnnots, managedAnnotations)
	}

	if pc.Spec.StatefulSet.Pod == nil {
		return
	}
	wantsPod := pc.Spec.StatefulSet.Pod

	if wantsPodLabels := wantsPod.Labels.Parse(); len(wantsPodLabels) > 0 {
		tmpl.ObjectMeta.Labels = mergeProtected(tmpl.ObjectMeta.Labels, wantsPodLabels, managedLabels)
	}

	if wantsPodAnnots := wantsPod.Annotations; len(wantsPodAnnots) > 0 {
		tmpl.ObjectMeta.Annotations = mergeProtected(tmpl.ObjectMeta.Annotations, wantsPodAnnots, managedAnnotations)
	}

	tmpl.Spec.SecurityContext = wantsPod.SecurityContext
	tmpl.Spec.ImagePullSecrets = wantsPod.ImagePullSecrets
	if applyNodeName {
		tmpl.Spec.NodeName = wantsPod.NodeName
	}
	tmpl.Spec.NodeSelector = wantsPod.NodeSelector
	tmpl.Spec.Affinity = wantsPod.Affinity
	tmpl.Spec.Tolerations = wantsPod.Tolerations
	tmpl.Spec.PriorityClassName = wantsPod.PriorityClassName
	tmpl.Spec.TopologySpreadConstraints = wantsPod.TopologySpreadConstraints

	if wantsPod.DNSPolicy != nil {
		tmpl.Spec.DNSPolicy = *wantsPod.DNSPolicy
	}

	if wantsPod.DNSConfig != nil {
		tmpl.Spec.DNSConfig = wantsPod.DNSConfig
	}

	if wantsPod.TailscaleContainer != nil {
		for i := range tmpl.Spec.Containers {
			c := &tmpl.Spec.Containers[i]
			if c.Name != containerName {
				continue
			}

			applyContainerOverlay(c, wantsPod.TailscaleContainer)
			break
		}
	}

	if wantsPod.TailscaleInitContainer != nil {
		for i := range tmpl.Spec.InitContainers {
			c := &tmpl.Spec.InitContainers[i]
			if c.Name != initContainerName {
				continue
			}

			applyContainerOverlay(c, wantsPod.TailscaleInitContainer)
			break
		}
	}
}

func mergeProtected(current, custom map[string]string, protected []string) map[string]string {
	if custom == nil {
		custom = make(map[string]string)
	}
	for k, v := range current {
		if slices.Contains(protected, k) {
			custom[k] = v
		}
	}
	return custom
}

func applyContainerOverlay(c *corev1.Container, overlay *tsapi.Container) {
	if overlay.SecurityContext != nil {
		c.SecurityContext = overlay.SecurityContext
	}

	if len(overlay.Resources.Requests) > 0 {
		c.Resources.Requests = overlay.Resources.Requests
	}

	if len(overlay.Resources.Limits) > 0 {
		c.Resources.Limits = overlay.Resources.Limits
	}

	for _, e := range overlay.Env {
		// Env vars added by ProxyClass are appended; Kubernetes uses the last entry for a duplicate name, so this
		// lets the user override anything we set (e.g. TS_USERSPACE) without us having to know the full list.
		c.Env = append(c.Env, corev1.EnvVar{Name: string(e.Name), Value: e.Value})
	}

	if overlay.Image != "" {
		c.Image = overlay.Image
	}

	if overlay.ImagePullPolicy != "" {
		c.ImagePullPolicy = overlay.ImagePullPolicy
	}
}
