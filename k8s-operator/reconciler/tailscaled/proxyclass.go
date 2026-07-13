// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailscaled

import (
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

// ApplyProxyClass overlays the settings in pc onto ss. It's the generic slice of ProxyClass application used by
// any reconciler that produces a tailscaled StatefulSet (peer relay, connector, proxy group, etc.).
func ApplyProxyClass(ss *appsv1.StatefulSet, pc *tsapi.ProxyClass, managedLabels, managedAnnotations []string) *appsv1.StatefulSet {
	if pc == nil || ss == nil || pc.Spec.StatefulSet == nil {
		return ss
	}

	if wantsLabels := pc.Spec.StatefulSet.Labels.Parse(); len(wantsLabels) > 0 {
		ss.ObjectMeta.Labels = mergeProtected(ss.ObjectMeta.Labels, wantsLabels, managedLabels)
	}

	if wantsAnnots := pc.Spec.StatefulSet.Annotations; len(wantsAnnots) > 0 {
		ss.ObjectMeta.Annotations = mergeProtected(ss.ObjectMeta.Annotations, wantsAnnots, managedAnnotations)
	}

	if pc.Spec.StatefulSet.Pod == nil {
		return ss
	}
	wantsPod := pc.Spec.StatefulSet.Pod

	if wantsPodLabels := wantsPod.Labels.Parse(); len(wantsPodLabels) > 0 {
		ss.Spec.Template.ObjectMeta.Labels = mergeProtected(ss.Spec.Template.ObjectMeta.Labels, wantsPodLabels, managedLabels)
	}

	if wantsPodAnnots := wantsPod.Annotations; len(wantsPodAnnots) > 0 {
		ss.Spec.Template.ObjectMeta.Annotations = mergeProtected(ss.Spec.Template.ObjectMeta.Annotations, wantsPodAnnots, managedAnnotations)
	}

	ss.Spec.Template.Spec.SecurityContext = wantsPod.SecurityContext
	ss.Spec.Template.Spec.ImagePullSecrets = wantsPod.ImagePullSecrets
	ss.Spec.Template.Spec.NodeName = wantsPod.NodeName
	ss.Spec.Template.Spec.NodeSelector = wantsPod.NodeSelector
	ss.Spec.Template.Spec.Affinity = wantsPod.Affinity
	ss.Spec.Template.Spec.Tolerations = wantsPod.Tolerations
	ss.Spec.Template.Spec.PriorityClassName = wantsPod.PriorityClassName
	ss.Spec.Template.Spec.TopologySpreadConstraints = wantsPod.TopologySpreadConstraints

	if wantsPod.DNSPolicy != nil {
		ss.Spec.Template.Spec.DNSPolicy = *wantsPod.DNSPolicy
	}

	if wantsPod.DNSConfig != nil {
		ss.Spec.Template.Spec.DNSConfig = wantsPod.DNSConfig
	}

	if wantsPod.TailscaleContainer != nil {
		for i := range ss.Spec.Template.Spec.Containers {
			c := &ss.Spec.Template.Spec.Containers[i]
			if c.Name != containerName {
				continue
			}

			applyContainerOverlay(c, wantsPod.TailscaleContainer)
			break
		}
	}

	return ss
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
