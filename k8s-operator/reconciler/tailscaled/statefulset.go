// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package tailscaled provides shared building blocks for operator reconcilers that manage StatefulSets running
// tailscaled pods (peer relays, connectors, proxy groups, etc). Callers describe the workload via StatefulSetOptions
// / ConfigSecretOptions and this package returns fully-populated *appsv1.StatefulSet and *corev1.Secret objects
// wired up the same way across the codebase: config-file-driven tailscaled started from a per-replica Secret
// mounted at /etc/tsconfig/<pod-name>.
package tailscaled

import (
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
)

const (
	// ConfigVolumeMountPath is the base directory tailscaled reads config files from. Each pod's config lives at
	// <ConfigVolumeMountPath>/<POD_NAME>/cap-<version>.hujson.
	ConfigVolumeMountPath = "/etc/tsconfig"

	// ConfigDirEnvVar is the env var containerboot reads to find the config file directory. It is templated with
	// $(POD_NAME) so each replica picks its own directory at runtime.
	ConfigDirEnvVar = "TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR"

	// containerName is the single container inside each pod that runs tailscaled.
	containerName = "tailscaled"
)

// StatefulSetOptions describes a StatefulSet of tailscaled pods. The zero value is not valid , Name, Namespace,
// Image, Labels, and ConfigSecretNameFunc must be set.
type StatefulSetOptions struct {
	// Name is the StatefulSet's metadata name; pods will be named <Name>-<ordinal>.
	Name string

	// Namespace is the namespace the StatefulSet lives in.
	Namespace string

	// Labels are applied to the StatefulSet, its pod template, and used as the label selector. Callers must
	// include enough labels to uniquely identify the workload , typically at least tailscale.com/parent-resource
	// and tailscale.com/parent-resource-type.
	Labels map[string]string

	// Image is the tailscale container image used for every pod.
	Image string

	// Replicas is the desired number of pods.
	Replicas int32

	// ServiceAccountName is the ServiceAccount used by every pod. Must have get/create/patch/update permission on
	// the per-pod state Secret named after each pod (containerboot's TS_KUBE_SECRET). Defaults to "default" when
	// unset, which is unlikely to have the needed RBAC.
	ServiceAccountName string

	// ConfigSecretNameFunc returns the name of the config Secret containing tailscaled config for the given
	// replica ordinal. Its output is used to build a per-replica volume and mount into the pod at
	// <ConfigVolumeMountPath>/<Name>-<ordinal>.
	ConfigSecretNameFunc func(idx int32) string
}

// NewStatefulSet returns a *appsv1.StatefulSet configured to run tailscaled from per-replica config Secrets.
// The caller is responsible for setting resource requests/limits, ProxyClass overrides, etc. after the fact.
func NewStatefulSet(opts StatefulSetOptions) *appsv1.StatefulSet {
	volumes := make([]corev1.Volume, 0, opts.Replicas)
	mounts := make([]corev1.VolumeMount, 0, opts.Replicas)
	for i := int32(0); i < opts.Replicas; i++ {
		volName := fmt.Sprintf("tailscaledconfig-%d", i)
		volumes = append(volumes, corev1.Volume{
			Name: volName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: opts.ConfigSecretNameFunc(i)},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{
			Name:      volName,
			ReadOnly:  true,
			MountPath: fmt.Sprintf("%s/%s-%d", ConfigVolumeMountPath, opts.Name, i),
		})
	}

	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "StatefulSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
			Labels:    opts.Labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &opts.Replicas,
			ServiceName: opts.Name,
			Selector:    &metav1.LabelSelector{MatchLabels: opts.Labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: opts.Labels},
				Spec: corev1.PodSpec{
					ServiceAccountName: opts.ServiceAccountName,
					Volumes:            volumes,
					Containers: []corev1.Container{{
						Name:         containerName,
						Image:        opts.Image,
						VolumeMounts: mounts,
						Env: []corev1.EnvVar{
							{
								Name: "POD_NAME",
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
								},
							},
							{
								// containerboot picks up the config file matching its own capability version from
								// this directory.
								Name:  ConfigDirEnvVar,
								Value: fmt.Sprintf("%s/$(POD_NAME)", ConfigVolumeMountPath),
							},
							{
								// tailscaled persists device/machine keys in this Secret so a pod restart doesn't
								// force reauth. Naming it after the pod gives each replica its own state.
								Name:  "TS_KUBE_SECRET",
								Value: "$(POD_NAME)",
							},
						},
					}},
				},
			},
		},
	}
}

// ConfigSecretOptions describes a single-replica tailscaled config Secret. Name, Namespace, and Config must be
// set. If CapVersion is 0, tailcfg.CurrentCapabilityVersion is used.
type ConfigSecretOptions struct {
	Name       string
	Namespace  string
	Labels     map[string]string
	CapVersion tailcfg.CapabilityVersion
	Config     ipn.ConfigVAlpha
}

// NewConfigSecret marshals opts.Config into JSON and returns a *corev1.Secret with the file keyed by
// tsoperator.TailscaledConfigFileName(opts.CapVersion). The tailscale.com/secret-type=config label is stamped on
// automatically alongside any caller-provided labels.
func NewConfigSecret(opts ConfigSecretOptions) (*corev1.Secret, error) {
	cap := opts.CapVersion
	if cap == 0 {
		cap = tailcfg.CurrentCapabilityVersion
	}

	body, err := json.Marshal(opts.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tailscaled config: %w", err)
	}

	labels := make(map[string]string, len(opts.Labels)+1)
	for k, v := range opts.Labels {
		labels[k] = v
	}
	labels[kubetypes.LabelSecretType] = kubetypes.LabelSecretTypeConfig

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
			Labels:    labels,
		},
		Data: map[string][]byte{
			tsoperator.TailscaledConfigFileName(cap): body,
		},
	}, nil
}

// StateSecretOptions describes a per-pod tailscaled state Secret. Name must match the pod name (the value
// containerboot reads from TS_KUBE_SECRET) so that tailscaled can locate it at runtime.
type StateSecretOptions struct {
	Name      string
	Namespace string
	Labels    map[string]string
}

// NewStateSecret returns an empty *corev1.Secret to be pre-created for tailscaled's kube state store. Pre-creating it
// (rather than letting containerboot create it on first run) lets callers stamp ownership labels so cleanup can select
// state Secrets by label rather than by pod-name convention. The tailscale.com/secret-type=state label is stamped on
// automatically alongside any caller-provided labels; tailscaled populates the Data on first run.
func NewStateSecret(opts StateSecretOptions) *corev1.Secret {
	labels := make(map[string]string, len(opts.Labels)+1)
	for k, v := range opts.Labels {
		labels[k] = v
	}
	labels[kubetypes.LabelSecretType] = kubetypes.LabelSecretTypeState

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.Name,
			Namespace: opts.Namespace,
			Labels:    labels,
		},
	}
}

// DeviceIDFromStateSecret returns the tailnet device ID that tailscaled recorded in secret, or "" if none. secret
// should be a state Secret populated by containerboot; the device ID is the value stored under kubetypes.KeyDeviceID.
func DeviceIDFromStateSecret(secret *corev1.Secret) string {
	return string(secret.Data[kubetypes.KeyDeviceID])
}
