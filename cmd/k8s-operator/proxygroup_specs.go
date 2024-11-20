// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/ptr"
)

// Returns the base StatefulSet definition for a ProxyGroup. A ProxyClass may be
// applied over the top after.
func pgStatefulSet(pg *tsapi.ProxyGroup, namespace, image, tsFirewallMode, cfgHash string) (*appsv1.StatefulSet, error) {
	ss := new(appsv1.StatefulSet)
	if err := yaml.Unmarshal(proxyYaml, &ss); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proxy spec: %w", err)
	}
	// Validate some base assumptions.
	if len(ss.Spec.Template.Spec.InitContainers) != 1 {
		return nil, fmt.Errorf("[unexpected] base proxy config had %d init containers instead of 1", len(ss.Spec.Template.Spec.InitContainers))
	}
	if len(ss.Spec.Template.Spec.Containers) != 1 {
		return nil, fmt.Errorf("[unexpected] base proxy config had %d containers instead of 1", len(ss.Spec.Template.Spec.Containers))
	}

	// StatefulSet config.
	ss.ObjectMeta = metav1.ObjectMeta{
		Name:            pg.Name,
		Namespace:       namespace,
		Labels:          pgLabels(pg.Name, nil),
		OwnerReferences: pgOwnerReference(pg),
	}
	ss.Spec.Replicas = ptr.To(pgReplicas(pg))
	ss.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: pgLabels(pg.Name, nil),
	}

	// Template config.
	tmpl := &ss.Spec.Template
	tmpl.ObjectMeta = metav1.ObjectMeta{
		Name:                       pg.Name,
		Namespace:                  namespace,
		Labels:                     pgLabels(pg.Name, nil),
		DeletionGracePeriodSeconds: ptr.To[int64](10),
		Annotations: map[string]string{
			podAnnotationLastSetConfigFileHash: cfgHash,
		},
	}
	tmpl.Spec.ServiceAccountName = pg.Name
	tmpl.Spec.InitContainers[0].Image = image
	tmpl.Spec.Volumes = func() []corev1.Volume {
		var volumes []corev1.Volume
		for i := range pgReplicas(pg) {
			volumes = append(volumes, corev1.Volume{
				Name: fmt.Sprintf("tailscaledconfig-%d", i),
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf("%s-%d-config", pg.Name, i),
					},
				},
			})
		}

		if pg.Spec.Type == tsapi.ProxyGroupTypeEgress {
			volumes = append(volumes, corev1.Volume{
				Name: pgEgressCMName(pg.Name),
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: pgEgressCMName(pg.Name),
						},
					},
				},
			})
		}

		return volumes
	}()

	// Main container config.
	c := &ss.Spec.Template.Spec.Containers[0]
	c.Image = image
	c.VolumeMounts = func() []corev1.VolumeMount {
		var mounts []corev1.VolumeMount

		// TODO(tomhjp): Read config directly from the secret instead. The
		// mounts change on scaling up/down which causes unnecessary restarts
		// for pods that haven't meaningfully changed.
		for i := range pgReplicas(pg) {
			mounts = append(mounts, corev1.VolumeMount{
				Name:      fmt.Sprintf("tailscaledconfig-%d", i),
				ReadOnly:  true,
				MountPath: fmt.Sprintf("/etc/tsconfig/%s-%d", pg.Name, i),
			})
		}

		if pg.Spec.Type == tsapi.ProxyGroupTypeEgress {
			mounts = append(mounts, corev1.VolumeMount{
				Name:      pgEgressCMName(pg.Name),
				MountPath: "/etc/proxies",
				ReadOnly:  true,
			})
		}

		return mounts
	}()
	c.Env = func() []corev1.EnvVar {
		envs := []corev1.EnvVar{
			{
				// TODO(irbekrm): verify that .status.podIPs are always set, else read in .status.podIP as well.
				Name: "POD_IPS", // this will be a comma separate list i.e 10.136.0.6,2600:1900:4011:161:0:e:0:6
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "status.podIPs",
					},
				},
			},
			{
				Name:  "TS_KUBE_SECRET",
				Value: "$(POD_NAME)",
			},
			{
				Name:  "TS_STATE",
				Value: "kube:$(POD_NAME)",
			},
			{
				Name:  "TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR",
				Value: "/etc/tsconfig/$(POD_NAME)",
			},
			{
				Name:  "TS_INTERNAL_APP",
				Value: kubetypes.AppProxyGroupEgress,
			},
		}

		if tsFirewallMode != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "TS_DEBUG_FIREWALL_MODE",
				Value: tsFirewallMode,
			})
		}

		if pg.Spec.Type == tsapi.ProxyGroupTypeEgress {
			envs = append(envs, corev1.EnvVar{
				Name:  "TS_EGRESS_SERVICES_CONFIG_PATH",
				Value: fmt.Sprintf("/etc/proxies/%s", egressservices.KeyEgressServices),
			})
		}

		return append(c.Env, envs...)
	}()

	return ss, nil
}

func pgServiceAccount(pg *tsapi.ProxyGroup, namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pg.Name,
			Namespace:       namespace,
			Labels:          pgLabels(pg.Name, nil),
			OwnerReferences: pgOwnerReference(pg),
		},
	}
}

func pgRole(pg *tsapi.ProxyGroup, namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pg.Name,
			Namespace:       namespace,
			Labels:          pgLabels(pg.Name, nil),
			OwnerReferences: pgOwnerReference(pg),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs: []string{
					"get",
					"patch",
					"update",
				},
				ResourceNames: func() (secrets []string) {
					for i := range pgReplicas(pg) {
						secrets = append(secrets,
							fmt.Sprintf("%s-%d-config", pg.Name, i), // Config with auth key.
							fmt.Sprintf("%s-%d", pg.Name, i),        // State.
						)
					}
					return secrets
				}(),
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs: []string{
					"create",
					"patch",
					"get",
				},
			},
		},
	}
}

func pgRoleBinding(pg *tsapi.ProxyGroup, namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pg.Name,
			Namespace:       namespace,
			Labels:          pgLabels(pg.Name, nil),
			OwnerReferences: pgOwnerReference(pg),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      pg.Name,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: pg.Name,
		},
	}
}

func pgStateSecrets(pg *tsapi.ProxyGroup, namespace string) (secrets []*corev1.Secret) {
	for i := range pgReplicas(pg) {
		secrets = append(secrets, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            fmt.Sprintf("%s-%d", pg.Name, i),
				Namespace:       namespace,
				Labels:          pgSecretLabels(pg.Name, "state"),
				OwnerReferences: pgOwnerReference(pg),
			},
		})
	}

	return secrets
}

func pgEgressCM(pg *tsapi.ProxyGroup, namespace string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pgEgressCMName(pg.Name),
			Namespace:       namespace,
			Labels:          pgLabels(pg.Name, nil),
			OwnerReferences: pgOwnerReference(pg),
		},
	}
}

func pgSecretLabels(pgName, typ string) map[string]string {
	return pgLabels(pgName, map[string]string{
		labelSecretType: typ, // "config" or "state".
	})
}

func pgLabels(pgName string, customLabels map[string]string) map[string]string {
	l := make(map[string]string, len(customLabels)+3)
	for k, v := range customLabels {
		l[k] = v
	}

	l[LabelManaged] = "true"
	l[LabelParentType] = "proxygroup"
	l[LabelParentName] = pgName

	return l
}

func pgOwnerReference(owner *tsapi.ProxyGroup) []metav1.OwnerReference {
	return []metav1.OwnerReference{*metav1.NewControllerRef(owner, tsapi.SchemeGroupVersion.WithKind("ProxyGroup"))}
}

func pgReplicas(pg *tsapi.ProxyGroup) int32 {
	if pg.Spec.Replicas != nil {
		return *pg.Spec.Replicas
	}

	return 2
}

func pgEgressCMName(pg string) string {
	return fmt.Sprintf("%s-egress-config", pg)
}
