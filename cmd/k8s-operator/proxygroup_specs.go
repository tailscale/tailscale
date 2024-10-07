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
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/types/ptr"
)

// Returns the base StatefulSet definition for a ProxyGroup. A ProxyClass may be
// applied over the top after.
func pgStatefulSet(pg *tsapi.ProxyGroup, namespace, image, tsFirewallMode, cfgHash string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pg.Name,
			Namespace:       namespace,
			Labels:          pgLabels(pg.Name, nil),
			OwnerReferences: pgOwnerReference(pg),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To(pgReplicas(pg)),
			Selector: &metav1.LabelSelector{
				MatchLabels: pgLabels(pg.Name, nil),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:                       pg.Name,
					Namespace:                  namespace,
					Labels:                     pgLabels(pg.Name, nil),
					DeletionGracePeriodSeconds: ptr.To[int64](10),
					Annotations: map[string]string{
						podAnnotationLastSetConfigFileHash: cfgHash,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: pg.Name,
					InitContainers: []corev1.Container{
						{
							Name:  "sysctler",
							Image: image,
							SecurityContext: &corev1.SecurityContext{
								Privileged: ptr.To(true),
							},
							Command: []string{
								"/bin/sh",
								"-c",
							},
							Args: []string{
								"sysctl -w net.ipv4.ip_forward=1 && if sysctl net.ipv6.conf.all.forwarding; then sysctl -w net.ipv6.conf.all.forwarding=1; fi",
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "tailscale",
							Image: image,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"NET_ADMIN",
									},
								},
							},
							VolumeMounts: func() []corev1.VolumeMount {
								var mounts []corev1.VolumeMount
								for i := range pgReplicas(pg) {
									mounts = append(mounts, corev1.VolumeMount{
										Name:      fmt.Sprintf("tailscaledconfig-%d", i),
										ReadOnly:  true,
										MountPath: fmt.Sprintf("/etc/tsconfig/%s-%d", pg.Name, i),
									})
								}

								return mounts
							}(),
							Env: func() []corev1.EnvVar {
								envs := []corev1.EnvVar{
									{
										Name: "POD_IP",
										ValueFrom: &corev1.EnvVarSource{
											FieldRef: &corev1.ObjectFieldSelector{
												FieldPath: "status.podIP",
											},
										},
									},
									{
										Name: "POD_NAME",
										ValueFrom: &corev1.EnvVarSource{
											FieldRef: &corev1.ObjectFieldSelector{
												// Secret is named after the pod.
												FieldPath: "metadata.name",
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
										Name:  "TS_USERSPACE",
										Value: "false",
									},
								}

								if tsFirewallMode != "" {
									envs = append(envs, corev1.EnvVar{
										Name:  "TS_DEBUG_FIREWALL_MODE",
										Value: tsFirewallMode,
									})
								}

								return envs
							}(),
						},
					},
					Volumes: func() []corev1.Volume {
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

						return volumes
					}(),
				},
			},
		},
	}
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
