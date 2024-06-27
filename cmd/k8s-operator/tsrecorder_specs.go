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

func tsrStatefulSet(tsr *tsapi.TSRecorder, namespace string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          labels("tsrecorder", tsr.Name),
			OwnerReferences: tsrOwnerReference(tsr),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels("tsrecorder", tsr.Name),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tsr.Name,
					Namespace: namespace,
					Labels:    labels("tsrecorder", tsr.Name),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: tsr.Name,
					Containers: []corev1.Container{
						{
							Name: "tsrecorder",
							Image: func() string {
								repo, tag := tsr.Spec.Image.Repo, tsr.Spec.Image.Tag
								if repo == "" {
									repo = "tailscale/tsrecorder"
								}
								if tag == "" {
									tag = "stable"
								}
								return fmt.Sprintf("%s:%s", repo, tag)
							}(),
							Env: []corev1.EnvVar{
								{
									Name: "TS_AUTHKEY",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: tsr.Name,
											},
											Key: "authkey",
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
									Name:  "TS_STATE",
									Value: "kube:$(POD_NAME)",
								},
								{
									Name:  "TSRECORDER_HOSTNAME",
									Value: "$(POD_NAME)",
								},
							},
							Command: []string{"/tsrecorder"},
							Args: func() []string {
								var args []string
								if tsr.Spec.Storage.File.Directory != "" {
									args = append(args, "--dst="+tsr.Spec.Storage.File.Directory)
								}
								if tsr.Spec.EnableUI {
									args = append(args, "--ui")
								}
								return args
							}(),
							VolumeMounts: append([]corev1.VolumeMount{
								{
									Name:      "data",
									MountPath: "/data",
									ReadOnly:  false,
								},
							}, tsr.Spec.ExtraVolumeMounts...),
						},
					},
					Volumes: append([]corev1.Volume{
						{
							Name: "data",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					}, tsr.Spec.ExtraVolumes...),
				},
			},
		},
	}
}

func tsrServiceAccount(tsr *tsapi.TSRecorder, namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          labels("tsrecorder", tsr.Name),
			OwnerReferences: tsrOwnerReference(tsr),
		},
	}
}

func tsrRole(tsr *tsapi.TSRecorder, namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          labels("tsrecorder", tsr.Name),
			OwnerReferences: tsrOwnerReference(tsr),
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
				ResourceNames: []string{
					tsr.Name,                      // Contains the auth key.
					fmt.Sprintf("%s-0", tsr.Name), // Contains the node state.
				},
			},
		},
	}
}

func tsrRoleBinding(tsr *tsapi.TSRecorder, namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          labels("tsrecorder", tsr.Name),
			OwnerReferences: tsrOwnerReference(tsr),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      tsr.Name,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: tsr.Name,
		},
	}
}

func tsrAuthSecret(tsr *tsapi.TSRecorder, namespace string, authKey string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            tsr.Name,
			Labels:          labels("tsrecorder", tsr.Name),
			OwnerReferences: tsrOwnerReference(tsr),
		},
		StringData: map[string]string{
			"authkey": authKey,
		},
	}
}

func tsrStateSecret(tsr *tsapi.TSRecorder, namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%s-0", tsr.Name),
			Namespace:       namespace,
			Labels:          labels("tsrecorder", tsr.Name),
			OwnerReferences: tsrOwnerReference(tsr),
		},
	}
}

func labels(app, instance string) map[string]string {
	// ref: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
	return map[string]string{
		"app.kubernetes.io/name":       app,
		"app.kubernetes.io/instance":   instance,
		"app.kubernetes.io/managed-by": "tailscale-operator",
	}
}

func tsrOwnerReference(owner metav1.Object) []metav1.OwnerReference {
	return []metav1.OwnerReference{*metav1.NewControllerRef(owner, tsapi.SchemeGroupVersion.WithKind("TSRecorder"))}
}
