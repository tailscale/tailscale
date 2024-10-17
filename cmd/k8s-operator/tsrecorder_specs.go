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
	"tailscale.com/version"
)

func tsrStatefulSet(tsr *tsapi.Recorder, namespace string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          labels("recorder", tsr.Name, tsr.Spec.StatefulSet.Labels),
			OwnerReferences: tsrOwnerReference(tsr),
			Annotations:     tsr.Spec.StatefulSet.Annotations,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels("recorder", tsr.Name, tsr.Spec.StatefulSet.Pod.Labels),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        tsr.Name,
					Namespace:   namespace,
					Labels:      labels("recorder", tsr.Name, tsr.Spec.StatefulSet.Pod.Labels),
					Annotations: tsr.Spec.StatefulSet.Pod.Annotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: tsr.Name,
					Affinity:           tsr.Spec.StatefulSet.Pod.Affinity,
					SecurityContext:    tsr.Spec.StatefulSet.Pod.SecurityContext,
					ImagePullSecrets:   tsr.Spec.StatefulSet.Pod.ImagePullSecrets,
					NodeSelector:       tsr.Spec.StatefulSet.Pod.NodeSelector,
					Tolerations:        tsr.Spec.StatefulSet.Pod.Tolerations,
					Containers: []corev1.Container{
						{
							Name: "recorder",
							Image: func() string {
								image := tsr.Spec.StatefulSet.Pod.Container.Image
								if image == "" {
									image = fmt.Sprintf("tailscale/tsrecorder:%s", selfVersionImageTag())
								}

								return image
							}(),
							ImagePullPolicy: tsr.Spec.StatefulSet.Pod.Container.ImagePullPolicy,
							Resources:       tsr.Spec.StatefulSet.Pod.Container.Resources,
							SecurityContext: tsr.Spec.StatefulSet.Pod.Container.SecurityContext,
							Env:             env(tsr),
							EnvFrom: func() []corev1.EnvFromSource {
								if tsr.Spec.Storage.S3 == nil || tsr.Spec.Storage.S3.Credentials.Secret.Name == "" {
									return nil
								}

								return []corev1.EnvFromSource{{
									SecretRef: &corev1.SecretEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: tsr.Spec.Storage.S3.Credentials.Secret.Name,
										},
									},
								}}
							}(),
							Command: []string{"/tsrecorder"},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "data",
									MountPath: "/data",
									ReadOnly:  false,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "data",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}
}

func tsrServiceAccount(tsr *tsapi.Recorder, namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          labels("recorder", tsr.Name, nil),
			OwnerReferences: tsrOwnerReference(tsr),
		},
	}
}

func tsrRole(tsr *tsapi.Recorder, namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          labels("recorder", tsr.Name, nil),
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

func tsrRoleBinding(tsr *tsapi.Recorder, namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          labels("recorder", tsr.Name, nil),
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

func tsrAuthSecret(tsr *tsapi.Recorder, namespace string, authKey string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            tsr.Name,
			Labels:          labels("recorder", tsr.Name, nil),
			OwnerReferences: tsrOwnerReference(tsr),
		},
		StringData: map[string]string{
			"authkey": authKey,
		},
	}
}

func tsrStateSecret(tsr *tsapi.Recorder, namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%s-0", tsr.Name),
			Namespace:       namespace,
			Labels:          labels("recorder", tsr.Name, nil),
			OwnerReferences: tsrOwnerReference(tsr),
		},
	}
}

func env(tsr *tsapi.Recorder) []corev1.EnvVar {
	envs := []corev1.EnvVar{
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
	}

	for _, env := range tsr.Spec.StatefulSet.Pod.Container.Env {
		envs = append(envs, corev1.EnvVar{
			Name:  string(env.Name),
			Value: env.Value,
		})
	}

	if tsr.Spec.Storage.S3 != nil {
		envs = append(envs,
			corev1.EnvVar{
				Name:  "TSRECORDER_DST",
				Value: fmt.Sprintf("s3://%s", tsr.Spec.Storage.S3.Endpoint),
			},
			corev1.EnvVar{
				Name:  "TSRECORDER_BUCKET",
				Value: tsr.Spec.Storage.S3.Bucket,
			},
		)
	} else {
		envs = append(envs, corev1.EnvVar{
			Name:  "TSRECORDER_DST",
			Value: "/data/recordings",
		})
	}

	if tsr.Spec.EnableUI {
		envs = append(envs, corev1.EnvVar{
			Name:  "TSRECORDER_UI",
			Value: "true",
		})
	}

	return envs
}

func labels(app, instance string, customLabels map[string]string) map[string]string {
	l := make(map[string]string, len(customLabels)+3)
	for k, v := range customLabels {
		l[k] = v
	}

	// ref: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
	l["app.kubernetes.io/name"] = app
	l["app.kubernetes.io/instance"] = instance
	l["app.kubernetes.io/managed-by"] = "tailscale-operator"

	return l
}

func tsrOwnerReference(owner metav1.Object) []metav1.OwnerReference {
	return []metav1.OwnerReference{*metav1.NewControllerRef(owner, tsapi.SchemeGroupVersion.WithKind("Recorder"))}
}

// selfVersionImageTag returns the container image tag of the running operator
// build.
func selfVersionImageTag() string {
	meta := version.GetMeta()
	var versionPrefix string
	if meta.UnstableBranch {
		versionPrefix = "unstable-"
	}
	return fmt.Sprintf("%sv%s", versionPrefix, meta.MajorMinorPatch)
}
