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

func tsrStatefulSet(tsr *tsapi.Recorder, namespace string, loginServer string) *appsv1.StatefulSet {
	var replicas int32 = 1
	if tsr.Spec.Replicas != nil {
		replicas = *tsr.Spec.Replicas
	}

	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          tsrLabels("recorder", tsr.Name, tsr.Spec.StatefulSet.Labels),
			OwnerReferences: tsrOwnerReference(tsr),
			Annotations:     tsr.Spec.StatefulSet.Annotations,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{
				MatchLabels: tsrLabels("recorder", tsr.Name, tsr.Spec.StatefulSet.Pod.Labels),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        tsr.Name,
					Namespace:   namespace,
					Labels:      tsrLabels("recorder", tsr.Name, tsr.Spec.StatefulSet.Pod.Labels),
					Annotations: tsr.Spec.StatefulSet.Pod.Annotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: tsrServiceAccountName(tsr),
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
							Env:             tsrEnv(tsr, loginServer),
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

	for replica := range replicas {
		volumeName := fmt.Sprintf("authkey-%d", replica)

		ss.Spec.Template.Spec.Containers[0].VolumeMounts = append(ss.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      volumeName,
			ReadOnly:  true,
			MountPath: fmt.Sprintf("/etc/tailscaled/%s-%d", ss.Name, replica),
		})

		ss.Spec.Template.Spec.Volumes = append(ss.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf("%s-auth-%d", tsr.Name, replica),
					Items:      []corev1.KeyToPath{{Key: "authkey", Path: "authkey"}},
				},
			},
		})
	}

	return ss
}

func tsrServiceAccount(tsr *tsapi.Recorder, namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsrServiceAccountName(tsr),
			Namespace:       namespace,
			Labels:          tsrLabels("recorder", tsr.Name, nil),
			OwnerReferences: tsrOwnerReference(tsr),
			Annotations:     tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations,
		},
	}
}

func tsrServiceAccountName(tsr *tsapi.Recorder) string {
	sa := tsr.Spec.StatefulSet.Pod.ServiceAccount
	name := tsr.Name
	if sa.Name != "" {
		name = sa.Name
	}

	return name
}

func tsrRole(tsr *tsapi.Recorder, namespace string) *rbacv1.Role {
	var replicas int32 = 1
	if tsr.Spec.Replicas != nil {
		replicas = *tsr.Spec.Replicas
	}

	resourceNames := make([]string, 0)
	for replica := range replicas {
		resourceNames = append(resourceNames,
			fmt.Sprintf("%s-%d", tsr.Name, replica),      // State secret.
			fmt.Sprintf("%s-auth-%d", tsr.Name, replica), // Auth key secret.
		)
	}

	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       namespace,
			Labels:          tsrLabels("recorder", tsr.Name, nil),
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
				ResourceNames: resourceNames,
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs: []string{
					"get",
					"create",
					"patch",
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
			Labels:          tsrLabels("recorder", tsr.Name, nil),
			OwnerReferences: tsrOwnerReference(tsr),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      tsrServiceAccountName(tsr),
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: tsr.Name,
		},
	}
}

func tsrAuthSecret(tsr *tsapi.Recorder, namespace string, authKey string, replica int32) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            fmt.Sprintf("%s-auth-%d", tsr.Name, replica),
			Labels:          tsrLabels("recorder", tsr.Name, nil),
			OwnerReferences: tsrOwnerReference(tsr),
		},
		StringData: map[string]string{
			"authkey": authKey,
		},
	}
}

func tsrStateSecret(tsr *tsapi.Recorder, namespace string, replica int32) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%s-%d", tsr.Name, replica),
			Namespace:       namespace,
			Labels:          tsrLabels("recorder", tsr.Name, nil),
			OwnerReferences: tsrOwnerReference(tsr),
		},
	}
}

func tsrEnv(tsr *tsapi.Recorder, loginServer string) []corev1.EnvVar {
	envs := []corev1.EnvVar{
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
			Name: "POD_UID",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.uid",
				},
			},
		},
		{
			Name:  "TS_AUTHKEY_FILE",
			Value: "/etc/tailscaled/$(POD_NAME)/authkey",
		},
		{
			Name:  "TS_STATE",
			Value: "kube:$(POD_NAME)",
		},
		{
			Name:  "TSRECORDER_HOSTNAME",
			Value: "$(POD_NAME)",
		},
		{
			Name:  "TSRECORDER_LOGIN_SERVER",
			Value: loginServer,
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

func tsrLabels(app, instance string, customLabels map[string]string) map[string]string {
	labels := make(map[string]string, len(customLabels)+3)
	for k, v := range customLabels {
		labels[k] = v
	}

	// ref: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
	labels["app.kubernetes.io/name"] = app
	labels["app.kubernetes.io/instance"] = instance
	labels["app.kubernetes.io/managed-by"] = "tailscale-operator"

	return labels
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
