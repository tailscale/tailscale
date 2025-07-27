// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"fmt"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/types/ptr"
)

func idpStatefulSet(idp *tsapi.IDP, namespace string, loginServer string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:            idp.Name,
			Namespace:       namespace,
			Labels:          labels("idp", idp.Name, idp.Spec.StatefulSet.Labels),
			OwnerReferences: idpOwnerReference(idp),
			Annotations:     idp.Spec.StatefulSet.Annotations,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels("idp", idp.Name, idp.Spec.StatefulSet.Pod.Labels),
			},
			ServiceName: idp.Name,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        idp.Name,
					Namespace:   namespace,
					Labels:      labels("idp", idp.Name, idp.Spec.StatefulSet.Pod.Labels),
					Annotations: idp.Spec.StatefulSet.Pod.Annotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: idpServiceAccountName(idp),
					Affinity:           idp.Spec.StatefulSet.Pod.Affinity,
					SecurityContext:    idp.Spec.StatefulSet.Pod.SecurityContext,
					ImagePullSecrets:   idp.Spec.StatefulSet.Pod.ImagePullSecrets,
					NodeSelector:       idp.Spec.StatefulSet.Pod.NodeSelector,
					Tolerations:        idp.Spec.StatefulSet.Pod.Tolerations,
					Containers: []corev1.Container{
						{
							Name: "idp",
							Image: func() string {
								image := idp.Spec.StatefulSet.Pod.Container.Image
								if image == "" {
									image = fmt.Sprintf("tailscale/tsidp:%s", selfVersionImageTag())
								}
								return image
							}(),
							ImagePullPolicy: idp.Spec.StatefulSet.Pod.Container.ImagePullPolicy,
							Resources:       idp.Spec.StatefulSet.Pod.Container.Resources,
							SecurityContext: idp.Spec.StatefulSet.Pod.Container.SecurityContext,
							Env:             idpEnv(idp, loginServer),
							Command:         []string{"/usr/local/bin/tsidp"},
							WorkingDir:      "/data",
							Ports: []corev1.ContainerPort{
								{
									Name:          "https",
									ContainerPort: idpPort(idp),
									Protocol:      corev1.ProtocolTCP,
								},
							},
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

func idpServiceAccount(idp *tsapi.IDP, namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            idpServiceAccountName(idp),
			Namespace:       namespace,
			Labels:          labels("idp", idp.Name, nil),
			OwnerReferences: idpOwnerReference(idp),
			Annotations:     idp.Spec.StatefulSet.Pod.ServiceAccount.Annotations,
		},
	}
}

func idpServiceAccountName(idp *tsapi.IDP) string {
	sa := idp.Spec.StatefulSet.Pod.ServiceAccount
	name := idp.Name
	if sa.Name != "" {
		name = sa.Name
	}
	return name
}

func idpRole(idp *tsapi.IDP, namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:            idp.Name,
			Namespace:       namespace,
			Labels:          labels("idp", idp.Name, nil),
			OwnerReferences: idpOwnerReference(idp),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "patch", "update", "create"},
				// IDP needs create permission for dynamic kubestore secrets
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"get", "create", "patch"},
			},
		},
	}
}

func idpRoleBinding(idp *tsapi.IDP, namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            idp.Name,
			Namespace:       namespace,
			Labels:          labels("idp", idp.Name, nil),
			OwnerReferences: idpOwnerReference(idp),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      idpServiceAccountName(idp),
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: idp.Name,
		},
	}
}

func idpService(idp *tsapi.IDP, namespace string) *corev1.Service {
	port := idpPort(idp)

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            idp.Name,
			Namespace:       namespace,
			Labels:          labels("idp", idp.Name, nil),
			OwnerReferences: idpOwnerReference(idp),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app.kubernetes.io/name":     "idp",
				"app.kubernetes.io/instance": idp.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       port,
					TargetPort: intstr.FromInt(int(port)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func idpAuthSecret(idp *tsapi.IDP, namespace string, authKey string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            idp.Name,
			Labels:          labels("idp", idp.Name, nil),
			OwnerReferences: idpOwnerReference(idp),
		},
		StringData: map[string]string{
			"authkey": authKey,
		},
	}
}

func idpEnv(idp *tsapi.IDP, loginServer string) []corev1.EnvVar {
	env := []corev1.EnvVar{
		{
			Name: "TS_AUTHKEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: idp.Name,
					},
					Key: "authkey",
				},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
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
	}

	// Add TS_STATE to use Kubernetes secret for state storage
	env = append(env, corev1.EnvVar{
		Name:  "TS_STATE",
		Value: fmt.Sprintf("kube:%s-state", idp.Name),
	})

	// TSIDP configuration via environment variables
	env = append(env, corev1.EnvVar{
		Name:  "TSIDP_VERBOSE",
		Value: "true",
	})

	env = append(env, corev1.EnvVar{
		Name:  "TS_HOSTNAME",
		Value: idpHostname(idp),
	})

	env = append(env, corev1.EnvVar{
		Name:  "TSIDP_PORT",
		Value: strconv.Itoa(int(idpPort(idp))),
	})

	if idp.Spec.EnableFunnel {
		env = append(env, corev1.EnvVar{
			Name:  "TSIDP_FUNNEL",
			Value: "true",
		})
	}

	if idp.Spec.LocalPort != nil {
		env = append(env, corev1.EnvVar{
			Name:  "TSIDP_LOCAL_PORT",
			Value: strconv.Itoa(int(*idp.Spec.LocalPort)),
		})
	}

	// Add TSIDP_FUNNEL_CLIENTS_STORE for funnel client storage
	env = append(env, corev1.EnvVar{
		Name:  "TSIDP_FUNNEL_CLIENTS_STORE",
		Value: fmt.Sprintf("kube:%s-funnel-clients", idp.Name),
	})

	// Add TSIDP_LOGIN_SERVER if loginServer is set
	if loginServer != "" {
		env = append(env, corev1.EnvVar{
			Name:  "TSIDP_LOGIN_SERVER",
			Value: loginServer,
		})
	}

	// Add custom environment variables
	for _, customEnv := range idp.Spec.StatefulSet.Pod.Container.Env {
		env = append(env, corev1.EnvVar{
			Name:  string(customEnv.Name),
			Value: customEnv.Value,
		})
	}

	return env
}

func idpHostname(idp *tsapi.IDP) string {
	if idp.Spec.Hostname != "" {
		return idp.Spec.Hostname
	}
	return "idp"
}

func idpPort(idp *tsapi.IDP) int32 {
	if idp.Spec.Port != 0 {
		return idp.Spec.Port
	}
	return 443
}

func idpStateSecret(idp *tsapi.IDP, namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%s-state", idp.Name),
			Namespace:       namespace,
			Labels:          labels("idp", idp.Name, nil),
			OwnerReferences: idpOwnerReference(idp),
		},
	}
}

func idpOwnerReference(owner metav1.Object) []metav1.OwnerReference {
	return []metav1.OwnerReference{*metav1.NewControllerRef(owner, tsapi.SchemeGroupVersion.WithKind("IDP"))}
}
