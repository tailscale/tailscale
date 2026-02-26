// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/ingressservices"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/ptr"
)

const (
	// deletionGracePeriodSeconds is set to 6 minutes to ensure that the pre-stop hook of these proxies have enough chance to terminate gracefully.
	deletionGracePeriodSeconds int64 = 360
	staticEndpointPortName           = "static-endpoint-port"
	// authAPIServerProxySAName is the ServiceAccount deployed by the helm chart
	// if apiServerProxy.authEnabled is true.
	authAPIServerProxySAName = "kube-apiserver-auth-proxy"
)

func pgNodePortServiceName(proxyGroupName string, replica int32) string {
	return fmt.Sprintf("%s-%d-nodeport", proxyGroupName, replica)
}

func pgNodePortService(pg *tsapi.ProxyGroup, name string, namespace string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			Labels:          pgLabels(pg.Name, nil),
			OwnerReferences: pgOwnerReference(pg),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				// NOTE(ChaosInTheCRD): we set the ports once we've iterated over every svc and found any old configuration we want to persist.
				{
					Name:     staticEndpointPortName,
					Protocol: corev1.ProtocolUDP,
				},
			},
			Selector: map[string]string{
				appsv1.StatefulSetPodNameLabel: strings.TrimSuffix(name, "-nodeport"),
			},
		},
	}
}

// Returns the base StatefulSet definition for a ProxyGroup. A ProxyClass may be
// applied over the top after.
func pgStatefulSet(pg *tsapi.ProxyGroup, namespace, image, tsFirewallMode string, port *uint16, proxyClass *tsapi.ProxyClass) (*appsv1.StatefulSet, error) {
	if pg.Spec.Type == tsapi.ProxyGroupTypeKubernetesAPIServer {
		return kubeAPIServerStatefulSet(pg, namespace, image, port)
	}
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
	}
	tmpl.Spec.ServiceAccountName = pg.Name
	tmpl.Spec.InitContainers[0].Image = image
	proxyConfigVolName := pgEgressCMName(pg.Name)
	if pg.Spec.Type == tsapi.ProxyGroupTypeIngress {
		proxyConfigVolName = pgIngressCMName(pg.Name)
	}
	tmpl.Spec.Volumes = func() []corev1.Volume {
		var volumes []corev1.Volume
		for i := range pgReplicas(pg) {
			volumes = append(volumes, corev1.Volume{
				Name: fmt.Sprintf("tailscaledconfig-%d", i),
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: pgConfigSecretName(pg.Name, i),
					},
				},
			})
		}

		volumes = append(volumes, corev1.Volume{
			Name: proxyConfigVolName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: proxyConfigVolName,
					},
				},
			},
		})

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

		mounts = append(mounts, corev1.VolumeMount{
			Name:      proxyConfigVolName,
			MountPath: "/etc/proxies",
			ReadOnly:  true,
		})

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
				Name:  "TS_EXPERIMENTAL_SERVICE_AUTO_ADVERTISEMENT",
				Value: "false",
			},
			{
				// TODO(tomhjp): This is tsrecorder-specific and does nothing. Delete.
				Name:  "TS_STATE",
				Value: "kube:$(POD_NAME)",
			},
			{
				Name:  "TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR",
				Value: "/etc/tsconfig/$(POD_NAME)",
			},
			{
				// This ensures that cert renewals can succeed if ACME account
				// keys have changed since issuance. We cannot guarantee or
				// validate that the account key has not changed, see
				// https://github.com/tailscale/tailscale/issues/18251
				Name:  "TS_DEBUG_ACME_FORCE_RENEWAL",
				Value: "true",
			},
		}

		if port != nil {
			envs = append(envs, corev1.EnvVar{
				Name:  "PORT",
				Value: strconv.Itoa(int(*port)),
			})
		}

		if tsFirewallMode != "" {
			envs = append(envs, corev1.EnvVar{
				Name:  "TS_DEBUG_FIREWALL_MODE",
				Value: tsFirewallMode,
			})
		}

		if pg.Spec.Type == tsapi.ProxyGroupTypeEgress {
			envs = append(envs,
				// TODO(irbekrm): in 1.80 we deprecated TS_EGRESS_SERVICES_CONFIG_PATH in favour of
				// TS_EGRESS_PROXIES_CONFIG_PATH. Remove it in 1.84.
				corev1.EnvVar{
					Name:  "TS_EGRESS_SERVICES_CONFIG_PATH",
					Value: fmt.Sprintf("/etc/proxies/%s", egressservices.KeyEgressServices),
				},
				corev1.EnvVar{
					Name:  "TS_EGRESS_PROXIES_CONFIG_PATH",
					Value: "/etc/proxies",
				},
				corev1.EnvVar{
					Name:  "TS_INTERNAL_APP",
					Value: kubetypes.AppProxyGroupEgress,
				},
				corev1.EnvVar{
					Name:  "TS_ENABLE_HEALTH_CHECK",
					Value: "true",
				})
		} else { // ingress
			envs = append(envs, corev1.EnvVar{
				Name:  "TS_INTERNAL_APP",
				Value: kubetypes.AppProxyGroupIngress,
			},
				corev1.EnvVar{
					Name:  "TS_INGRESS_PROXIES_CONFIG_PATH",
					Value: fmt.Sprintf("/etc/proxies/%s", ingressservices.IngressConfigKey),
				},
				corev1.EnvVar{
					Name:  "TS_SERVE_CONFIG",
					Value: fmt.Sprintf("/etc/proxies/%s", serveConfigKey),
				},
				corev1.EnvVar{
					// Run proxies in cert share mode to
					// ensure that only one TLS cert is
					// issued for an HA Ingress.
					Name:  "TS_EXPERIMENTAL_CERT_SHARE",
					Value: "true",
				},
			)
		}
		return append(c.Env, envs...)
	}()

	// The pre-stop hook is used to ensure that a replica does not get terminated while cluster traffic for egress
	// services is still being routed to it.
	//
	// This mechanism currently (2025-01-26) rely on the local health check being accessible on the Pod's
	// IP, so they are not supported for ProxyGroups where users have configured TS_LOCAL_ADDR_PORT to a custom
	// value.
	//
	// NB: For _Ingress_ ProxyGroups, we run shutdown logic within containerboot
	// in reaction to a SIGTERM signal instead of using a pre-stop hook. This is
	// because Ingress pods need to unadvertise services, and it's preferable to
	// avoid triggering those side-effects from a GET request that would be
	// accessible to the whole cluster network (in the absence of NetworkPolicy
	// rules).
	//
	// TODO(tomhjp): add a readiness probe or gate to Ingress Pods. There is a
	// small window where the Pod is marked ready but routing can still fail.
	if pg.Spec.Type == tsapi.ProxyGroupTypeEgress && !hasLocalAddrPortSet(proxyClass) {
		c.Lifecycle = &corev1.Lifecycle{
			PreStop: &corev1.LifecycleHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: kubetypes.EgessServicesPreshutdownEP,
					Port: intstr.FromInt(defaultLocalAddrPort),
				},
			},
		}
		// Set the deletion grace period to 6 minutes to ensure that the pre-stop hook has enough time to terminate
		// gracefully.
		ss.Spec.Template.DeletionGracePeriodSeconds = ptr.To(deletionGracePeriodSeconds)
	}

	return ss, nil
}

func kubeAPIServerStatefulSet(pg *tsapi.ProxyGroup, namespace, image string, port *uint16) (*appsv1.StatefulSet, error) {
	sts := &appsv1.StatefulSet{
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
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: pgServiceAccountName(pg),
					Containers: []corev1.Container{
						{
							Name:  mainContainerName,
							Image: image,
							Env: func() []corev1.EnvVar {
								envs := []corev1.EnvVar{
									{
										// Used as default hostname and in Secret names.
										Name: "POD_NAME",
										ValueFrom: &corev1.EnvVarSource{
											FieldRef: &corev1.ObjectFieldSelector{
												FieldPath: "metadata.name",
											},
										},
									},
									{
										// Used by kubeclient to post Events about the Pod's lifecycle.
										Name: "POD_UID",
										ValueFrom: &corev1.EnvVarSource{
											FieldRef: &corev1.ObjectFieldSelector{
												FieldPath: "metadata.uid",
											},
										},
									},
									{
										// Used in an interpolated env var if metrics enabled.
										Name: "POD_IP",
										ValueFrom: &corev1.EnvVarSource{
											FieldRef: &corev1.ObjectFieldSelector{
												FieldPath: "status.podIP",
											},
										},
									},
									{
										// Included for completeness with POD_IP and easier backwards compatibility in future.
										Name: "POD_IPS",
										ValueFrom: &corev1.EnvVarSource{
											FieldRef: &corev1.ObjectFieldSelector{
												FieldPath: "status.podIPs",
											},
										},
									},
									{
										Name: "TS_K8S_PROXY_CONFIG",
										Value: "kube:" + types.NamespacedName{
											Namespace: namespace,
											Name:      "$(POD_NAME)-config",
										}.String(),
									},
									{
										// This ensures that cert renewals can succeed if ACME account
										// keys have changed since issuance. We cannot guarantee or
										// validate that the account key has not changed, see
										// https://github.com/tailscale/tailscale/issues/18251
										Name:  "TS_DEBUG_ACME_FORCE_RENEWAL",
										Value: "true",
									},
								}

								if port != nil {
									envs = append(envs, corev1.EnvVar{
										Name:  "PORT",
										Value: strconv.Itoa(int(*port)),
									})
								}

								return envs
							}(),
							Ports: []corev1.ContainerPort{
								{
									Name:          "k8s-proxy",
									ContainerPort: 443,
									Protocol:      corev1.ProtocolTCP,
								},
							},
						},
					},
				},
			},
		},
	}

	return sts, nil
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
					"list",
					"watch", // For k8s-proxy.
				},
			},
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
							pgConfigSecretName(pg.Name, i), // Config with auth key.
							pgPodName(pg.Name, i),          // State.
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
				Name:      pgServiceAccountName(pg),
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: pg.Name,
		},
	}
}

// kube-apiserver proxies in auth mode use a static ServiceAccount. Everything
// else uses a per-ProxyGroup ServiceAccount.
func pgServiceAccountName(pg *tsapi.ProxyGroup) string {
	if isAuthAPIServerProxy(pg) {
		return authAPIServerProxySAName
	}

	return pg.Name
}

func isAuthAPIServerProxy(pg *tsapi.ProxyGroup) bool {
	if pg.Spec.Type != tsapi.ProxyGroupTypeKubernetesAPIServer {
		return false
	}

	// The default is auth mode.
	return pg.Spec.KubeAPIServer == nil ||
		pg.Spec.KubeAPIServer.Mode == nil ||
		*pg.Spec.KubeAPIServer.Mode == tsapi.APIServerProxyModeAuth
}

func pgStateSecrets(pg *tsapi.ProxyGroup, namespace string) (secrets []*corev1.Secret) {
	for i := range pgReplicas(pg) {
		secrets = append(secrets, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            pgStateSecretName(pg.Name, i),
				Namespace:       namespace,
				Labels:          pgSecretLabels(pg.Name, kubetypes.LabelSecretTypeState),
				OwnerReferences: pgOwnerReference(pg),
			},
		})
	}

	return secrets
}

func pgEgressCM(pg *tsapi.ProxyGroup, namespace string) (*corev1.ConfigMap, []byte) {
	hp := hepPings(pg)
	hpBs := []byte(strconv.Itoa(hp))
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pgEgressCMName(pg.Name),
			Namespace:       namespace,
			Labels:          pgLabels(pg.Name, nil),
			OwnerReferences: pgOwnerReference(pg),
		},
		BinaryData: map[string][]byte{egressservices.KeyHEPPings: hpBs},
	}, hpBs
}

func pgIngressCM(pg *tsapi.ProxyGroup, namespace string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pgIngressCMName(pg.Name),
			Namespace:       namespace,
			Labels:          pgLabels(pg.Name, nil),
			OwnerReferences: pgOwnerReference(pg),
		},
	}
}

func pgSecretLabels(pgName, secretType string) map[string]string {
	return pgLabels(pgName, map[string]string{
		kubetypes.LabelSecretType: secretType, // "config" or "state".
	})
}

func pgLabels(pgName string, customLabels map[string]string) map[string]string {
	labels := make(map[string]string, len(customLabels)+3)
	for k, v := range customLabels {
		labels[k] = v
	}

	labels[kubetypes.LabelManaged] = "true"
	labels[LabelParentType] = "proxygroup"
	labels[LabelParentName] = pgName

	return labels
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

func pgPodName(pgName string, i int32) string {
	return fmt.Sprintf("%s-%d", pgName, i)
}

func pgHostname(pg *tsapi.ProxyGroup, i int32) string {
	if pg.Spec.HostnamePrefix != "" {
		return fmt.Sprintf("%s-%d", pg.Spec.HostnamePrefix, i)
	}

	return fmt.Sprintf("%s-%d", pg.Name, i)
}

func pgConfigSecretName(pgName string, i int32) string {
	return fmt.Sprintf("%s-%d-config", pgName, i)
}

func pgStateSecretName(pgName string, i int32) string {
	return fmt.Sprintf("%s-%d", pgName, i)
}

func pgEgressCMName(pg string) string {
	return fmt.Sprintf("%s-egress-config", pg)
}

// hasLocalAddrPortSet returns true if the proxyclass has the TS_LOCAL_ADDR_PORT env var set. For egress ProxyGroups,
// currently (2025-01-26) this means that the ProxyGroup does not support graceful failover.
func hasLocalAddrPortSet(proxyClass *tsapi.ProxyClass) bool {
	if proxyClass == nil || proxyClass.Spec.StatefulSet == nil || proxyClass.Spec.StatefulSet.Pod == nil || proxyClass.Spec.StatefulSet.Pod.TailscaleContainer == nil {
		return false
	}
	return slices.ContainsFunc(proxyClass.Spec.StatefulSet.Pod.TailscaleContainer.Env, func(env tsapi.Env) bool {
		return env.Name == envVarTSLocalAddrPort
	})
}

// hepPings returns the number of times a health check endpoint exposed by a Service fronting ProxyGroup replicas should
// be pinged to ensure that all currently configured backend replicas are hit.
func hepPings(pg *tsapi.ProxyGroup) int {
	rc := pgReplicas(pg)
	// Assuming a Service implemented using round robin load balancing, number-of-replica-times should be enough, but in
	// practice, we cannot assume that the requests will be load balanced perfectly.
	return int(rc) * 3
}
