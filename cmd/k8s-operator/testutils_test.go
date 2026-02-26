// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"path"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
)

const (
	vipTestIP = "5.6.7.8"
)

// confgOpts contains configuration options for creating cluster resources for
// Tailscale proxies.
type configOpts struct {
	stsName                                        string
	secretName                                     string
	hostname                                       string
	namespace                                      string
	tailscaleNamespace                             string
	namespaced                                     bool
	parentType                                     string
	proxyType                                      string
	priorityClassName                              string
	firewallMode                                   string
	tailnetTargetIP                                string
	tailnetTargetFQDN                              string
	clusterTargetIP                                string
	clusterTargetDNS                               string
	subnetRoutes                                   string
	isExitNode                                     bool
	isAppConnector                                 bool
	serveConfig                                    *ipn.ServeConfig
	shouldEnableForwardingClusterTrafficViaIngress bool
	proxyClass                                     string // configuration from the named ProxyClass should be applied to proxy resources
	app                                            string
	shouldRemoveAuthKey                            bool
	secretExtraData                                map[string][]byte
	resourceVersion                                string
	replicas                                       *int32
	enableMetrics                                  bool
	serviceMonitorLabels                           tsapi.Labels
}

func expectedSTS(t *testing.T, cl client.Client, opts configOpts) *appsv1.StatefulSet {
	t.Helper()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tsContainer := corev1.Container{
		Name:  "tailscale",
		Image: "tailscale/tailscale",
		Env: []corev1.EnvVar{
			{Name: "TS_USERSPACE", Value: "false"},
			{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "", FieldPath: "status.podIP"}, ResourceFieldRef: nil, ConfigMapKeyRef: nil, SecretKeyRef: nil}},
			{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "", FieldPath: "metadata.name"}, ResourceFieldRef: nil, ConfigMapKeyRef: nil, SecretKeyRef: nil}},
			{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "", FieldPath: "metadata.uid"}, ResourceFieldRef: nil, ConfigMapKeyRef: nil, SecretKeyRef: nil}},
			{Name: "TS_KUBE_SECRET", Value: "$(POD_NAME)"},
			{Name: "TS_EXPERIMENTAL_SERVICE_AUTO_ADVERTISEMENT", Value: "false"},
			{Name: "TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR", Value: "/etc/tsconfig/$(POD_NAME)"},
			{Name: "TS_DEBUG_ACME_FORCE_RENEWAL", Value: "true"},
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.To(true),
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1m"),
				corev1.ResourceMemory: resource.MustParse("1Mi"),
			},
		},
		ImagePullPolicy: "Always",
	}
	if opts.shouldEnableForwardingClusterTrafficViaIngress {
		tsContainer.Env = append(tsContainer.Env, corev1.EnvVar{
			Name:  "EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS",
			Value: "true",
		})
	}
	var annots map[string]string
	var volumes []corev1.Volume
	volumes = []corev1.Volume{
		{
			Name: "tailscaledconfig-0",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: opts.secretName,
				},
			},
		},
	}
	tsContainer.VolumeMounts = []corev1.VolumeMount{{
		Name:      "tailscaledconfig-0",
		ReadOnly:  true,
		MountPath: "/etc/tsconfig/" + opts.secretName,
	}}
	if opts.firewallMode != "" {
		tsContainer.Env = append(tsContainer.Env, corev1.EnvVar{
			Name:  "TS_DEBUG_FIREWALL_MODE",
			Value: opts.firewallMode,
		})
	}
	if opts.tailnetTargetIP != "" {
		mak.Set(&annots, "tailscale.com/operator-last-set-ts-tailnet-target-ip", opts.tailnetTargetIP)
		tsContainer.Env = append(tsContainer.Env, corev1.EnvVar{
			Name:  "TS_TAILNET_TARGET_IP",
			Value: opts.tailnetTargetIP,
		})
	} else if opts.tailnetTargetFQDN != "" {
		mak.Set(&annots, "tailscale.com/operator-last-set-ts-tailnet-target-fqdn", opts.tailnetTargetFQDN)
		tsContainer.Env = append(tsContainer.Env, corev1.EnvVar{
			Name:  "TS_TAILNET_TARGET_FQDN",
			Value: opts.tailnetTargetFQDN,
		})

	} else if opts.clusterTargetIP != "" {
		tsContainer.Env = append(tsContainer.Env, corev1.EnvVar{
			Name:  "TS_DEST_IP",
			Value: opts.clusterTargetIP,
		})
		mak.Set(&annots, "tailscale.com/operator-last-set-cluster-ip", opts.clusterTargetIP)
	} else if opts.clusterTargetDNS != "" {
		tsContainer.Env = append(tsContainer.Env, corev1.EnvVar{
			Name:  "TS_EXPERIMENTAL_DEST_DNS_NAME",
			Value: opts.clusterTargetDNS,
		})
		mak.Set(&annots, "tailscale.com/operator-last-set-cluster-dns-name", opts.clusterTargetDNS)
	}
	if opts.serveConfig != nil {
		tsContainer.Env = append(tsContainer.Env, corev1.EnvVar{
			Name:  "TS_SERVE_CONFIG",
			Value: "/etc/tailscaled/$(POD_NAME)/serve-config",
		})
		volumes = append(volumes, corev1.Volume{
			Name: "serve-config-0",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: opts.secretName,
					Items: []corev1.KeyToPath{{
						Key:  "serve-config",
						Path: "serve-config",
					}},
				},
			},
		})
		tsContainer.VolumeMounts = append(tsContainer.VolumeMounts, corev1.VolumeMount{Name: "serve-config-0", ReadOnly: true, MountPath: path.Join("/etc/tailscaled", opts.secretName)})
	}
	tsContainer.Env = append(tsContainer.Env, corev1.EnvVar{
		Name:  "TS_INTERNAL_APP",
		Value: opts.app,
	})
	if opts.enableMetrics {
		tsContainer.Env = append(tsContainer.Env,
			corev1.EnvVar{
				Name:  "TS_DEBUG_ADDR_PORT",
				Value: "$(POD_IP):9001"},
			corev1.EnvVar{
				Name:  "TS_TAILSCALED_EXTRA_ARGS",
				Value: "--debug=$(TS_DEBUG_ADDR_PORT)",
			},
			corev1.EnvVar{
				Name:  "TS_LOCAL_ADDR_PORT",
				Value: "$(POD_IP):9002",
			},
			corev1.EnvVar{
				Name:  "TS_ENABLE_METRICS",
				Value: "true",
			},
		)
		tsContainer.Ports = append(tsContainer.Ports,
			corev1.ContainerPort{Name: "debug", ContainerPort: 9001, Protocol: "TCP"},
			corev1.ContainerPort{Name: "metrics", ContainerPort: 9002, Protocol: "TCP"},
		)
	}
	ss := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "StatefulSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.stsName,
			Namespace: "operator-ns",
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource":      "test",
				"tailscale.com/parent-resource-ns":   opts.namespace,
				"tailscale.com/parent-resource-type": opts.parentType,
			},
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: opts.replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "1234-UID"},
			},
			ServiceName: opts.stsName,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations:                annots,
					DeletionGracePeriodSeconds: ptr.To[int64](10),
					Labels: map[string]string{
						"tailscale.com/managed":              "true",
						"tailscale.com/parent-resource":      "test",
						"tailscale.com/parent-resource-ns":   opts.namespace,
						"tailscale.com/parent-resource-type": opts.parentType,
						"app":                                "1234-UID",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "proxies",
					PriorityClassName:  opts.priorityClassName,
					InitContainers: []corev1.Container{
						{
							Name:    "sysctler",
							Image:   "tailscale/tailscale",
							Command: []string{"/bin/sh", "-c"},
							Args:    []string{"sysctl -w net.ipv4.ip_forward=1 && if sysctl net.ipv6.conf.all.forwarding; then sysctl -w net.ipv6.conf.all.forwarding=1; fi"},
							SecurityContext: &corev1.SecurityContext{
								Privileged: ptr.To(true),
							},
						},
					},
					Containers: []corev1.Container{tsContainer},
					Volumes:    volumes,
				},
			},
		},
	}
	// If opts.proxyClass is set, retrieve the ProxyClass and apply
	// configuration from that to the StatefulSet.
	if opts.proxyClass != "" {
		t.Logf("applying configuration from ProxyClass %s", opts.proxyClass)
		proxyClass := new(tsapi.ProxyClass)
		if err := cl.Get(context.Background(), types.NamespacedName{Name: opts.proxyClass}, proxyClass); err != nil {
			t.Fatalf("error getting ProxyClass: %v", err)
		}
		return applyProxyClassToStatefulSet(proxyClass, ss, new(tailscaleSTSConfig), zl.Sugar())
	}
	return ss
}

func expectedSTSUserspace(t *testing.T, cl client.Client, opts configOpts) *appsv1.StatefulSet {
	t.Helper()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tsContainer := corev1.Container{
		Name:  "tailscale",
		Image: "tailscale/tailscale",
		Env: []corev1.EnvVar{
			{Name: "TS_USERSPACE", Value: "true"},
			{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "", FieldPath: "status.podIP"}, ResourceFieldRef: nil, ConfigMapKeyRef: nil, SecretKeyRef: nil}},
			{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "", FieldPath: "metadata.name"}, ResourceFieldRef: nil, ConfigMapKeyRef: nil, SecretKeyRef: nil}},
			{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "", FieldPath: "metadata.uid"}, ResourceFieldRef: nil, ConfigMapKeyRef: nil, SecretKeyRef: nil}},
			{Name: "TS_KUBE_SECRET", Value: "$(POD_NAME)"},
			{Name: "TS_EXPERIMENTAL_SERVICE_AUTO_ADVERTISEMENT", Value: "false"},
			{Name: "TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR", Value: "/etc/tsconfig/$(POD_NAME)"},
			{Name: "TS_DEBUG_ACME_FORCE_RENEWAL", Value: "true"},
			{Name: "TS_SERVE_CONFIG", Value: "/etc/tailscaled/$(POD_NAME)/serve-config"},
			{Name: "TS_INTERNAL_APP", Value: opts.app},
		},
		ImagePullPolicy: "Always",
		VolumeMounts: []corev1.VolumeMount{
			{Name: "tailscaledconfig-0", ReadOnly: true, MountPath: path.Join("/etc/tsconfig", opts.secretName)},
			{Name: "serve-config-0", ReadOnly: true, MountPath: path.Join("/etc/tailscaled", opts.secretName)},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1m"),
				corev1.ResourceMemory: resource.MustParse("1Mi"),
			},
		},
	}
	if opts.enableMetrics {
		tsContainer.Env = append(tsContainer.Env,
			corev1.EnvVar{
				Name:  "TS_DEBUG_ADDR_PORT",
				Value: "$(POD_IP):9001"},
			corev1.EnvVar{
				Name:  "TS_TAILSCALED_EXTRA_ARGS",
				Value: "--debug=$(TS_DEBUG_ADDR_PORT)",
			},
			corev1.EnvVar{
				Name:  "TS_LOCAL_ADDR_PORT",
				Value: "$(POD_IP):9002",
			},
			corev1.EnvVar{
				Name:  "TS_ENABLE_METRICS",
				Value: "true",
			},
		)
		tsContainer.Ports = append(tsContainer.Ports, corev1.ContainerPort{
			Name: "debug", ContainerPort: 9001, Protocol: "TCP"},
			corev1.ContainerPort{Name: "metrics", ContainerPort: 9002, Protocol: "TCP"},
		)
	}
	volumes := []corev1.Volume{
		{
			Name: "tailscaledconfig-0",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: opts.secretName,
				},
			},
		},
		{
			Name: "serve-config-0",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: opts.secretName,
					Items:      []corev1.KeyToPath{{Key: "serve-config", Path: "serve-config"}},
				},
			},
		},
	}
	ss := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "StatefulSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.stsName,
			Namespace: "operator-ns",
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource":      "test",
				"tailscale.com/parent-resource-ns":   opts.namespace,
				"tailscale.com/parent-resource-type": opts.parentType,
			},
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "1234-UID"},
			},
			ServiceName: opts.stsName,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					DeletionGracePeriodSeconds: ptr.To[int64](10),
					Labels: map[string]string{
						"tailscale.com/managed":              "true",
						"tailscale.com/parent-resource":      "test",
						"tailscale.com/parent-resource-ns":   opts.namespace,
						"tailscale.com/parent-resource-type": opts.parentType,
						"app":                                "1234-UID",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "proxies",
					PriorityClassName:  opts.priorityClassName,
					Containers:         []corev1.Container{tsContainer},
					Volumes:            volumes,
				},
			},
		},
	}
	// If opts.proxyClass is set, retrieve the ProxyClass and apply
	// configuration from that to the StatefulSet.
	if opts.proxyClass != "" {
		t.Logf("applying configuration from ProxyClass %s", opts.proxyClass)
		proxyClass := new(tsapi.ProxyClass)
		if err := cl.Get(context.Background(), types.NamespacedName{Name: opts.proxyClass}, proxyClass); err != nil {
			t.Fatalf("error getting ProxyClass: %v", err)
		}
		return applyProxyClassToStatefulSet(proxyClass, ss, new(tailscaleSTSConfig), zl.Sugar())
	}
	return ss
}

func expectedHeadlessService(name string, parentType string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:         name,
			GenerateName: "ts-test-",
			Namespace:    "operator-ns",
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource":      "test",
				"tailscale.com/parent-resource-ns":   "default",
				"tailscale.com/parent-resource-type": parentType,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "1234-UID",
			},
			ClusterIP:      "None",
			IPFamilyPolicy: ptr.To(corev1.IPFamilyPolicyPreferDualStack),
		},
	}
}

func expectedMetricsService(opts configOpts) *corev1.Service {
	labels := metricsLabels(opts)
	selector := map[string]string{
		"tailscale.com/managed":              "true",
		"tailscale.com/parent-resource":      "test",
		"tailscale.com/parent-resource-type": opts.parentType,
	}
	if opts.namespaced {
		selector["tailscale.com/parent-resource-ns"] = opts.namespace
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      metricsResourceName(opts.stsName),
			Namespace: opts.tailscaleNamespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: selector,
			Type:     corev1.ServiceTypeClusterIP,
			Ports:    []corev1.ServicePort{{Protocol: "TCP", Port: 9002, Name: "metrics"}},
		},
	}
}

func metricsLabels(opts configOpts) map[string]string {
	promJob := fmt.Sprintf("ts_%s_default_test", opts.proxyType)
	if !opts.namespaced {
		promJob = fmt.Sprintf("ts_%s_test", opts.proxyType)
	}
	labels := map[string]string{
		"tailscale.com/managed":        "true",
		"tailscale.com/metrics-target": opts.stsName,
		"ts_prom_job":                  promJob,
		"ts_proxy_type":                opts.proxyType,
		"ts_proxy_parent_name":         "test",
	}
	if opts.namespaced {
		labels["ts_proxy_parent_namespace"] = "default"
	}
	return labels
}

func expectedServiceMonitor(t *testing.T, opts configOpts) *unstructured.Unstructured {
	t.Helper()
	smLabels := metricsLabels(opts)
	if len(opts.serviceMonitorLabels) != 0 {
		smLabels = mergeMapKeys(smLabels, opts.serviceMonitorLabels.Parse())
	}
	name := metricsResourceName(opts.stsName)
	sm := &ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       opts.tailscaleNamespace,
			Labels:          smLabels,
			ResourceVersion: opts.resourceVersion,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: name, BlockOwnerDeletion: ptr.To(true), Controller: ptr.To(true)}},
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceMonitor",
			APIVersion: "monitoring.coreos.com/v1",
		},
		Spec: ServiceMonitorSpec{
			Selector: metav1.LabelSelector{MatchLabels: metricsLabels(opts)},
			Endpoints: []ServiceMonitorEndpoint{{
				Port: "metrics",
			}},
			NamespaceSelector: ServiceMonitorNamespaceSelector{
				MatchNames: []string{opts.tailscaleNamespace},
			},
			JobLabel: "ts_prom_job",
			TargetLabels: []string{
				"ts_proxy_parent_name",
				"ts_proxy_parent_namespace",
				"ts_proxy_type",
			},
		},
	}
	u, err := serviceMonitorToUnstructured(sm)
	if err != nil {
		t.Fatalf("error converting ServiceMonitor to unstructured: %v", err)
	}
	return u
}

func expectedSecret(t *testing.T, cl client.Client, opts configOpts) *corev1.Secret {
	t.Helper()
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.secretName,
			Namespace: "operator-ns",
		},
	}
	if opts.serveConfig != nil {
		serveConfigBs, err := json.Marshal(opts.serveConfig)
		if err != nil {
			t.Fatalf("error marshalling serve config: %v", err)
		}
		mak.Set(&s.StringData, "serve-config", string(serveConfigBs))
	}
	conf := &ipn.ConfigVAlpha{
		Version:             "alpha0",
		AcceptDNS:           "false",
		Hostname:            &opts.hostname,
		Locked:              "false",
		AuthKey:             ptr.To("secret-authkey"),
		AcceptRoutes:        "false",
		AppConnector:        &ipn.AppConnectorPrefs{Advertise: false},
		NoStatefulFiltering: "true",
	}
	if opts.proxyClass != "" {
		t.Logf("applying configuration from ProxyClass %s", opts.proxyClass)
		proxyClass := new(tsapi.ProxyClass)
		if err := cl.Get(context.Background(), types.NamespacedName{Name: opts.proxyClass}, proxyClass); err != nil {
			t.Fatalf("error getting ProxyClass: %v", err)
		}
		if proxyClass.Spec.TailscaleConfig != nil && proxyClass.Spec.TailscaleConfig.AcceptRoutes {
			conf.AcceptRoutes = "true"
		}
	}
	if opts.shouldRemoveAuthKey {
		conf.AuthKey = nil
	}
	if opts.isAppConnector {
		conf.AppConnector = &ipn.AppConnectorPrefs{Advertise: true}
	}
	var routes []netip.Prefix
	if opts.subnetRoutes != "" || opts.isExitNode {
		r := opts.subnetRoutes
		if opts.isExitNode {
			r = "0.0.0.0/0,::/0," + r
		}
		for _, rr := range strings.Split(r, ",") {
			prefix, err := netip.ParsePrefix(rr)
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, prefix)
		}
	}
	conf.AdvertiseRoutes = routes
	bnn, err := json.Marshal(conf)
	if err != nil {
		t.Fatalf("error marshalling tailscaled config")
	}
	conf.AppConnector = nil
	bn, err := json.Marshal(conf)
	if err != nil {
		t.Fatalf("error marshalling tailscaled config")
	}
	mak.Set(&s.StringData, "cap-95.hujson", string(bn))
	mak.Set(&s.StringData, "cap-107.hujson", string(bnn))
	labels := map[string]string{
		"tailscale.com/managed":              "true",
		"tailscale.com/parent-resource":      "test",
		"tailscale.com/parent-resource-ns":   "default",
		"tailscale.com/parent-resource-type": opts.parentType,
	}
	if opts.parentType == "connector" {
		labels["tailscale.com/parent-resource-ns"] = "" // Connector is cluster scoped
	}
	s.Labels = labels
	for key, val := range opts.secretExtraData {
		mak.Set(&s.Data, key, val)
	}
	return s
}

func findNoGenName(t *testing.T, client client.Client, ns, name, typ string) {
	t.Helper()
	labels := map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentName:        name,
		LabelParentNamespace:   ns,
		LabelParentType:        typ,
	}
	s, err := getSingleObject[corev1.Secret](context.Background(), client, "operator-ns", labels)
	if err != nil {
		t.Fatalf("finding secrets for %q: %v", name, err)
	}
	if s != nil {
		t.Fatalf("found unexpected secret with name %q", s.GetName())
	}
}

func findGenName(t *testing.T, client client.Client, ns, name, typ string) (full, noSuffix string) {
	t.Helper()
	labels := map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentName:        name,
		LabelParentNamespace:   ns,
		LabelParentType:        typ,
	}
	s, err := getSingleObject[corev1.Secret](context.Background(), client, "operator-ns", labels)
	if err != nil {
		t.Fatalf("finding secret for %q: %v", name, err)
	}
	if s == nil {
		t.Fatalf("no secret found for %q %s %+#v", name, ns, labels)
	}
	return s.GetName(), strings.TrimSuffix(s.GetName(), "-0")
}

func findGenNames(t *testing.T, cl client.Client, ns, name, typ string) []string {
	t.Helper()
	labels := map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentName:        name,
		LabelParentNamespace:   ns,
		LabelParentType:        typ,
	}

	var list corev1.SecretList
	if err := cl.List(t.Context(), &list, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
		t.Fatalf("finding secrets for %q: %v", name, err)
	}

	if len(list.Items) == 0 {
		t.Fatalf("no secrets found for %q %s %+#v", name, ns, labels)
	}

	names := make([]string, len(list.Items))
	for i, secret := range list.Items {
		names[i] = secret.GetName()
	}

	return names
}

func mustCreate(t *testing.T, client client.Client, obj client.Object) {
	t.Helper()
	if err := client.Create(context.Background(), obj); err != nil {
		t.Fatalf("creating %q: %v", obj.GetName(), err)
	}
}
func mustCreateAll(t *testing.T, client client.Client, objs ...client.Object) {
	t.Helper()
	for _, obj := range objs {
		mustCreate(t, client, obj)
	}
}

func mustDeleteAll(t *testing.T, client client.Client, objs ...client.Object) {
	t.Helper()
	for _, obj := range objs {
		if err := client.Delete(context.Background(), obj); err != nil {
			t.Fatalf("deleting %q: %v", obj.GetName(), err)
		}
	}
}

func mustUpdate[T any, O ptrObject[T]](t *testing.T, client client.Client, ns, name string, update func(O)) {
	t.Helper()
	obj := O(new(T))
	if err := client.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: ns,
	}, obj); err != nil {
		t.Fatalf("getting %q: %v", name, err)
	}
	update(obj)
	if err := client.Update(context.Background(), obj); err != nil {
		t.Fatalf("updating %q: %v", name, err)
	}
}

func mustUpdateStatus[T any, O ptrObject[T]](t *testing.T, client client.Client, ns, name string, update func(O)) {
	t.Helper()
	obj := O(new(T))
	if err := client.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: ns,
	}, obj); err != nil {
		t.Fatalf("getting %q: %v", name, err)
	}
	update(obj)
	if err := client.Status().Update(context.Background(), obj); err != nil {
		t.Fatalf("updating %q: %v", name, err)
	}
}

// expectEqual accepts a Kubernetes object and a Kubernetes client. It tests
// whether an object with equivalent contents can be retrieved by the passed
// client. If you want to NOT test some object fields for equality, use the
// modify func to ensure that they are removed from the cluster object and the
// object passed as 'want'. If no such modifications are needed, you can pass
// nil in place of the modify function.
func expectEqual[T any, O ptrObject[T]](t *testing.T, client client.Client, want O, modifiers ...func(O)) {
	t.Helper()
	got := O(new(T))
	if err := client.Get(context.Background(), types.NamespacedName{
		Name:      want.GetName(),
		Namespace: want.GetNamespace(),
	}, got); err != nil {
		t.Fatalf("getting %q: %v", want.GetName(), err)
	}
	// The resource version changes eagerly whenever the operator does even a
	// no-op update. Asserting a specific value leads to overly brittle tests,
	// so just remove it from both got and want.
	got.SetResourceVersion("")
	want.SetResourceVersion("")
	for _, modifier := range modifiers {
		modifier(want)
		modifier(got)
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected %s (-got +want):\n%s", reflect.TypeOf(want).Elem().Name(), diff)
	}
}

func expectEqualUnstructured(t *testing.T, client client.Client, want *unstructured.Unstructured) {
	t.Helper()
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(want.GroupVersionKind())
	if err := client.Get(context.Background(), types.NamespacedName{
		Name:      want.GetName(),
		Namespace: want.GetNamespace(),
	}, got); err != nil {
		t.Fatalf("getting %q: %v", want.GetName(), err)
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected contents of Unstructured (-got +want):\n%s", diff)
	}
}

func expectMissing[T any, O ptrObject[T]](t *testing.T, client client.Client, ns, name string) {
	t.Helper()
	obj := O(new(T))
	err := client.Get(context.Background(), types.NamespacedName{
		Name:      name,
		Namespace: ns,
	}, obj)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("%s %s/%s unexpectedly present, wanted missing", reflect.TypeOf(obj).Elem().Name(), ns, name)
	}
}

func expectReconciled(t *testing.T, sr reconcile.Reconciler, ns, name string) {
	t.Helper()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: ns,
			Name:      name,
		},
	}
	res, err := sr.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if res.Requeue {
		t.Fatalf("unexpected immediate requeue")
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("unexpected timed requeue (%v)", res.RequeueAfter)
	}
}

func expectRequeue(t *testing.T, sr reconcile.Reconciler, ns, name string) {
	t.Helper()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: ns,
		},
	}
	res, err := sr.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected timed requeue, got success")
	}
}
func expectError(t *testing.T, sr reconcile.Reconciler, ns, name string) {
	t.Helper()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: ns,
		},
	}
	_, err := sr.Reconcile(context.Background(), req)
	if err == nil {
		t.Error("Reconcile: expected error but did not get one")
	}
}

// expectEvents accepts a test recorder and a list of events, tests that expected
// events are sent down the recorder's channel. Waits for 5s for each event.
func expectEvents(t *testing.T, rec *record.FakeRecorder, wantsEvents []string) {
	t.Helper()
	// Events are not expected to arrive in order.
	seenEvents := make([]string, 0)
	for range len(wantsEvents) {
		timer := time.NewTimer(time.Second * 5)
		defer timer.Stop()
		select {
		case gotEvent := <-rec.Events:
			found := false
			for _, wantEvent := range wantsEvents {
				if wantEvent == gotEvent {
					found = true
					seenEvents = append(seenEvents, gotEvent)
					break
				}
			}
			if !found {
				t.Errorf("got unexpected event %q, expected events: %+#v", gotEvent, wantsEvents)
			}
		case <-timer.C:
			t.Errorf("timeout waiting for an event, wants events %#+v, got events %+#v", wantsEvents, seenEvents)
		}
	}
}

type fakeTSClient struct {
	sync.Mutex
	keyRequests []tailscale.KeyCapabilities
	deleted     []string
	vipServices map[tailcfg.ServiceName]*tailscale.VIPService
}
type fakeTSNetServer struct {
	certDomains []string
}

func (f *fakeTSNetServer) CertDomains() []string {
	return f.certDomains
}

func (c *fakeTSClient) CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error) {
	c.Lock()
	defer c.Unlock()
	c.keyRequests = append(c.keyRequests, caps)
	k := &tailscale.Key{
		ID:           "key",
		Created:      time.Now(),
		Capabilities: caps,
	}
	return "secret-authkey", k, nil
}

func (c *fakeTSClient) Device(ctx context.Context, deviceID string, fields *tailscale.DeviceFieldsOpts) (*tailscale.Device, error) {
	return &tailscale.Device{
		DeviceID: deviceID,
		Hostname: "hostname-" + deviceID,
		Addresses: []string{
			"1.2.3.4",
			"::1",
		},
	}, nil
}

func (c *fakeTSClient) DeleteDevice(ctx context.Context, deviceID string) error {
	c.Lock()
	defer c.Unlock()
	c.deleted = append(c.deleted, deviceID)
	return nil
}

func (c *fakeTSClient) KeyRequests() []tailscale.KeyCapabilities {
	c.Lock()
	defer c.Unlock()
	return c.keyRequests
}

func (c *fakeTSClient) Deleted() []string {
	c.Lock()
	defer c.Unlock()
	return c.deleted
}

func removeResourceReqs(sts *appsv1.StatefulSet) {
	if sts != nil {
		sts.Spec.Template.Spec.Resources = nil
	}
}

func removeTargetPortsFromSvc(svc *corev1.Service) {
	newPorts := make([]corev1.ServicePort, 0)
	for _, p := range svc.Spec.Ports {
		newPorts = append(newPorts, corev1.ServicePort{Protocol: p.Protocol, Port: p.Port, Name: p.Name})
	}
	svc.Spec.Ports = newPorts
}

func removeAuthKeyIfExistsModifier(t *testing.T) func(s *corev1.Secret) {
	return func(secret *corev1.Secret) {
		t.Helper()
		if len(secret.StringData["cap-95.hujson"]) != 0 {
			conf := &ipn.ConfigVAlpha{}
			if err := json.Unmarshal([]byte(secret.StringData["cap-95.hujson"]), conf); err != nil {
				t.Fatalf("error umarshalling 'cap-95.hujson' contents: %v", err)
			}
			conf.AuthKey = nil
			b, err := json.Marshal(conf)
			if err != nil {
				t.Fatalf("error marshalling 'cap-95.huson' contents: %v", err)
			}
			mak.Set(&secret.StringData, "cap-95.hujson", string(b))
		}
		if len(secret.StringData["cap-107.hujson"]) != 0 {
			conf := &ipn.ConfigVAlpha{}
			if err := json.Unmarshal([]byte(secret.StringData["cap-107.hujson"]), conf); err != nil {
				t.Fatalf("error umarshalling 'cap-107.hujson' contents: %v", err)
			}
			conf.AuthKey = nil
			b, err := json.Marshal(conf)
			if err != nil {
				t.Fatalf("error marshalling 'cap-107.huson' contents: %v", err)
			}
			mak.Set(&secret.StringData, "cap-107.hujson", string(b))
		}
	}
}

func (c *fakeTSClient) GetVIPService(ctx context.Context, name tailcfg.ServiceName) (*tailscale.VIPService, error) {
	c.Lock()
	defer c.Unlock()
	if c.vipServices == nil {
		return nil, tailscale.ErrResponse{Status: http.StatusNotFound}
	}
	svc, ok := c.vipServices[name]
	if !ok {
		return nil, tailscale.ErrResponse{Status: http.StatusNotFound}
	}
	return svc, nil
}

func (c *fakeTSClient) ListVIPServices(ctx context.Context) (*tailscale.VIPServiceList, error) {
	c.Lock()
	defer c.Unlock()
	if c.vipServices == nil {
		return nil, &tailscale.ErrResponse{Status: http.StatusNotFound}
	}
	result := &tailscale.VIPServiceList{}
	for _, svc := range c.vipServices {
		result.VIPServices = append(result.VIPServices, *svc)
	}
	return result, nil
}

func (c *fakeTSClient) CreateOrUpdateVIPService(ctx context.Context, svc *tailscale.VIPService) error {
	c.Lock()
	defer c.Unlock()
	if c.vipServices == nil {
		c.vipServices = make(map[tailcfg.ServiceName]*tailscale.VIPService)
	}

	if svc.Addrs == nil {
		svc.Addrs = []string{vipTestIP}
	}

	c.vipServices[svc.Name] = svc
	return nil
}

func (c *fakeTSClient) DeleteVIPService(ctx context.Context, name tailcfg.ServiceName) error {
	c.Lock()
	defer c.Unlock()
	if c.vipServices != nil {
		delete(c.vipServices, name)
	}
	return nil
}

type fakeLocalClient struct {
	status *ipnstate.Status
}

func (f *fakeLocalClient) StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	if f.status == nil {
		return &ipnstate.Status{
			Self: &ipnstate.PeerStatus{
				DNSName: "test-node.test.ts.net.",
			},
		}, nil
	}
	return f.status, nil
}
