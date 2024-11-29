// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

const (
	labelMetricsTarget = "tailscale.com/metrics-target"

	// These labels get transferred from the metrics Service to the ingested Prometheus metrics.
	labelPromProxyType            = "ts_proxy_type"
	labelPromProxyParentName      = "ts_proxy_parent_name"
	labelPromProxyParentNamespace = "ts_proxy_parent_namespace"
	labelPromJob                  = "ts_prom_job"

	serviceMonitorCRD = "servicemonitors.monitoring.coreos.com"
)

// ServiceMonitor contains a subset of fields of servicemonitors.monitoring.coreos.com Custom Resource Definition.
// Duplicating it here allows us to avoid importing prometheus-operator library.
// https://github.com/prometheus-operator/prometheus-operator/blob/bb4514e0d5d69f20270e29cfd4ad39b87865ccdf/pkg/apis/monitoring/v1/servicemonitor_types.go#L40
type ServiceMonitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              ServiceMonitorSpec `json:"spec"`
}

// https://github.com/prometheus-operator/prometheus-operator/blob/bb4514e0d5d69f20270e29cfd4ad39b87865ccdf/pkg/apis/monitoring/v1/servicemonitor_types.go#L55
type ServiceMonitorSpec struct {
	// Endpoints defines the endpoints to be scraped on the selected Service(s).
	// https://github.com/prometheus-operator/prometheus-operator/blob/bb4514e0d5d69f20270e29cfd4ad39b87865ccdf/pkg/apis/monitoring/v1/servicemonitor_types.go#L82
	Endpoints []ServiceMonitorEndpoint `json:"endpoints"`
	// JobLabel is the label on the Service whose value will become the value of the Prometheus job label for the metrics ingested via this ServiceMonitor.
	// https://github.com/prometheus-operator/prometheus-operator/blob/bb4514e0d5d69f20270e29cfd4ad39b87865ccdf/pkg/apis/monitoring/v1/servicemonitor_types.go#L66
	JobLabel string `json:"jobLabel"`
	// NamespaceSelector selects the namespace of Service(s) that this ServiceMonitor allows to scrape.
	// https://github.com/prometheus-operator/prometheus-operator/blob/bb4514e0d5d69f20270e29cfd4ad39b87865ccdf/pkg/apis/monitoring/v1/servicemonitor_types.go#L88
	NamespaceSelector ServiceMonitorNamespaceSelector `json:"namespaceSelector,omitempty"`
	// Selector is the label selector for Service(s) that this ServiceMonitor allows to scrape.
	// https://github.com/prometheus-operator/prometheus-operator/blob/bb4514e0d5d69f20270e29cfd4ad39b87865ccdf/pkg/apis/monitoring/v1/servicemonitor_types.go#L85
	Selector metav1.LabelSelector `json:"selector"`
	// TargetLabels are labels on the selected Service that should be applied as Prometheus labels to the ingested metrics.
	// https://github.com/prometheus-operator/prometheus-operator/blob/bb4514e0d5d69f20270e29cfd4ad39b87865ccdf/pkg/apis/monitoring/v1/servicemonitor_types.go#L72
	TargetLabels []string `json:"targetLabels"`
}

// ServiceMonitorNamespaceSelector selects namespaces in which Prometheus operator will attempt to find Services for
// this ServiceMonitor.
// https://github.com/prometheus-operator/prometheus-operator/blob/bb4514e0d5d69f20270e29cfd4ad39b87865ccdf/pkg/apis/monitoring/v1/servicemonitor_types.go#L88
type ServiceMonitorNamespaceSelector struct {
	MatchNames []string `json:"matchNames,omitempty"`
}

// ServiceMonitorEndpoint defines an endpoint of Service to scrape. We only define port here. Prometheus by default
// scrapes /metrics path, which is what we want.
type ServiceMonitorEndpoint struct {
	// Port is the name of the Service port that Prometheus will scrape.
	Port string `json:"port,omitempty"`
}

func reconcileMetricsResources(ctx context.Context, logger *zap.SugaredLogger, opts *metricsOpts, pc *tsapi.ProxyClass, cl client.Client) error {
	if opts.proxyType == proxyTypeEgress {
		// Metrics are currently not being enabled for standalone egress proxies.
		return nil
	}
	if pc == nil || pc.Spec.Metrics == nil || !pc.Spec.Metrics.Enable {
		return maybeCleanupMetricsResources(ctx, opts, cl)
	}
	metricsSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      metricsResourceName(opts.proxyStsName),
			Namespace: opts.tsNamespace,
			Labels:    metricsResourceLabels(opts),
		},
		Spec: corev1.ServiceSpec{
			Selector: opts.proxyLabels,
			Type:     corev1.ServiceTypeClusterIP,
			Ports:    []corev1.ServicePort{{Protocol: "TCP", Port: 9002, Name: "metrics"}},
		},
	}
	var err error
	metricsSvc, err = createOrUpdate(ctx, cl, opts.tsNamespace, metricsSvc, func(svc *corev1.Service) {
		svc.Spec.Ports = metricsSvc.Spec.Ports
		svc.Spec.Selector = metricsSvc.Spec.Selector
	})
	if err != nil {
		return fmt.Errorf("error ensuring metrics Service: %w", err)
	}

	crdExists, err := hasServiceMonitorCRD(ctx, cl)
	if err != nil {
		return fmt.Errorf("error verifying that %q CRD exists: %w", serviceMonitorCRD, err)
	}
	if !crdExists {
		return nil
	}

	if pc.Spec.Metrics.ServiceMonitor == nil || !pc.Spec.Metrics.ServiceMonitor.Enable {
		return maybeCleanupServiceMonitor(ctx, cl, opts.proxyStsName, opts.tsNamespace)
	}

	logger.Info("ensuring ServiceMonitor for metrics Service %s/%s", metricsSvc.Namespace, metricsSvc.Name)
	svcMonitor, err := newServiceMonitor(metricsSvc)
	if err != nil {
		return fmt.Errorf("error creating ServiceMonitor: %w", err)
	}
	// We don't use createOrUpdate here because that does not work with unstructured types. We also do not update
	// the ServiceMonitor because it is not expected that any of its fields would change. Currently this is good
	// enough, but in future we might want to add logic to create-or-update unstructured types.
	err = cl.Get(ctx, client.ObjectKeyFromObject(metricsSvc), svcMonitor.DeepCopy())
	if apierrors.IsNotFound(err) {
		if err := cl.Create(ctx, svcMonitor); err != nil {
			return fmt.Errorf("error creating ServiceMonitor: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("error getting ServiceMonitor: %w", err)
	}
	return nil
}

// maybeCleanupMetricsResources ensures that any metrics resources created for a proxy are deleted. Only metrics Service
// gets deleted explicitly because the ServiceMonitor has Service's owner reference, so gets garbage collected
// automatically.
func maybeCleanupMetricsResources(ctx context.Context, opts *metricsOpts, cl client.Client) error {
	sel := metricsSvcSelector(opts.proxyLabels, opts.proxyType)
	return cl.DeleteAllOf(ctx, &corev1.Service{}, client.InNamespace(opts.tsNamespace), client.MatchingLabels(sel))
}

// maybeCleanupServiceMonitor cleans up any ServiceMonitor created for the named proxy StatefulSet.
func maybeCleanupServiceMonitor(ctx context.Context, cl client.Client, stsName, ns string) error {
	smName := metricsResourceName(stsName)
	sm := serviceMonitorTemplate(smName, ns)
	u, err := serviceMonitorToUnstructured(sm)
	if err != nil {
		return fmt.Errorf("error building ServiceMonitor: %w", err)
	}
	err = cl.Get(ctx, types.NamespacedName{Name: smName, Namespace: ns}, u)
	if apierrors.IsNotFound(err) {
		return nil // nothing to do
	}
	if err != nil {
		return fmt.Errorf("error verifying if ServiceMonitor %s/%s exists: %w", ns, stsName, err)
	}
	return cl.Delete(ctx, u)
}

// newServiceMonitor takes a metrics Service created for a proxy and constructs and returns a ServiceMonitor for that
// proxy that can be applied to the kube API server.
// The ServiceMonitor is returned as Unstructured type - this allows us to avoid importing prometheus-operator API server client/schema.
func newServiceMonitor(metricsSvc *corev1.Service) (*unstructured.Unstructured, error) {
	sm := serviceMonitorTemplate(metricsSvc.Name, metricsSvc.Namespace)
	sm.ObjectMeta.Labels = metricsSvc.Labels
	sm.ObjectMeta.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(metricsSvc, corev1.SchemeGroupVersion.WithKind("Service"))}
	sm.Spec = ServiceMonitorSpec{
		Selector: metav1.LabelSelector{MatchLabels: metricsSvc.Labels},
		Endpoints: []ServiceMonitorEndpoint{{
			Port: "metrics",
		}},
		NamespaceSelector: ServiceMonitorNamespaceSelector{
			MatchNames: []string{metricsSvc.Namespace},
		},
		JobLabel: labelPromJob,
		TargetLabels: []string{
			labelPromProxyParentName,
			labelPromProxyParentNamespace,
			labelPromProxyType,
		},
	}
	return serviceMonitorToUnstructured(sm)
}

// serviceMonitorToUnstructured takes a ServiceMonitor and converts it to Unstructured type that can be used by the c/r
// client in Kubernetes API server calls.
func serviceMonitorToUnstructured(sm *ServiceMonitor) (*unstructured.Unstructured, error) {
	contents, err := runtime.DefaultUnstructuredConverter.ToUnstructured(sm)
	if err != nil {
		return nil, fmt.Errorf("error converting ServiceMonitor to Unstructured: %w", err)
	}
	u := &unstructured.Unstructured{}
	u.SetUnstructuredContent(contents)
	u.SetGroupVersionKind(sm.GroupVersionKind())
	return u, nil
}

// metricsResourceName returns name for metrics Service and ServiceMonitor for a proxy StatefulSet.
func metricsResourceName(stsName string) string {
	// Maximum length of StatefulSet name if 52 chars, so this is fine.
	return fmt.Sprintf("%s-metrics", stsName)
}

// metricsResourceLabels constructs labels that will be applied to metrics Service and metrics ServiceMonitor for a
// proxy.
func metricsResourceLabels(opts *metricsOpts) map[string]string {
	lbls := map[string]string{
		LabelManaged:             "true",
		labelMetricsTarget:       opts.proxyStsName,
		labelPromProxyType:       opts.proxyType,
		labelPromProxyParentName: opts.proxyLabels[LabelParentName],
	}
	// Include namespace label for proxies created for a namespaced type.
	if isNamespacedProxyType(opts.proxyType) {
		lbls[labelPromProxyParentNamespace] = opts.proxyLabels[LabelParentNamespace]
	}
	lbls[labelPromJob] = promJobName(opts)
	return lbls
}

// promJobName constructs the value of the Prometheus job label that will apply to all metrics for a ServiceMonitor.
func promJobName(opts *metricsOpts) string {
	// Include parent resource namespace for proxies created for namespaced types.
	if opts.proxyType == proxyTypeIngressResource || opts.proxyType == proxyTypeIngressService {
		return fmt.Sprintf("ts_%s_%s_%s", opts.proxyType, opts.proxyLabels[LabelParentNamespace], opts.proxyLabels[LabelParentName])
	}
	return fmt.Sprintf("ts_%s_%s", opts.proxyType, opts.proxyLabels[LabelParentName])
}

// metricsSvcSelector returns the minimum label set to uniquely identify a metrics Service for a proxy.
func metricsSvcSelector(proxyLabels map[string]string, proxyType string) map[string]string {
	sel := map[string]string{
		labelPromProxyType:       proxyType,
		labelPromProxyParentName: proxyLabels[LabelParentName],
	}
	// Include namespace label for proxies created for a namespaced type.
	if isNamespacedProxyType(proxyType) {
		sel[labelPromProxyParentNamespace] = proxyLabels[LabelParentNamespace]
	}
	return sel
}

// serviceMonitorTemplate returns a base ServiceMonitor type that, when converted to Unstructured, is a valid type that
// can be used in kube API server calls via the c/r client.
func serviceMonitorTemplate(name, ns string) *ServiceMonitor {
	return &ServiceMonitor{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceMonitor",
			APIVersion: "monitoring.coreos.com/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
	}
}

type metricsOpts struct {
	proxyStsName string            // name of StatefulSet for proxy
	tsNamespace  string            // namespace in which Tailscale is installed
	proxyLabels  map[string]string // labels of the proxy StatefulSet
	proxyType    string
}

func isNamespacedProxyType(typ string) bool {
	return typ == proxyTypeIngressResource || typ == proxyTypeIngressService
}
