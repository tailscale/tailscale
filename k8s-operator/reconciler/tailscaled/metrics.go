// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailscaled

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
)

const (
	// ServiceMonitorCRD is the name of the Prometheus ServiceMonitor CustomResourceDefinition.
	ServiceMonitorCRD = "servicemonitors.monitoring.coreos.com"

	labelMetricsTarget = "tailscale.com/metrics-target"

	// These labels get transferred from the metrics Service to the ingested Prometheus metrics.
	labelPromProxyType            = "ts_proxy_type"
	labelPromProxyParentName      = "ts_proxy_parent_name"
	labelPromProxyParentNamespace = "ts_proxy_parent_namespace"
	labelPromJob                  = "ts_prom_job"
)

// MetricsOptions describes the proxy that metrics resources are managed for.
type MetricsOptions struct {
	StatefulSetName string            // name of the proxy's StatefulSet; not needed by EnsureMetricsResourcesDeleted
	Namespace       string            // namespace of the proxy's StatefulSet
	PodLabels       map[string]string // labels that select the proxy's Pods
	Labels          map[string]string // extra labels for the metrics Service and ServiceMonitor
	ProxyType       string            // value of the ts_proxy_type label
	ParentName      string            // name of the resource the proxy was created for
	ParentNamespace string            // namespace of the resource the proxy was created for; empty if cluster scoped
}

// HasServiceMonitorCRD reports whether the Prometheus ServiceMonitor CRD is installed.
func HasServiceMonitorCRD(ctx context.Context, cl client.Client) (bool, error) {
	sm := &apiextensionsv1.CustomResourceDefinition{}
	if err := cl.Get(ctx, types.NamespacedName{Name: ServiceMonitorCRD}, sm); apierrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

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
	NamespaceSelector ServiceMonitorNamespaceSelector `json:"namespaceSelector"`
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

// EnsureMetricsResources creates, updates or deletes the metrics Service and ServiceMonitor for a proxy, as its
// ProxyClass's spec.metrics asks.
func EnsureMetricsResources(ctx context.Context, cl client.Client, logger *zap.SugaredLogger, opts MetricsOptions, pc *tsapi.ProxyClass) error {
	if pc == nil || pc.Spec.Metrics == nil || !pc.Spec.Metrics.Enable {
		return EnsureMetricsResourcesDeleted(ctx, cl, opts)
	}
	metricsSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      MetricsResourceName(opts.StatefulSetName),
			Namespace: opts.Namespace,
			Labels:    metricsResourceLabels(opts),
		},
		Spec: corev1.ServiceSpec{
			Selector: opts.PodLabels,
			Type:     corev1.ServiceTypeClusterIP,
			Ports:    []corev1.ServicePort{{Protocol: "TCP", Port: HealthCheckPort, Name: "metrics"}},
		},
	}
	metricsSvc, err := ensureMetricsService(ctx, cl, metricsSvc)
	if err != nil {
		return fmt.Errorf("error ensuring metrics Service: %w", err)
	}

	crdExists, err := HasServiceMonitorCRD(ctx, cl)
	if err != nil {
		return fmt.Errorf("error verifying that %q CRD exists: %w", ServiceMonitorCRD, err)
	}
	if !crdExists {
		return nil
	}

	if pc.Spec.Metrics.ServiceMonitor == nil || !pc.Spec.Metrics.ServiceMonitor.Enable {
		return maybeCleanupServiceMonitor(ctx, cl, opts.StatefulSetName, opts.Namespace)
	}

	logger.Infof("ensuring ServiceMonitor for metrics Service %s/%s", metricsSvc.Namespace, metricsSvc.Name)
	svcMonitor, err := newServiceMonitor(metricsSvc, pc.Spec.Metrics.ServiceMonitor)
	if err != nil {
		return fmt.Errorf("error creating ServiceMonitor: %w", err)
	}

	existing := svcMonitor.DeepCopy()
	err = cl.Get(ctx, client.ObjectKeyFromObject(metricsSvc), existing)
	if apierrors.IsNotFound(err) {
		if err := cl.Create(ctx, svcMonitor); err != nil {
			return fmt.Errorf("error creating ServiceMonitor: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("error getting ServiceMonitor: %w", err)
	}
	// Currently, we only update labels on the ServiceMonitor as those are the only values that can change.
	if !reflect.DeepEqual(existing.GetLabels(), svcMonitor.GetLabels()) {
		existing.SetLabels(svcMonitor.GetLabels())
		if err := cl.Update(ctx, existing); err != nil {
			return fmt.Errorf("error updating ServiceMonitor: %w", err)
		}
	}
	return nil
}

// ensureMetricsService creates svc, or updates the existing Service's ports and selector, and returns the result.
func ensureMetricsService(ctx context.Context, cl client.Client, svc *corev1.Service) (*corev1.Service, error) {
	existing := &corev1.Service{}
	err := cl.Get(ctx, client.ObjectKeyFromObject(svc), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := cl.Create(ctx, svc); err != nil {
			return nil, err
		}
		return svc, nil
	case err != nil:
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	existing.Spec.Ports = svc.Spec.Ports
	existing.Spec.Selector = svc.Spec.Selector
	if err := cl.Update(ctx, existing); err != nil {
		return nil, err
	}
	return existing, nil
}

// EnsureMetricsResourcesDeleted ensures that any metrics resources created for a proxy are deleted. Only metrics
// Service gets deleted explicitly because the ServiceMonitor has Service's owner reference, so gets garbage collected
// automatically.
func EnsureMetricsResourcesDeleted(ctx context.Context, cl client.Client, opts MetricsOptions) error {
	sel := metricsSvcSelector(opts)
	return cl.DeleteAllOf(ctx, &corev1.Service{}, client.InNamespace(opts.Namespace), client.MatchingLabels(sel))
}

// maybeCleanupServiceMonitor cleans up any ServiceMonitor created for the named proxy StatefulSet.
func maybeCleanupServiceMonitor(ctx context.Context, cl client.Client, stsName, ns string) error {
	smName := MetricsResourceName(stsName)
	sm := serviceMonitorTemplate(smName, ns)
	u, err := ServiceMonitorToUnstructured(sm)
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
func newServiceMonitor(metricsSvc *corev1.Service, spec *tsapi.ServiceMonitor) (*unstructured.Unstructured, error) {
	sm := serviceMonitorTemplate(metricsSvc.Name, metricsSvc.Namespace)
	sm.ObjectMeta.Labels = metricsSvc.Labels
	if spec != nil && len(spec.Labels) > 0 {
		sm.ObjectMeta.Labels = mergeMapKeys(sm.ObjectMeta.Labels, spec.Labels.Parse())
	}

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
	return ServiceMonitorToUnstructured(sm)
}

// ServiceMonitorToUnstructured takes a ServiceMonitor and converts it to Unstructured type that can be used by the c/r
// client in Kubernetes API server calls.
func ServiceMonitorToUnstructured(sm *ServiceMonitor) (*unstructured.Unstructured, error) {
	contents, err := runtime.DefaultUnstructuredConverter.ToUnstructured(sm)
	if err != nil {
		return nil, fmt.Errorf("error converting ServiceMonitor to Unstructured: %w", err)
	}
	u := &unstructured.Unstructured{}
	u.SetUnstructuredContent(contents)
	u.SetGroupVersionKind(sm.GroupVersionKind())
	return u, nil
}

// MetricsResourceName returns name for metrics Service and ServiceMonitor for a proxy StatefulSet.
func MetricsResourceName(stsName string) string {
	// Maximum length of StatefulSet name if 52 chars, so this is fine.
	return fmt.Sprintf("%s-metrics", stsName)
}

// metricsResourceLabels constructs labels that will be applied to metrics Service and metrics ServiceMonitor for a
// proxy.
func metricsResourceLabels(opts MetricsOptions) map[string]string {
	lbls := map[string]string{
		kubetypes.LabelManaged:   "true",
		labelMetricsTarget:       opts.StatefulSetName,
		labelPromProxyType:       opts.ProxyType,
		labelPromProxyParentName: tsoperator.TruncateLabelValue(opts.ParentName),
	}
	// Include namespace label for proxies created for a namespaced type.
	if opts.ParentNamespace != "" {
		lbls[labelPromProxyParentNamespace] = tsoperator.TruncateLabelValue(opts.ParentNamespace)
	}
	lbls[labelPromJob] = tsoperator.TruncateLabelValue(promJobName(opts))
	return mergeMapKeys(lbls, opts.Labels)
}

// promJobName constructs the value of the Prometheus job label that will apply to all metrics for a ServiceMonitor.
func promJobName(opts MetricsOptions) string {
	// Include parent resource namespace for proxies created for namespaced types.
	if opts.ParentNamespace != "" {
		return fmt.Sprintf("ts_%s_%s_%s", opts.ProxyType, opts.ParentNamespace, opts.ParentName)
	}
	return fmt.Sprintf("ts_%s_%s", opts.ProxyType, opts.ParentName)
}

// metricsSvcSelector returns the minimum label set to uniquely identify a metrics Service for a proxy.
func metricsSvcSelector(opts MetricsOptions) map[string]string {
	sel := map[string]string{
		labelPromProxyType:       opts.ProxyType,
		labelPromProxyParentName: tsoperator.TruncateLabelValue(opts.ParentName),
	}
	// Include namespace label for proxies created for a namespaced type.
	if opts.ParentNamespace != "" {
		sel[labelPromProxyParentNamespace] = tsoperator.TruncateLabelValue(opts.ParentNamespace)
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

func mergeMapKeys(a, b map[string]string) map[string]string {
	m := make(map[string]string, len(a)+len(b))
	maps.Copy(m, b)
	maps.Copy(m, a)
	return m
}
