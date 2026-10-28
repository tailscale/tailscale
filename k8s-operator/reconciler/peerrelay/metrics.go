// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
)

const (
	serviceMonitorCRD = "servicemonitors.monitoring.coreos.com"

	metricsPortName = "metrics"

	labelPromProxyType       = "ts_proxy_type"
	labelPromProxyParentName = "ts_proxy_parent_name"
	labelPromJob             = "ts_prom_job"
)

var serviceMonitorGVK = schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"}

func metricsServiceName(prName string) string {
	return resourceName(prName) + "-metrics"
}

func peerRelayMetricsLabels(prName string) map[string]string {
	labels := peerRelayLabels(prName)
	labels[labelPromProxyType] = parentTypePeerRelay
	labels[labelPromProxyParentName] = prName
	labels[labelPromJob] = fmt.Sprintf("ts_%s_%s", parentTypePeerRelay, prName)
	return labels
}

func (r *Reconciler) peerRelayMetricsService(pr *tsapi.PeerRelay) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      metricsServiceName(pr.Name),
			Namespace: r.tailscaleNamespace,
			Labels:    peerRelayMetricsLabels(pr.Name),
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: peerRelayLabels(pr.Name),
			Ports: []corev1.ServicePort{
				{
					Name:     metricsPortName,
					Protocol: corev1.ProtocolTCP,
					Port:     tailscaled.HealthCheckPort,
				},
			},
		},
	}
}

// peerRelayServiceMonitor returns a ServiceMonitor that scrapes svc.
func peerRelayServiceMonitor(svc *corev1.Service, spec *tsapi.ServiceMonitor) *unstructured.Unstructured {
	labels := make(map[string]string, len(svc.Labels)+len(spec.Labels))
	maps.Copy(labels, spec.Labels.Parse())
	maps.Copy(labels, svc.Labels)

	matchLabels := make(map[string]any, len(svc.Labels))
	for k, v := range svc.Labels {
		matchLabels[k] = v
	}

	sm := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"selector":          map[string]any{"matchLabels": matchLabels},
			"endpoints":         []any{map[string]any{"port": metricsPortName}},
			"namespaceSelector": map[string]any{"matchNames": []any{svc.Namespace}},
			"jobLabel":          labelPromJob,
			"targetLabels":      []any{labelPromProxyType, labelPromProxyParentName},
		},
	}}
	sm.SetGroupVersionKind(serviceMonitorGVK)
	sm.SetName(svc.Name)
	sm.SetNamespace(svc.Namespace)
	sm.SetLabels(labels)
	// Deleting the metrics Service garbage collects the ServiceMonitor.
	sm.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(svc, corev1.SchemeGroupVersion.WithKind("Service"))})
	return sm
}

// ensureMetricsResources applies or removes the metrics Service and ServiceMonitor as the ProxyClass asks.
func (r *Reconciler) ensureMetricsResources(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, pc *tsapi.ProxyClass) error {
	if pc == nil || pc.Spec.Metrics == nil || !pc.Spec.Metrics.Enable {
		return r.deleteMetricsService(ctx, logger, pr)
	}

	svc := r.peerRelayMetricsService(pr)
	logger.Debugf("applying metrics Service %q", svc.Name)
	if err := r.Patch(ctx, svc, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply metrics Service: %w", err)
	}

	found, err := hasServiceMonitorCRD(ctx, r.Client)
	switch {
	case err != nil:
		return fmt.Errorf("failed to get %q CRD: %w", serviceMonitorCRD, err)
	case !found:
		return nil
	}

	if pc.Spec.Metrics.ServiceMonitor == nil || !pc.Spec.Metrics.ServiceMonitor.Enable {
		return r.deleteServiceMonitor(ctx, logger, svc)
	}

	return r.ensureServiceMonitor(ctx, logger, peerRelayServiceMonitor(svc, pc.Spec.Metrics.ServiceMonitor))
}

// ensureServiceMonitor creates or updates desired without a patch, as the operator's RBAC can't patch ServiceMonitors.
func (r *Reconciler) ensureServiceMonitor(ctx context.Context, logger *zap.SugaredLogger, desired *unstructured.Unstructured) error {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(serviceMonitorGVK)
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		logger.Debugf("creating ServiceMonitor %q", desired.GetName())
		if err = r.Create(ctx, desired); err != nil {
			return fmt.Errorf("failed to create ServiceMonitor: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("failed to get ServiceMonitor: %w", err)
	}

	if reflect.DeepEqual(existing.GetLabels(), desired.GetLabels()) {
		return nil
	}

	logger.Debugf("updating ServiceMonitor %q", desired.GetName())
	existing.SetLabels(desired.GetLabels())
	if err = r.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update ServiceMonitor: %w", err)
	}

	return nil
}

func (r *Reconciler) deleteServiceMonitor(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) error {
	sm := &unstructured.Unstructured{}
	sm.SetGroupVersionKind(serviceMonitorGVK)
	sm.SetName(svc.Name)
	sm.SetNamespace(svc.Namespace)

	err := r.Delete(ctx, sm)
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("failed to delete ServiceMonitor: %w", err)
	}

	logger.Debugf("deleted ServiceMonitor %q", sm.GetName())
	return nil
}

func (r *Reconciler) deleteMetricsService(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: metricsServiceName(pr.Name), Namespace: r.tailscaleNamespace},
	}

	err := r.Delete(ctx, svc)
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("failed to delete metrics Service: %w", err)
	}

	logger.Debugf("deleted metrics Service %q", svc.Name)
	return nil
}

func hasServiceMonitorCRD(ctx context.Context, cl client.Client) (bool, error) {
	var crd apiextensionsv1.CustomResourceDefinition
	err := cl.Get(ctx, types.NamespacedName{Name: serviceMonitorCRD}, &crd)
	switch {
	case apierrors.IsNotFound(err):
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}
