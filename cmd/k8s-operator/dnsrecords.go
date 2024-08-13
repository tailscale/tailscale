// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/net"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	dnsRecordsRecocilerFinalizer = "tailscale.com/dns-records-reconciler"
	annotationTSMagicDNSName     = "tailscale.com/magic-dnsname"
)

// dnsRecordsReconciler knows how to update dnsrecords ConfigMap with DNS
// records.
// The records that it creates are:
//   - For tailscale Ingress, a mapping of the Ingress's MagicDNSName to the IP address of
//     the ingress proxy Pod.
//   - For egress proxies configured via tailscale.com/tailnet-fqdn annotation, a
//     mapping of the tailnet FQDN to the IP address of the egress proxy Pod.
//
// Records will only be created if there is exactly one ready
// tailscale.com/v1alpha1.DNSConfig instance in the cluster (so that we know
// that there is a ts.net nameserver deployed in the cluster).
type dnsRecordsReconciler struct {
	client.Client
	tsNamespace           string // namespace in which we provision tailscale resources
	logger                *zap.SugaredLogger
	isDefaultLoadBalancer bool // true if operator is the default ingress controller in this cluster
}

// Reconcile takes a reconcile.Request for a headless Service fronting a
// tailscale proxy and updates DNS Records in dnsrecords ConfigMap for the
// in-cluster ts.net nameserver if required.
func (dnsRR *dnsRecordsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := dnsRR.logger.With("Service", req.NamespacedName)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	headlessSvc := new(corev1.Service)
	err = dnsRR.Client.Get(ctx, req.NamespacedName, headlessSvc)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Service not found")
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Service: %w", err)
	}
	if !(isManagedByType(headlessSvc, "svc") || isManagedByType(headlessSvc, "ingress")) {
		logger.Debugf("Service is not a headless Service for a tailscale ingress or egress proxy; do nothing")
		return reconcile.Result{}, nil
	}

	if !headlessSvc.DeletionTimestamp.IsZero() {
		logger.Debug("Service is being deleted, clean up resources")
		return reconcile.Result{}, dnsRR.maybeCleanup(ctx, headlessSvc, logger)
	}

	// Check that there is a ts.net nameserver deployed to the cluster by
	// checking that there is tailscale.com/v1alpha1.DNSConfig resource in a
	// Ready state.
	dnsCfgLst := new(tsapi.DNSConfigList)
	if err = dnsRR.List(ctx, dnsCfgLst); err != nil {
		return reconcile.Result{}, fmt.Errorf("error listing DNSConfigs: %w", err)
	}
	if len(dnsCfgLst.Items) == 0 {
		logger.Debugf("DNSConfig does not exist, not creating DNS records")
		return reconcile.Result{}, nil
	}
	if len(dnsCfgLst.Items) > 1 {
		logger.Errorf("Invalid cluster state - more than one DNSConfig found in cluster. Please ensure no more than one exists")
		return reconcile.Result{}, nil
	}
	dnsCfg := dnsCfgLst.Items[0]
	if !operatorutils.DNSCfgIsReady(&dnsCfg) {
		logger.Info("DNSConfig is not ready yet, waiting...")
		return reconcile.Result{}, nil
	}

	return reconcile.Result{}, dnsRR.maybeProvision(ctx, headlessSvc, logger)
}

// maybeProvision ensures that dnsrecords ConfigMap contains a record for the
// proxy associated with the headless Service.
// The record is only provisioned if the proxy is for a tailscale Ingress or
// egress configured via tailscale.com/tailnet-fqdn annotation.
//
// For Ingress, the record is a mapping between the MagicDNSName of the Ingress, retrieved from
// ingress.status.loadBalancer.ingress.hostname field and the proxy Pod IP addresses
// retrieved from the EndpoinSlice associated with this headless Service, i.e
// Records{IP4: <MagicDNS name of the Ingress>: <[IPs of the ingress proxy Pods]>}
//
// For egress, the record is a mapping between tailscale.com/tailnet-fqdn
// annotation and the proxy Pod IP addresses, retrieved from the EndpointSlice
// associated with this headless Service, i.e
// Records{IP4: {<tailscale.com/tailnet-fqdn>: <[IPs of the egress proxy Pods]>}
//
// If records need to be created for this proxy, maybeProvision will also:
// - update the headless Service with a tailscale.com/magic-dnsname annotation
// - update the headless Service with a finalizer
func (dnsRR *dnsRecordsReconciler) maybeProvision(ctx context.Context, headlessSvc *corev1.Service, logger *zap.SugaredLogger) error {
	if headlessSvc == nil {
		logger.Info("[unexpected] maybeProvision called with a nil Service")
		return nil
	}
	isEgressFQDNSvc, err := dnsRR.isSvcForFQDNEgressProxy(ctx, headlessSvc)
	if err != nil {
		return fmt.Errorf("error checking whether the Service is for an egress proxy: %w", err)
	}
	if !(isEgressFQDNSvc || isManagedByType(headlessSvc, "ingress")) {
		logger.Debug("Service is not fronting a proxy that we create DNS records for; do nothing")
		return nil
	}
	fqdn, err := dnsRR.fqdnForDNSRecord(ctx, headlessSvc, logger)
	if err != nil {
		return fmt.Errorf("error determining DNS name for record: %w", err)
	}
	if fqdn == "" {
		logger.Debugf("MagicDNS name does not (yet) exist, not provisioning DNS record")
		return nil // a new reconcile will be triggered once it's added
	}

	oldHeadlessSvc := headlessSvc.DeepCopy()
	// Ensure that headless Service is annotated with a finalizer to help
	// with records cleanup when proxy resources are deleted.
	if !slices.Contains(headlessSvc.Finalizers, dnsRecordsRecocilerFinalizer) {
		headlessSvc.Finalizers = append(headlessSvc.Finalizers, dnsRecordsRecocilerFinalizer)
	}
	// Ensure that headless Service is annotated with the current MagicDNS
	// name to help with records cleanup when proxy resources are deleted or
	// MagicDNS name changes.
	oldFqdn := headlessSvc.Annotations[annotationTSMagicDNSName]
	if oldFqdn != "" && oldFqdn != fqdn { // i.e user has changed the value of tailscale.com/tailnet-fqdn annotation
		logger.Debugf("MagicDNS name has changed, remvoving record for %s", oldFqdn)
		updateFunc := func(rec *operatorutils.Records) {
			delete(rec.IP4, oldFqdn)
		}
		if err = dnsRR.updateDNSConfig(ctx, updateFunc); err != nil {
			return fmt.Errorf("error removing record for %s: %w", oldFqdn, err)
		}
	}
	mak.Set(&headlessSvc.Annotations, annotationTSMagicDNSName, fqdn)
	if !apiequality.Semantic.DeepEqual(oldHeadlessSvc, headlessSvc) {
		logger.Infof("provisioning DNS record for MagicDNS name: %s", fqdn) // this will be printed exactly once
		if err := dnsRR.Update(ctx, headlessSvc); err != nil {
			return fmt.Errorf("error updating proxy headless Service metadata: %w", err)
		}
	}

	// Get the Pod IP addresses for the proxy from the EndpointSlices for
	// the headless Service. The Service can have multiple EndpointSlices
	// associated with it, for example in dual-stack clusters.
	labels := map[string]string{discoveryv1.LabelServiceName: headlessSvc.Name} // https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	var eps = new(discoveryv1.EndpointSliceList)
	if err := dnsRR.List(ctx, eps, client.InNamespace(dnsRR.tsNamespace), client.MatchingLabels(labels)); err != nil {
		return fmt.Errorf("error listing EndpointSlices for the proxy's headless Service: %w", err)
	}
	if len(eps.Items) == 0 {
		logger.Debugf("proxy's headless Service EndpointSlice does not yet exist. We will reconcile again once it's created")
		return nil
	}
	// Each EndpointSlice for a Service can have a list of endpoints that each
	// can have multiple addresses - these are the IP addresses of any Pods
	// selected by that Service. Pick all the IPv4 addresses.
	// It is also possible that multiple EndpointSlices have overlapping addresses.
	// https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#duplicate-endpoints
	ips := make(set.Set[string], 0)
	for _, slice := range eps.Items {
		if slice.AddressType != discoveryv1.AddressTypeIPv4 {
			logger.Infof("EndpointSlice is for AddressType %s, currently only IPv4 address type is supported", slice.AddressType)
			continue
		}
		for _, ep := range slice.Endpoints {
			if !epIsReady(&ep) {
				logger.Debugf("Endpoint with addresses %v appears not ready to receive traffic %v", ep.Addresses, ep.Conditions.String())
				continue
			}
			for _, ip := range ep.Addresses {
				if !net.IsIPv4String(ip) {
					logger.Infof("EndpointSlice contains IP address %q that is not IPv4, ignoring. Currently only IPv4 is supported", ip)
				} else {
					ips.Add(ip)
				}
			}
		}
	}
	if ips.Len() == 0 {
		logger.Debugf("EndpointSlice for the Service contains no IPv4 addresses. We will reconcile again once they are created.")
		return nil
	}
	updateFunc := func(rec *operatorutils.Records) {
		mak.Set(&rec.IP4, fqdn, ips.Slice())
	}
	if err = dnsRR.updateDNSConfig(ctx, updateFunc); err != nil {
		return fmt.Errorf("error updating DNS records: %w", err)
	}
	return nil
}

// epIsReady reports whether the endpoint is currently in a state to receive new
// traffic. As per kube docs, only explicitly set 'false' for 'Ready' or
// 'Serving' conditions or explicitly set 'true' for 'Terminating' condition
// means that the Endpoint is NOT ready.
// https://github.com/kubernetes/kubernetes/blob/60c4c2b2521fb454ce69dee737e3eb91a25e0535/pkg/apis/discovery/types.go#L109-L131
func epIsReady(ep *discoveryv1.Endpoint) bool {
	return (ep.Conditions.Ready == nil || *ep.Conditions.Ready) &&
		(ep.Conditions.Serving == nil || *ep.Conditions.Serving) &&
		(ep.Conditions.Terminating == nil || !*ep.Conditions.Terminating)
}

// maybeCleanup ensures that the DNS record for the proxy has been removed from
// dnsrecords ConfigMap and the tailscale.com/dns-records-reconciler finalizer
// has been removed from the Service. If the record is not found in the
// ConfigMap, the ConfigMap does not exist, or the Service does not have
// tailscale.com/magic-dnsname annotation, just remove the finalizer.
func (h *dnsRecordsReconciler) maybeCleanup(ctx context.Context, headlessSvc *corev1.Service, logger *zap.SugaredLogger) error {
	ix := slices.Index(headlessSvc.Finalizers, dnsRecordsRecocilerFinalizer)
	if ix == -1 {
		logger.Debugf("no finalizer, nothing to do")
		return nil
	}
	cm := &corev1.ConfigMap{}
	err := h.Client.Get(ctx, types.NamespacedName{Name: operatorutils.DNSRecordsCMName, Namespace: h.tsNamespace}, cm)
	if apierrors.IsNotFound(err) {
		logger.Debug("'dsnrecords' ConfigMap not found")
		return h.removeHeadlessSvcFinalizer(ctx, headlessSvc)
	}
	if err != nil {
		return fmt.Errorf("error retrieving 'dnsrecords' ConfigMap: %w", err)
	}
	if cm.Data == nil {
		logger.Debug("'dnsrecords' ConfigMap contains no records")
		return h.removeHeadlessSvcFinalizer(ctx, headlessSvc)
	}
	_, ok := cm.Data[operatorutils.DNSRecordsCMKey]
	if !ok {
		logger.Debug("'dnsrecords' ConfigMap contains no records")
		return h.removeHeadlessSvcFinalizer(ctx, headlessSvc)
	}
	fqdn, _ := headlessSvc.GetAnnotations()[annotationTSMagicDNSName]
	if fqdn == "" {
		return h.removeHeadlessSvcFinalizer(ctx, headlessSvc)
	}
	logger.Infof("removing DNS record for MagicDNS name %s", fqdn)
	updateFunc := func(rec *operatorutils.Records) {
		delete(rec.IP4, fqdn)
	}
	if err = h.updateDNSConfig(ctx, updateFunc); err != nil {
		return fmt.Errorf("error updating DNS config: %w", err)
	}
	return h.removeHeadlessSvcFinalizer(ctx, headlessSvc)
}

func (dnsRR *dnsRecordsReconciler) removeHeadlessSvcFinalizer(ctx context.Context, headlessSvc *corev1.Service) error {
	idx := slices.Index(headlessSvc.Finalizers, dnsRecordsRecocilerFinalizer)
	if idx == -1 {
		return nil
	}
	headlessSvc.Finalizers = append(headlessSvc.Finalizers[:idx], headlessSvc.Finalizers[idx+1:]...)
	return dnsRR.Update(ctx, headlessSvc)
}

// fqdnForDNSRecord returns MagicDNS name associated with a given headless Service.
// If the headless Service is for a tailscale Ingress proxy, returns ingress.status.loadBalancer.ingress.hostname.
// If the headless Service is for an tailscale egress proxy configured via tailscale.com/tailnet-fqdn annotation, returns the annotation value.
// This function is not expected to be called with headless Services for other
// proxy types, or any other Services, but it just returns an empty string if
// that happens.
func (dnsRR *dnsRecordsReconciler) fqdnForDNSRecord(ctx context.Context, headlessSvc *corev1.Service, logger *zap.SugaredLogger) (string, error) {
	parentName := parentFromObjectLabels(headlessSvc)
	if isManagedByType(headlessSvc, "ingress") {
		ing := new(networkingv1.Ingress)
		if err := dnsRR.Get(ctx, parentName, ing); err != nil {
			return "", err
		}
		if len(ing.Status.LoadBalancer.Ingress) == 0 {
			return "", nil
		}
		return ing.Status.LoadBalancer.Ingress[0].Hostname, nil
	}
	if isManagedByType(headlessSvc, "svc") {
		svc := new(corev1.Service)
		if err := dnsRR.Get(ctx, parentName, svc); apierrors.IsNotFound(err) {
			logger.Info("[unexpected] parent Service for egress proxy %s not found", headlessSvc.Name)
			return "", nil
		} else if err != nil {
			return "", err
		}
		return svc.Annotations[AnnotationTailnetTargetFQDN], nil
	}
	return "", nil
}

// updateDNSConfig runs the provided update function against dnsrecords
// ConfigMap. At this point the in-cluster ts.net nameserver is expected to be
// successfully created together with the ConfigMap.
func (dnsRR *dnsRecordsReconciler) updateDNSConfig(ctx context.Context, update func(*operatorutils.Records)) error {
	cm := &corev1.ConfigMap{}
	err := dnsRR.Get(ctx, types.NamespacedName{Name: operatorutils.DNSRecordsCMName, Namespace: dnsRR.tsNamespace}, cm)
	if apierrors.IsNotFound(err) {
		dnsRR.logger.Info("[unexpected] dnsrecords ConfigMap not found in cluster. Not updating DNS records. Please open an isue and attach operator logs.")
		return nil
	}
	if err != nil {
		return fmt.Errorf("error retrieving dnsrecords ConfigMap: %w", err)
	}
	dnsRecords := operatorutils.Records{Version: operatorutils.Alpha1Version, IP4: map[string][]string{}}
	if cm.Data != nil && cm.Data[operatorutils.DNSRecordsCMKey] != "" {
		if err := json.Unmarshal([]byte(cm.Data[operatorutils.DNSRecordsCMKey]), &dnsRecords); err != nil {
			return err
		}
	}
	update(&dnsRecords)
	dnsRecordsBs, err := json.Marshal(dnsRecords)
	if err != nil {
		return fmt.Errorf("error marshalling DNS records: %w", err)
	}
	mak.Set(&cm.Data, operatorutils.DNSRecordsCMKey, string(dnsRecordsBs))
	return dnsRR.Update(ctx, cm)
}

// isSvcForFQDNEgressProxy returns true if the Service is a headless Service
// created for a proxy for a tailscale egress Service configured via
// tailscale.com/tailnet-fqdn annotation.
func (dnsRR *dnsRecordsReconciler) isSvcForFQDNEgressProxy(ctx context.Context, svc *corev1.Service) (bool, error) {
	if !isManagedByType(svc, "svc") {
		return false, nil
	}
	parentName := parentFromObjectLabels(svc)
	parentSvc := new(corev1.Service)
	if err := dnsRR.Get(ctx, parentName, parentSvc); apierrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	annots := parentSvc.Annotations
	return annots != nil && annots[AnnotationTailnetTargetFQDN] != "", nil
}
