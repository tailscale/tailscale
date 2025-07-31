// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

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

	// Service types for consistent string usage
	serviceTypeIngress = "ingress"
	serviceTypeSvc     = "svc"
)

// dnsRecordsReconciler knows how to update dnsrecords ConfigMap with DNS
// records.
// The records that it creates are:
//   - For tailscale Ingress, a mapping of the Ingress's MagicDNSName to the IP addresses
//     (both IPv4 and IPv6) of the ingress proxy Pod.
//   - For egress proxies configured via tailscale.com/tailnet-fqdn annotation, a
//     mapping of the tailnet FQDN to the IP addresses (both IPv4 and IPv6) of the egress proxy Pod.
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

// Reconcile takes a reconcile.Request for a Service fronting a
// tailscale proxy and updates DNS Records in dnsrecords ConfigMap for the
// in-cluster ts.net nameserver if required.
func (dnsRR *dnsRecordsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := dnsRR.logger.With("Service", req.NamespacedName)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	proxySvc := new(corev1.Service)
	err = dnsRR.Client.Get(ctx, req.NamespacedName, proxySvc)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Service not found")
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Service: %w", err)
	}
	if !(isManagedByType(proxySvc, serviceTypeSvc) || isManagedByType(proxySvc, serviceTypeIngress)) {
		logger.Debugf("Service is not a proxy Service for a tailscale ingress or egress proxy; do nothing")
		return reconcile.Result{}, nil
	}

	if !proxySvc.DeletionTimestamp.IsZero() {
		logger.Debug("Service is being deleted, clean up resources")
		return reconcile.Result{}, dnsRR.maybeCleanup(ctx, proxySvc, logger)
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

	if err := dnsRR.maybeProvision(ctx, proxySvc, logger); err != nil {
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			logger.Infof("optimistic lock error, retrying: %s", err)
		} else {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// maybeProvision ensures that dnsrecords ConfigMap contains a record for the
// proxy associated with the Service.
// The record is only provisioned if the proxy is for a tailscale Ingress or
// egress configured via tailscale.com/tailnet-fqdn annotation.
//
// For Ingress, the record is a mapping between the MagicDNSName of the Ingress, retrieved from
// ingress.status.loadBalancer.ingress.hostname field and the proxy Pod IP addresses
// retrieved from the EndpointSlice associated with this Service, i.e
// Records{IP4: {<MagicDNS name>: <[IPv4 addresses]>}, IP6: {<MagicDNS name>: <[IPv6 addresses]>}}
//
// For egress, the record is a mapping between tailscale.com/tailnet-fqdn
// annotation and the proxy Pod IP addresses, retrieved from the EndpointSlice
// associated with this Service, i.e
// Records{IP4: {<tailnet-fqdn>: <[IPv4 addresses]>}, IP6: {<tailnet-fqdn>: <[IPv6 addresses]>}}
//
// For ProxyGroup egress, the record is a mapping between tailscale.com/magic-dnsname
// annotation and the ClusterIP Service IPs (which provides portmapping), i.e
// Records{IP4: {<magic-dnsname>: <[IPv4 ClusterIPs]>}, IP6: {<magic-dnsname>: <[IPv6 ClusterIPs]>}}
//
// If records need to be created for this proxy, maybeProvision will also:
// - update the Service with a tailscale.com/magic-dnsname annotation
// - update the Service with a finalizer
func (dnsRR *dnsRecordsReconciler) maybeProvision(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) error {
	if !dnsRR.isInterestingService(ctx, proxySvc) {
		logger.Debug("Service is not fronting a proxy that we create DNS records for; do nothing")
		return nil
	}
	fqdn, err := dnsRR.fqdnForDNSRecord(ctx, proxySvc, logger)
	if err != nil {
		return fmt.Errorf("error determining DNS name for record: %w", err)
	}
	if fqdn == "" {
		logger.Debugf("MagicDNS name does not (yet) exist, not provisioning DNS record")
		return nil // a new reconcile will be triggered once it's added
	}

	oldProxySvc := proxySvc.DeepCopy()
	// Ensure that proxy Service is annotated with a finalizer to help
	// with records cleanup when proxy resources are deleted.
	if !slices.Contains(proxySvc.Finalizers, dnsRecordsRecocilerFinalizer) {
		proxySvc.Finalizers = append(proxySvc.Finalizers, dnsRecordsRecocilerFinalizer)
	}
	// Ensure that proxy Service is annotated with the current MagicDNS
	// name to help with records cleanup when proxy resources are deleted or
	// MagicDNS name changes.
	oldFqdn := proxySvc.Annotations[annotationTSMagicDNSName]
	if oldFqdn != "" && oldFqdn != fqdn { // i.e user has changed the value of tailscale.com/tailnet-fqdn annotation
		logger.Debugf("MagicDNS name has changed, removing record for %s", oldFqdn)
		updateFunc := func(rec *operatorutils.Records) {
			delete(rec.IP4, oldFqdn)
		}
		if err = dnsRR.updateDNSConfig(ctx, updateFunc); err != nil {
			return fmt.Errorf("error removing record for %s: %w", oldFqdn, err)
		}
	}
	mak.Set(&proxySvc.Annotations, annotationTSMagicDNSName, fqdn)
	if !apiequality.Semantic.DeepEqual(oldProxySvc, proxySvc) {
		logger.Infof("provisioning DNS record for MagicDNS name: %s", fqdn) // this will be printed exactly once
		if err := dnsRR.Update(ctx, proxySvc); err != nil {
			return fmt.Errorf("error updating proxy Service metadata: %w", err)
		}
	}

	// Get the IP addresses for the DNS record
	ip4s, ip6s, err := dnsRR.getTargetIPs(ctx, proxySvc, logger)
	if err != nil {
		return fmt.Errorf("error getting target IPs: %w", err)
	}
	if len(ip4s) == 0 && len(ip6s) == 0 {
		logger.Debugf("No target IP addresses available yet. We will reconcile again once they are available.")
		return nil
	}

	updateFunc := func(rec *operatorutils.Records) {
		if len(ip4s) > 0 {
			mak.Set(&rec.IP4, fqdn, ip4s)
		}
		if len(ip6s) > 0 {
			mak.Set(&rec.IP6, fqdn, ip6s)
		}
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
func (dnsRR *dnsRecordsReconciler) maybeCleanup(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) error {
	ix := slices.Index(proxySvc.Finalizers, dnsRecordsRecocilerFinalizer)
	if ix == -1 {
		logger.Debugf("no finalizer, nothing to do")
		return nil
	}
	cm := &corev1.ConfigMap{}
	err := dnsRR.Client.Get(ctx, types.NamespacedName{Name: operatorutils.DNSRecordsCMName, Namespace: dnsRR.tsNamespace}, cm)
	if apierrors.IsNotFound(err) {
		logger.Debug("'dnsrecords' ConfigMap not found")
		return dnsRR.removeProxySvcFinalizer(ctx, proxySvc)
	}
	if err != nil {
		return fmt.Errorf("error retrieving 'dnsrecords' ConfigMap: %w", err)
	}
	if cm.Data == nil {
		logger.Debug("'dnsrecords' ConfigMap contains no records")
		return dnsRR.removeProxySvcFinalizer(ctx, proxySvc)
	}
	_, ok := cm.Data[operatorutils.DNSRecordsCMKey]
	if !ok {
		logger.Debug("'dnsrecords' ConfigMap contains no records")
		return dnsRR.removeProxySvcFinalizer(ctx, proxySvc)
	}
	fqdn := proxySvc.GetAnnotations()[annotationTSMagicDNSName]
	if fqdn == "" {
		return dnsRR.removeProxySvcFinalizer(ctx, proxySvc)
	}
	logger.Infof("removing DNS record for MagicDNS name %s", fqdn)
	updateFunc := func(rec *operatorutils.Records) {
		delete(rec.IP4, fqdn)
		if rec.IP6 != nil {
			delete(rec.IP6, fqdn)
		}
	}
	if err = dnsRR.updateDNSConfig(ctx, updateFunc); err != nil {
		return fmt.Errorf("error updating DNS config: %w", err)
	}
	return dnsRR.removeProxySvcFinalizer(ctx, proxySvc)
}

func (dnsRR *dnsRecordsReconciler) removeProxySvcFinalizer(ctx context.Context, proxySvc *corev1.Service) error {
	idx := slices.Index(proxySvc.Finalizers, dnsRecordsRecocilerFinalizer)
	if idx == -1 {
		return nil
	}
	proxySvc.Finalizers = slices.Delete(proxySvc.Finalizers, idx, idx+1)
	return dnsRR.Update(ctx, proxySvc)
}

// fqdnForDNSRecord returns MagicDNS name associated with a given proxy Service.
// If the proxy Service is for a tailscale Ingress proxy, returns ingress.status.loadBalancer.ingress.hostname.
// If the proxy Service is for an tailscale egress proxy configured via tailscale.com/tailnet-fqdn annotation, returns the annotation value.
// For ProxyGroup egress Services, returns the tailnet-fqdn annotation from the parent Service.
// This function is not expected to be called with proxy Services for other
// proxy types, or any other Services, but it just returns an empty string if
// that happens.
func (dnsRR *dnsRecordsReconciler) fqdnForDNSRecord(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) (string, error) {
	parentName := parentFromObjectLabels(proxySvc)
	if isManagedByType(proxySvc, serviceTypeIngress) {
		ing := new(networkingv1.Ingress)
		if err := dnsRR.Get(ctx, parentName, ing); err != nil {
			return "", err
		}
		if len(ing.Status.LoadBalancer.Ingress) == 0 {
			return "", nil
		}
		return ing.Status.LoadBalancer.Ingress[0].Hostname, nil
	}
	if isManagedByType(proxySvc, serviceTypeSvc) {
		svc := new(corev1.Service)
		if err := dnsRR.Get(ctx, parentName, svc); apierrors.IsNotFound(err) {
			logger.Infof("[unexpected] parent Service for egress proxy %s not found", proxySvc.Name)
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
		dnsRR.logger.Info("[unexpected] dnsrecords ConfigMap not found in cluster. Not updating DNS records. Please open an issue and attach operator logs.")
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

// isProxyGroupEgressService reports whether the Service is a ClusterIP Service
// created for ProxyGroup egress. For ProxyGroup egress, there are no headless
// services. Instead, the DNS reconciler processes the ClusterIP Service
// directly, which has portmapping and should use its own IP for DNS records.
func (dnsRR *dnsRecordsReconciler) isProxyGroupEgressService(svc *corev1.Service) bool {
	return svc.GetLabels()[labelProxyGroup] != "" &&
		svc.GetLabels()[labelSvcType] == typeEgress &&
		svc.Spec.Type == corev1.ServiceTypeClusterIP &&
		isManagedByType(svc, serviceTypeSvc)
}

// isInterestingService reports whether the Service is one that we should create
// DNS records for.
func (dnsRR *dnsRecordsReconciler) isInterestingService(ctx context.Context, svc *corev1.Service) bool {
	if isManagedByType(svc, serviceTypeIngress) {
		return true
	}

	isEgressFQDNSvc, err := dnsRR.isSvcForFQDNEgressProxy(ctx, svc)
	if err != nil {
		return false
	}
	if isEgressFQDNSvc {
		return true
	}

	if dnsRR.isProxyGroupEgressService(svc) {
		return dnsRR.parentSvcTargetsFQDN(ctx, svc)
	}

	return false
}

// parentSvcTargetsFQDN reports whether the parent Service of a ProxyGroup
// egress Service has an FQDN target (not an IP target).
func (dnsRR *dnsRecordsReconciler) parentSvcTargetsFQDN(ctx context.Context, svc *corev1.Service) bool {

	parentName := parentFromObjectLabels(svc)
	parentSvc := new(corev1.Service)
	if err := dnsRR.Get(ctx, parentName, parentSvc); err != nil {
		return false
	}

	return parentSvc.Annotations[AnnotationTailnetTargetFQDN] != ""
}

// getTargetIPs returns the IPv4 and IPv6 addresses that should be used for DNS records
// for the given proxy Service.
func (dnsRR *dnsRecordsReconciler) getTargetIPs(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) ([]string, []string, error) {
	if dnsRR.isProxyGroupEgressService(proxySvc) {
		return dnsRR.getClusterIPServiceIPs(proxySvc, logger)
	}
	return dnsRR.getPodIPs(ctx, proxySvc, logger)
}

// getClusterIPServiceIPs returns the ClusterIPs of a ProxyGroup egress Service.
// It separates IPv4 and IPv6 addresses for dual-stack services.
func (dnsRR *dnsRecordsReconciler) getClusterIPServiceIPs(proxySvc *corev1.Service, logger *zap.SugaredLogger) ([]string, []string, error) {
	// Handle services with no ClusterIP
	if proxySvc.Spec.ClusterIP == "" || proxySvc.Spec.ClusterIP == "None" {
		logger.Debugf("ProxyGroup egress ClusterIP Service does not have a ClusterIP yet.")
		return nil, nil, nil
	}

	var ip4s, ip6s []string

	// Check all ClusterIPs for dual-stack support
	clusterIPs := proxySvc.Spec.ClusterIPs
	if len(clusterIPs) == 0 && proxySvc.Spec.ClusterIP != "" {
		// Fallback to single ClusterIP for backward compatibility
		clusterIPs = []string{proxySvc.Spec.ClusterIP}
	}

	for _, ip := range clusterIPs {
		if net.IsIPv4String(ip) {
			ip4s = append(ip4s, ip)
			logger.Debugf("Using IPv4 ClusterIP %s for ProxyGroup egress DNS record", ip)
		} else if net.IsIPv6String(ip) {
			ip6s = append(ip6s, ip)
			logger.Debugf("Using IPv6 ClusterIP %s for ProxyGroup egress DNS record", ip)
		} else {
			logger.Debugf("ClusterIP %s is not a valid IP address", ip)
		}
	}

	if len(ip4s) == 0 && len(ip6s) == 0 {
		return nil, nil, fmt.Errorf("no valid ClusterIPs found")
	}

	return ip4s, ip6s, nil
}

// getPodIPs returns Pod IPv4 and IPv6 addresses from EndpointSlices for non-ProxyGroup Services.
func (dnsRR *dnsRecordsReconciler) getPodIPs(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) ([]string, []string, error) {
	// Get the Pod IP addresses for the proxy from the EndpointSlices for
	// the headless Service. The Service can have multiple EndpointSlices
	// associated with it, for example in dual-stack clusters.
	labels := map[string]string{discoveryv1.LabelServiceName: proxySvc.Name} // https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	var eps = new(discoveryv1.EndpointSliceList)
	if err := dnsRR.List(ctx, eps, client.InNamespace(dnsRR.tsNamespace), client.MatchingLabels(labels)); err != nil {
		return nil, nil, fmt.Errorf("error listing EndpointSlices for the proxy's Service: %w", err)
	}
	if len(eps.Items) == 0 {
		logger.Debugf("proxy's Service EndpointSlice does not yet exist.")
		return nil, nil, nil
	}
	// Each EndpointSlice for a Service can have a list of endpoints that each
	// can have multiple addresses - these are the IP addresses of any Pods
	// selected by that Service. Separate IPv4 and IPv6 addresses.
	// It is also possible that multiple EndpointSlices have overlapping addresses.
	// https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#duplicate-endpoints
	ip4s := make(set.Set[string], 0)
	ip6s := make(set.Set[string], 0)
	for _, slice := range eps.Items {
		for _, ep := range slice.Endpoints {
			if !epIsReady(&ep) {
				logger.Debugf("Endpoint with addresses %v appears not ready to receive traffic %v", ep.Addresses, ep.Conditions.String())
				continue
			}
			for _, ip := range ep.Addresses {
				switch slice.AddressType {
				case discoveryv1.AddressTypeIPv4:
					if net.IsIPv4String(ip) {
						ip4s.Add(ip)
					} else {
						logger.Debugf("EndpointSlice with AddressType IPv4 contains non-IPv4 address %q, ignoring", ip)
					}
				case discoveryv1.AddressTypeIPv6:
					if net.IsIPv6String(ip) {
						// Strip zone ID if present (e.g., fe80::1%eth0 -> fe80::1)
						if idx := strings.IndexByte(ip, '%'); idx != -1 {
							ip = ip[:idx]
						}
						ip6s.Add(ip)
					} else {
						logger.Debugf("EndpointSlice with AddressType IPv6 contains non-IPv6 address %q, ignoring", ip)
					}
				default:
					logger.Debugf("EndpointSlice is for unsupported AddressType %s, skipping", slice.AddressType)
				}
			}
		}
	}
	if ip4s.Len() == 0 && ip6s.Len() == 0 {
		logger.Debugf("EndpointSlice for the Service contains no IP addresses.")
		return nil, nil, nil
	}
	return ip4s.Slice(), ip6s.Slice(), nil
}
