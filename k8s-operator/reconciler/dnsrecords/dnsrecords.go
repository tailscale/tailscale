// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package dnsrecords provides reconciliation logic for keeping the dnsrecords
// ConfigMap up to date with DNS records for tailscale ingress and egress proxies.
package dnsrecords

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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/net"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	reconcilerName = "dns-records-reconciler"

	dnsRecordsRecocilerFinalizer = "tailscale.com/dns-records-reconciler"
	annotationTSMagicDNSName     = "tailscale.com/magic-dnsname"

	// Service types for consistent string usage.
	serviceTypeIngress = "ingress"
	serviceTypeSvc     = "svc"

	optimisticLockErrorMsg = "the object has been modified; please apply your changes to the latest version and try again"

	// AnnotationTailnetTargetFQDN is the annotation used to configure an egress proxy's tailnet target FQDN.
	AnnotationTailnetTargetFQDN = "tailscale.com/tailnet-fqdn"

	labelProxyGroup = "tailscale.com/proxy-group"
	labelSvcType    = "tailscale.com/svc-type"
	typeEgress      = "egress"
)

// ReconcilerOptions contains the options for creating a new Reconciler.
type ReconcilerOptions struct {
	Client                client.Client
	TailscaleNamespace    string
	Logger                *zap.SugaredLogger
	IsDefaultLoadBalancer bool // true if operator is the default ingress controller in this cluster
}

// Reconciler knows how to update dnsrecords ConfigMap with DNS records.
// The records that it creates are:
//   - For tailscale Ingress, a mapping of the Ingress's MagicDNSName to the IP addresses
//     (both IPv4 and IPv6) of the ingress proxy Pod.
//   - For egress proxies configured via tailscale.com/tailnet-fqdn annotation, a
//     mapping of the tailnet FQDN to the IP addresses (both IPv4 and IPv6) of the egress proxy Pod.
//
// Records will only be created if there is exactly one ready
// tailscale.com/v1alpha1.DNSConfig instance in the cluster (so that we know
// that there is a ts.net nameserver deployed in the cluster).
type Reconciler struct {
	client.Client
	tsNamespace           string
	logger                *zap.SugaredLogger
	isDefaultLoadBalancer bool
}

// NewReconciler creates a new Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	return &Reconciler{
		Client:                options.Client,
		tsNamespace:           options.TailscaleNamespace,
		logger:                options.Logger.Named(reconcilerName),
		isDefaultLoadBalancer: options.IsDefaultLoadBalancer,
	}
}

// Register registers the dnsrecords reconciler with the controller manager.
func (r *Reconciler) Register(mgr manager.Manager) error {
	logger := r.logger.Named("event-handlers")
	epsHandler := handler.EnqueueRequestsFromMapFunc(endpointSliceHandler)
	dnsCfgHandler := handler.EnqueueRequestsFromMapFunc(enqueueAllIngressEgressProxySvcsInNS(r.tsNamespace, r.Client, logger))
	svcHandler := handler.EnqueueRequestsFromMapFunc(serviceHandler)
	ingressHandler := handler.EnqueueRequestsFromMapFunc(ingressHandlerForNamespace(r.tsNamespace, r.isDefaultLoadBalancer, r.Client, logger))
	return builder.ControllerManagedBy(mgr).
		Named(reconcilerName).
		Watches(&corev1.Service{}, svcHandler).
		Watches(&networkingv1.Ingress{}, ingressHandler).
		Watches(&discoveryv1.EndpointSlice{}, epsHandler).
		Watches(&tsapi.DNSConfig{}, dnsCfgHandler).
		Complete(r)
}

// Reconcile takes a reconcile.Request for a Service fronting a
// tailscale proxy and updates DNS Records in dnsrecords ConfigMap for the
// in-cluster ts.net nameserver if required.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := r.logger.With("Service", req.NamespacedName)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	proxySvc := new(corev1.Service)
	err = r.Client.Get(ctx, req.NamespacedName, proxySvc)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Service not found")
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Service: %w", err)
	}
	if !(reconciler.IsManagedByType(proxySvc, serviceTypeSvc) || reconciler.IsManagedByType(proxySvc, serviceTypeIngress)) {
		logger.Debugf("Service is not a proxy Service for a tailscale ingress or egress proxy; do nothing")
		return reconcile.Result{}, nil
	}

	if !proxySvc.DeletionTimestamp.IsZero() {
		logger.Debug("Service is being deleted, clean up resources")
		return reconcile.Result{}, r.maybeCleanup(ctx, proxySvc, logger)
	}

	// Check that there is a ts.net nameserver deployed to the cluster by
	// checking that there is tailscale.com/v1alpha1.DNSConfig resource in a
	// Ready state.
	dnsCfgLst := new(tsapi.DNSConfigList)
	if err = r.List(ctx, dnsCfgLst); err != nil {
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

	if err := r.maybeProvision(ctx, proxySvc, logger); err != nil {
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
func (r *Reconciler) maybeProvision(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) error {
	if !r.isInterestingService(ctx, proxySvc) {
		logger.Debug("Service is not fronting a proxy that we create DNS records for; do nothing")
		return nil
	}
	fqdn, err := r.fqdnForDNSRecord(ctx, proxySvc, logger)
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
		if err = r.updateDNSConfig(ctx, updateFunc); err != nil {
			return fmt.Errorf("error removing record for %s: %w", oldFqdn, err)
		}
	}
	mak.Set(&proxySvc.Annotations, annotationTSMagicDNSName, fqdn)
	if !apiequality.Semantic.DeepEqual(oldProxySvc, proxySvc) {
		logger.Infof("provisioning DNS record for MagicDNS name: %s", fqdn) // this will be printed exactly once
		if err := r.Update(ctx, proxySvc); err != nil {
			return fmt.Errorf("error updating proxy Service metadata: %w", err)
		}
	}

	// Get the IP addresses for the DNS record
	ip4s, ip6s, err := r.getTargetIPs(ctx, proxySvc, logger)
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
	if err = r.updateDNSConfig(ctx, updateFunc); err != nil {
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
func (r *Reconciler) maybeCleanup(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) error {
	ix := slices.Index(proxySvc.Finalizers, dnsRecordsRecocilerFinalizer)
	if ix == -1 {
		logger.Debugf("no finalizer, nothing to do")
		return nil
	}
	cm := &corev1.ConfigMap{}
	err := r.Client.Get(ctx, types.NamespacedName{Name: operatorutils.DNSRecordsCMName, Namespace: r.tsNamespace}, cm)
	if apierrors.IsNotFound(err) {
		logger.Debug("'dnsrecords' ConfigMap not found")
		return r.removeProxySvcFinalizer(ctx, proxySvc)
	}
	if err != nil {
		return fmt.Errorf("error retrieving 'dnsrecords' ConfigMap: %w", err)
	}
	if cm.Data == nil {
		logger.Debug("'dnsrecords' ConfigMap contains no records")
		return r.removeProxySvcFinalizer(ctx, proxySvc)
	}
	_, ok := cm.Data[operatorutils.DNSRecordsCMKey]
	if !ok {
		logger.Debug("'dnsrecords' ConfigMap contains no records")
		return r.removeProxySvcFinalizer(ctx, proxySvc)
	}
	fqdn := proxySvc.GetAnnotations()[annotationTSMagicDNSName]
	if fqdn == "" {
		return r.removeProxySvcFinalizer(ctx, proxySvc)
	}
	logger.Infof("removing DNS record for MagicDNS name %s", fqdn)
	updateFunc := func(rec *operatorutils.Records) {
		delete(rec.IP4, fqdn)
		if rec.IP6 != nil {
			delete(rec.IP6, fqdn)
		}
	}
	if err = r.updateDNSConfig(ctx, updateFunc); err != nil {
		return fmt.Errorf("error updating DNS config: %w", err)
	}
	return r.removeProxySvcFinalizer(ctx, proxySvc)
}

func (r *Reconciler) removeProxySvcFinalizer(ctx context.Context, proxySvc *corev1.Service) error {
	idx := slices.Index(proxySvc.Finalizers, dnsRecordsRecocilerFinalizer)
	if idx == -1 {
		return nil
	}
	proxySvc.Finalizers = slices.Delete(proxySvc.Finalizers, idx, idx+1)
	return r.Update(ctx, proxySvc)
}

// fqdnForDNSRecord returns MagicDNS name associated with a given proxy Service.
// If the proxy Service is for a tailscale Ingress proxy, returns ingress.status.loadBalancer.ingress.hostname.
// If the proxy Service is for a tailscale egress proxy configured via tailscale.com/tailnet-fqdn annotation, returns the annotation value.
// For ProxyGroup egress Services, returns the tailnet-fqdn annotation from the parent Service.
// This function is not expected to be called with proxy Services for other
// proxy types, or any other Services, but it just returns an empty string if
// that happens.
func (r *Reconciler) fqdnForDNSRecord(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) (string, error) {
	parentName := reconciler.ParentFromObjectLabels(proxySvc)
	if reconciler.IsManagedByType(proxySvc, serviceTypeIngress) {
		ing := new(networkingv1.Ingress)
		if err := r.Get(ctx, parentName, ing); err != nil {
			return "", err
		}
		if len(ing.Status.LoadBalancer.Ingress) == 0 {
			return "", nil
		}
		return ing.Status.LoadBalancer.Ingress[0].Hostname, nil
	}
	if reconciler.IsManagedByType(proxySvc, serviceTypeSvc) {
		svc := new(corev1.Service)
		if err := r.Get(ctx, parentName, svc); apierrors.IsNotFound(err) {
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
func (r *Reconciler) updateDNSConfig(ctx context.Context, update func(*operatorutils.Records)) error {
	cm := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: operatorutils.DNSRecordsCMName, Namespace: r.tsNamespace}, cm)
	if apierrors.IsNotFound(err) {
		r.logger.Info("[unexpected] dnsrecords ConfigMap not found in cluster. Not updating DNS records. Please open an issue and attach operator logs.")
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
	return r.Update(ctx, cm)
}

// isSvcForFQDNEgressProxy returns true if the Service is a headless Service
// created for a proxy for a tailscale egress Service configured via
// tailscale.com/tailnet-fqdn annotation.
func (r *Reconciler) isSvcForFQDNEgressProxy(ctx context.Context, svc *corev1.Service) (bool, error) {
	if !reconciler.IsManagedByType(svc, "svc") {
		return false, nil
	}
	parentName := reconciler.ParentFromObjectLabels(svc)
	parentSvc := new(corev1.Service)
	if err := r.Get(ctx, parentName, parentSvc); apierrors.IsNotFound(err) {
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
func (r *Reconciler) isProxyGroupEgressService(svc *corev1.Service) bool {
	return svc.GetLabels()[labelProxyGroup] != "" &&
		svc.GetLabels()[labelSvcType] == typeEgress &&
		svc.Spec.Type == corev1.ServiceTypeClusterIP &&
		reconciler.IsManagedByType(svc, serviceTypeSvc)
}

// isInterestingService reports whether the Service is one that we should create
// DNS records for.
func (r *Reconciler) isInterestingService(ctx context.Context, svc *corev1.Service) bool {
	if reconciler.IsManagedByType(svc, serviceTypeIngress) {
		return true
	}

	isEgressFQDNSvc, err := r.isSvcForFQDNEgressProxy(ctx, svc)
	if err != nil {
		return false
	}
	if isEgressFQDNSvc {
		return true
	}

	if r.isProxyGroupEgressService(svc) {
		return r.parentSvcTargetsFQDN(ctx, svc)
	}

	return false
}

// parentSvcTargetsFQDN reports whether the parent Service of a ProxyGroup
// egress Service has an FQDN target (not an IP target).
func (r *Reconciler) parentSvcTargetsFQDN(ctx context.Context, svc *corev1.Service) bool {
	parentName := reconciler.ParentFromObjectLabels(svc)
	parentSvc := new(corev1.Service)
	if err := r.Get(ctx, parentName, parentSvc); err != nil {
		return false
	}
	return parentSvc.Annotations[AnnotationTailnetTargetFQDN] != ""
}

// getTargetIPs returns the IPv4 and IPv6 addresses that should be used for DNS records
// for the given proxy Service.
func (r *Reconciler) getTargetIPs(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) ([]string, []string, error) {
	if r.isProxyGroupEgressService(proxySvc) {
		return r.getClusterIPServiceIPs(proxySvc, logger)
	}
	return r.getPodIPs(ctx, proxySvc, logger)
}

// getClusterIPServiceIPs returns the ClusterIPs of a ProxyGroup egress Service.
// It separates IPv4 and IPv6 addresses for dual-stack services.
func (r *Reconciler) getClusterIPServiceIPs(proxySvc *corev1.Service, logger *zap.SugaredLogger) ([]string, []string, error) {
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
func (r *Reconciler) getPodIPs(ctx context.Context, proxySvc *corev1.Service, logger *zap.SugaredLogger) ([]string, []string, error) {
	// Get the Pod IP addresses for the proxy from the EndpointSlices for
	// the headless Service. The Service can have multiple EndpointSlices
	// associated with it, for example in dual-stack clusters.
	labels := map[string]string{discoveryv1.LabelServiceName: proxySvc.Name} // https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	var eps = new(discoveryv1.EndpointSliceList)
	if err := r.List(ctx, eps, client.InNamespace(r.tsNamespace), client.MatchingLabels(labels)); err != nil {
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

// endpointSliceHandler filters EndpointSlice events for which
// dns-records-reconciler should reconcile a headless Service. The only events
// it should reconcile are those for EndpointSlices associated with proxy
// headless Services.
func endpointSliceHandler(ctx context.Context, o client.Object) []reconcile.Request {
	if !reconciler.IsManagedByType(o, "svc") && !reconciler.IsManagedByType(o, "ingress") {
		return nil
	}
	headlessSvcName, ok := o.GetLabels()[discoveryv1.LabelServiceName] // https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	if !ok {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: o.GetNamespace(), Name: headlessSvcName}}}
}

// serviceHandler filters Service events for which dns-records-reconciler
// should reconcile. If the event is for a cluster ingress/cluster egress
// proxy's headless Service, returns the Service for reconcile.
func serviceHandler(ctx context.Context, o client.Object) []reconcile.Request {
	if reconciler.IsManagedByType(o, "svc") || reconciler.IsManagedByType(o, "ingress") {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: o.GetNamespace(), Name: o.GetName()}}}
	}
	return nil
}

// ingressHandlerForNamespace filters Ingress events to ensure that
// dns-records-reconciler only reconciles on tailscale Ingress events. When an
// event is observed on a tailscale Ingress, reconcile the proxy headless Service.
func ingressHandlerForNamespace(ns string, isDefaultLoadBalancer bool, cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		ing, ok := o.(*networkingv1.Ingress)
		if !ok {
			return nil
		}
		if !isDefaultLoadBalancer && (ing.Spec.IngressClassName == nil || *ing.Spec.IngressClassName != "tailscale") {
			return nil
		}
		proxyResourceLabels := reconciler.ChildResourceLabels(ing.Name, ing.Namespace, "ingress")
		headlessSvc, err := getSingleObject[corev1.Service](ctx, cl, ns, proxyResourceLabels)
		if err != nil {
			logger.Errorf("error getting headless Service from parent labels: %v", err)
			return nil
		}
		if headlessSvc == nil {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: headlessSvc.Namespace, Name: headlessSvc.Name}}}
	}
}

// enqueueAllIngressEgressProxySvcsInNS returns a handler.MapFunc that on
// DNSConfig changes enqueues all headless Services for ingress/egress proxies
// in the operator namespace.
func enqueueAllIngressEgressProxySvcsInNS(ns string, cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, _ client.Object) []reconcile.Request {
		reqs := make([]reconcile.Request, 0)

		// Get all headless Services for proxies configured using Service.
		svcProxyLabels := map[string]string{
			kubetypes.LabelManaged:     "true",
			reconciler.LabelParentType: "svc",
		}
		svcHeadlessSvcList := &corev1.ServiceList{}
		if err := cl.List(ctx, svcHeadlessSvcList, client.InNamespace(ns), client.MatchingLabels(svcProxyLabels)); err != nil {
			logger.Errorf("error listing headless Services for tailscale ingress/egress Services in operator namespace: %v", err)
			return nil
		}
		for _, svc := range svcHeadlessSvcList.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}})
		}

		// Get all headless Services for proxies configured using Ingress.
		ingProxyLabels := map[string]string{
			kubetypes.LabelManaged:     "true",
			reconciler.LabelParentType: "ingress",
		}
		ingHeadlessSvcList := &corev1.ServiceList{}
		if err := cl.List(ctx, ingHeadlessSvcList, client.InNamespace(ns), client.MatchingLabels(ingProxyLabels)); err != nil {
			logger.Errorf("error listing headless Services for tailscale Ingresses in operator namespace: %v", err)
			return nil
		}
		for _, svc := range ingHeadlessSvcList.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}})
		}
		return reqs
	}
}

type ptrObject[T any] interface {
	client.Object
	*T
}

// getSingleObject searches for k8s objects of type T with the given labels,
// and returns it. Returns nil if no objects match the labels, and an error if
// more than one object matches.
func getSingleObject[T any, O ptrObject[T]](ctx context.Context, c client.Client, ns string, labels map[string]string) (O, error) {
	ret := O(new(T))
	kinds, _, err := c.Scheme().ObjectKinds(ret)
	if err != nil {
		return nil, err
	}
	if len(kinds) != 1 {
		return nil, fmt.Errorf("more than 1 GroupVersionKind for %T", ret)
	}

	gvk := kinds[0]
	gvk.Kind += "List"
	lst := unstructured.UnstructuredList{}
	lst.SetGroupVersionKind(gvk)
	if err := c.List(ctx, &lst, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
		return nil, err
	}

	if len(lst.Items) == 0 {
		return nil, nil
	}
	if len(lst.Items) > 1 {
		return nil, fmt.Errorf("found multiple matching %T objects", ret)
	}

	item := lst.Items[0]
	ret2 := O(new(T))
	if err := c.Scheme().Convert(&item, ret2, nil); err != nil {
		return nil, err
	}
	return ret2, nil
}
