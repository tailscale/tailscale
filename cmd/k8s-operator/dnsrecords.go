// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet and to make Tailscale nodes available to cluster
// workloads
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/client/tailscale/apitype"
	kube "tailscale.com/k8s-operator"
	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/util/mak"
)

const (
	dnsConfigKey  = "dns.json"
	configMapName = "dnsconfig"

	dnsRecordsRecocilerFinalizer = "tailscale.com/dns-records-reconciler"
	annotationTSMagicDNSName     = "tailscale.com/magic-dns"
)

// dnsRecordsReconciler knows how to update ts.net nameserver with records
// of a tailnet MagicDNS name to kube Service endpoints.
type dnsRecordsReconciler struct {
	client.Client
	// namespace in which tailscale resources get provisioned
	tsNamespace string
	// localClient knows how to talk to tailscaled local API
	localAPIClient        localClient
	logger                *zap.SugaredLogger
	isDefaultLoadBalancer bool
}

type localClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

func (dnsRR *dnsRecordsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := dnsRR.logger.With("EndpointSlice", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	// Check that this is an EndpointSlice is for a headless Service for a
	// tailscale proxy type that we support creating DNS records for.
	// Currently this is cluster egress or L7 cluster ingress.
	eps := new(discoveryv1.EndpointSlice)
	err = dnsRR.Get(ctx, req.NamespacedName, eps)
	if apierrors.IsNotFound(err) {
		logger.Debugf("EndpointSlice not found")
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get EndpointSlice: %w", err)
	}
	if !eps.DeletionTimestamp.IsZero() {
		logger.Debug("EndpointSlice is being deleted, clean up resources")
		return reconcile.Result{}, dnsRR.maybeCleanup(ctx, eps, logger)
	}

	maybeHeadlessSvcName, ok := eps.Labels[discoveryv1.LabelServiceName]
	if !ok {
		logger.Debugf("EndpointSlice does not have %s label, do nothing", discoveryv1.LabelServiceName)
		return reconcile.Result{}, nil
	}
	maybyHeadlessSvc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: maybeHeadlessSvcName, Namespace: dnsRR.tsNamespace}}
	if err = dnsRR.Get(ctx, client.ObjectKeyFromObject(maybyHeadlessSvc), maybyHeadlessSvc); err != nil {
		return reconcile.Result{}, fmt.Errorf("error retrieving Service for EndpointSlice: %w", err)
	}
	ok, err = dnsRR.isHeadlessSvcForSupportedProxy(ctx, maybyHeadlessSvc)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("error validating proxy for DNS records: %w", err)
	}
	if !ok {
		logger.Debugf("EndpointSlice is not for a proxy type that we create DNS records for, do nothing")
		return reconcile.Result{}, nil
	}

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

	if !kube.DNSCfgIsReady(&dnsCfg) {
		logger.Info("DNSConfig is not ready yet, waiting...")
		return reconcile.Result{}, nil
	}
	return reconcile.Result{}, dnsRR.maybeProvision(ctx, eps, logger)
}

func (dnsRR *dnsRecordsReconciler) maybeProvision(ctx context.Context, eps *discoveryv1.EndpointSlice, logger *zap.SugaredLogger) error {
	logger.Debugf("provisioning record")
	if eps == nil {
		return nil
	}
	fqdn, err := dnsRR.fqdnForDNSRecord(ctx, eps, logger)
	if err != nil {
		return fmt.Errorf("error determining DNS name for record: %w", err)
	}
	if fqdn == "" {
		logger.Debugf("MagicDNS name does not (yet) exist, not provisioning DNS record")
		return nil // a new reconcile will be triggered once it's added
	}
	oldEps := eps.DeepCopy()
	if !slices.Contains(eps.Finalizers, dnsRecordsRecocilerFinalizer) {
		eps.Finalizers = append(eps.Finalizers, dnsRecordsRecocilerFinalizer)
	}
	if _, ok := eps.Annotations[annotationTSMagicDNSName]; !ok {
		mak.Set(&eps.Annotations, annotationTSMagicDNSName, fqdn) // label eps with the assocated MagicDNS name to make record cleanup easier
	}
	if !apiequality.Semantic.DeepEqual(oldEps, eps) {
		logger.Infof("provisioning DNS record for MagicDNS name: %s", fqdn) // this will be printed exactly once
		if err := dnsRR.Update(ctx, eps); err != nil {
			return fmt.Errorf("error updating EndpointSlice metadata: %w", err)
		}
	}

	ips := make([]string, 0)
	for _, ep := range eps.Endpoints {
		ips = append(ips, ep.Addresses...)
	}
	if len(ips) == 0 {
		logger.Debugf("No endpoint addresses found")
		return nil // a new reconcile will be triggered once the EndpointSlice is updated with addresses
	}
	updateFunc := func(cfg *operatorutils.TSHosts) {
		mak.Set(&cfg.Hosts, fqdn, ips)
	}
	if err = dnsRR.updateDNSConfig(ctx, updateFunc); err != nil {
		return fmt.Errorf("error updating DNS records: %w", err)
	}
	return nil
}

func (h *dnsRecordsReconciler) maybeCleanup(ctx context.Context, eps *discoveryv1.EndpointSlice, logger *zap.SugaredLogger) error {
	ix := slices.Index(eps.Finalizers, dnsRecordsRecocilerFinalizer)
	if ix == -1 {
		logger.Debugf("no finalizer, nothing to do")
		return nil
	}
	cm := &corev1.ConfigMap{}
	err := h.Client.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: h.tsNamespace}, cm)
	if apierrors.IsNotFound(err) { // If the ConfigMap with the DNS config does not exist, just remove the finalizer
		logger.Debug("CM not found")
		return h.removeEPSFinalizer(ctx, eps)
	}
	if err != nil {
		return fmt.Errorf("error retrieving ConfigMap: %w", err)
	}
	_, ok := cm.Data[dnsConfigKey]
	if !ok {
		logger.Debug("config key not found")
		return h.removeEPSFinalizer(ctx, eps)
	}
	fqdn, ok := eps.GetAnnotations()[annotationTSMagicDNSName]
	if !ok || fqdn == "" {
		return h.removeEPSFinalizer(ctx, eps)
	}
	logger.Infof("removing DNS record for MagicDNS name %s", fqdn)
	updateFunc := func(cfg *operatorutils.TSHosts) {
		delete(cfg.Hosts, fqdn)
	}
	if err = h.updateDNSConfig(ctx, updateFunc); err != nil {
		return fmt.Errorf("error updating DNS config: %w", err)
	}
	return h.removeEPSFinalizer(ctx, eps)
}

func (dnsRR *dnsRecordsReconciler) isHeadlessSvcForSupportedProxy(ctx context.Context, svc *corev1.Service) (bool, error) {
	if isManagedByType(svc, "ingress") {
		return true, nil
	}
	if !isManagedByType(svc, "svc") {
		return false, nil
	}
	parentNSName := parentFromObjectLabels(svc)
	parentSvc := new(corev1.Service)
	if err := dnsRR.Get(ctx, parentNSName, parentSvc); err != nil {
		return false, fmt.Errorf("error retrieving parent Service: %w", err)
	}
	if ip := tailnetTargetAnnotation(parentSvc); ip != "" {
		return true, nil // egress Service
	}
	if _, ok := parentSvc.GetAnnotations()[AnnotationTailnetTargetFQDN]; ok {
		return true, nil // egress Service
	}
	return false, nil // ingress Service
}

func (dnsRR *dnsRecordsReconciler) removeEPSFinalizer(ctx context.Context, eps *discoveryv1.EndpointSlice) error {
	idx := slices.Index(eps.Finalizers, dnsRecordsRecocilerFinalizer)
	if idx == -1 {
		return nil
	}
	eps.Finalizers = append(eps.Finalizers[:idx], eps.Finalizers[idx+1:]...)
	return dnsRR.Update(ctx, eps)
}

func (dnsRR *dnsRecordsReconciler) fqdnForDNSRecord(ctx context.Context, eps *discoveryv1.EndpointSlice, logger *zap.SugaredLogger) (string, error) {
	svcName, ok := eps.Labels[discoveryv1.LabelServiceName] // https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	if !ok {
		logger.Debugf("EndpointSlice is not managed by a Service")
		return "", nil
	}
	maybeHeadlessSvc := new(corev1.Service)
	if err := dnsRR.Get(ctx, types.NamespacedName{Namespace: dnsRR.tsNamespace, Name: svcName}, maybeHeadlessSvc); err != nil {
		return "", fmt.Errorf("error retrieving owning Service for EndpointSlice: %w", err)
	}
	parentName := parentFromObjectLabels(maybeHeadlessSvc)
	if isManagedByType(maybeHeadlessSvc, "ingress") {
		ing := new(networkingv1.Ingress)
		if err := dnsRR.Get(ctx, parentName, ing); err != nil {
			return "", err
		}
		if len(ing.Status.LoadBalancer.Ingress) == 0 {
			return "", nil
		}
		return ing.Status.LoadBalancer.Ingress[0].Hostname, nil
	}
	if isManagedByType(maybeHeadlessSvc, "svc") {
		svc := new(corev1.Service)
		if err := dnsRR.Get(ctx, parentName, svc); err != nil {
			return "", err
		}
		return dnsRR.fqdnForDNSRecordFromService(ctx, svc)
	}
	return "", nil
}

func (h *dnsRecordsReconciler) updateDNSConfig(ctx context.Context, update func(*operatorutils.TSHosts)) error {
	cm := &corev1.ConfigMap{}
	if err := h.Client.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: h.tsNamespace}, cm); err != nil {
		return fmt.Errorf("error retrieving nameserver config: %w", err)
	}
	dnsCfg := operatorutils.TSHosts{Hosts: make(map[string][]string)}
	if cm.Data != nil && cm.Data[dnsConfigKey] != "" {
		if err := json.Unmarshal([]byte(cm.Data[dnsConfigKey]), &dnsCfg); err != nil {
			return err
		}
	}
	update(&dnsCfg)
	configBytes, err := json.Marshal(dnsCfg)
	if err != nil {
		return fmt.Errorf("error marshalling DNS config: %w", err)
	}
	mak.Set(&cm.Data, dnsConfigKey, string(configBytes))
	return h.Update(ctx, cm)
}

func (dnsRR *dnsRecordsReconciler) fqdnForDNSRecordFromService(ctx context.Context, svc *corev1.Service) (string, error) {
	if tailnetIP := tailnetTargetAnnotation(svc); tailnetIP != "" {
		return dnsRR.tailnetFQDNForIP(ctx, tailnetIP)
	}
	if tailnetFQDN := svc.Annotations[AnnotationTailnetTargetFQDN]; tailnetFQDN != "" {
		return tailnetFQDN, nil
	}
	if hasLoadBalancerClass(svc, dnsRR.isDefaultLoadBalancer) {
		if len(svc.Status.LoadBalancer.Ingress) > 0 {
			return svc.Status.LoadBalancer.Ingress[0].Hostname, nil
		}
		return "", nil
	}
	if hasExposeAnnotation(svc) {
		return dnsRR.fqdnFromSecretData(ctx, svc)
	}
	return "", nil
}

func (h *dnsRecordsReconciler) tailnetFQDNForIP(ctx context.Context, ip string) (string, error) {
	whois, err := h.localAPIClient.WhoIs(ctx, ip)
	if err != nil {
		h.logger.Errorf("error determining Tailscale node: %v", err)
		return "", err
	}
	fqdn := whois.Node.Name
	fqdn = strings.TrimSuffix(fqdn, ".")
	return fqdn, nil
}

func (h *dnsRecordsReconciler) fqdnFromSecretData(ctx context.Context, svc *corev1.Service) (string, error) {
	childResourceLabels := map[string]string{
		LabelManaged:         "true",
		LabelParentName:      svc.Name,
		LabelParentNamespace: svc.Namespace,
		LabelParentType:      "svc",
	}
	secret, err := getSingleObject[corev1.Secret](ctx, h.Client, h.tsNamespace, childResourceLabels)
	if err != nil {
		return "", err
	}
	return string(secret.Data["device_fqdn"]), nil
}
