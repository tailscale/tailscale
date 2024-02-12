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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/client/tailscale/apitype"
	k8soperator "tailscale.com/k8s-operator"
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
// It reconciles a headless proxy Service.
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
	if !isManagedByType(headlessSvc, "svc") && !isManagedByType(headlessSvc, "ingress") {
		logger.Debugf("Service is not a headless Service for an ingress/egress proxy, do nothing")
		return reconcile.Result{}, nil
	}

	if !headlessSvc.DeletionTimestamp.IsZero() {
		logger.Debug("Service is being deleted, clean up resources")
		return reconcile.Result{}, dnsRR.maybeCleanup(ctx, headlessSvc, logger)
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
	if !k8soperator.DNSCfgIsReady(&dnsCfg) {
		logger.Info("DNSConfig is not ready yet, waiting...")
		return reconcile.Result{}, nil
	}

	return reconcile.Result{}, dnsRR.maybeProvision(ctx, headlessSvc, logger)
}

func (dnsRR *dnsRecordsReconciler) maybeProvision(ctx context.Context, headlessSvc *corev1.Service, logger *zap.SugaredLogger) error {
	if headlessSvc == nil {
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
	if !slices.Contains(headlessSvc.Finalizers, dnsRecordsRecocilerFinalizer) {
		headlessSvc.Finalizers = append(headlessSvc.Finalizers, dnsRecordsRecocilerFinalizer)
	}
	// Ensure that headless Service is annotated with the MagicDNS name to
	// make the records cleanup easier.
	oldFqdn := headlessSvc.Annotations[annotationTSMagicDNSName]
	if oldFqdn != "" && oldFqdn != fqdn { // this can happen if users change the value of tailnet FQDN to be exposed via cluster egress proxy
		logger.Debugf("MagicDNS name has changed, remvoving record for %s", oldFqdn)
		updateFunc := func(cfg *k8soperator.TSHosts) {
			delete(cfg.Hosts, oldFqdn)
		}
		if err = dnsRR.updateDNSConfig(ctx, updateFunc); err != nil {
			return fmt.Errorf("error removing record for %s: %w", oldFqdn, err)
		}
	}
	mak.Set(&headlessSvc.Annotations, annotationTSMagicDNSName, fqdn)
	// Ensure tailscale finalizer and MagicDNS name annotation has been applied.
	if !apiequality.Semantic.DeepEqual(oldHeadlessSvc, headlessSvc) {
		logger.Infof("provisioning DNS record for MagicDNS name: %s", fqdn) // this will be printed exactly once
		if err := dnsRR.Update(ctx, headlessSvc); err != nil {
			return fmt.Errorf("error updating proxy headless Service metadata: %w", err)
		}
	}

	// Get the Pod IP addresses for the proxy from the EndpointSlice for the
	// headless Service.
	labels := map[string]string{discoveryv1.LabelServiceName: headlessSvc.Name} // https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	eps, err := getSingleObject[discoveryv1.EndpointSlice](ctx, dnsRR.Client, dnsRR.tsNamespace, labels)
	if err != nil {
		return fmt.Errorf("error getting proxy EndpointSlice: %w", err)
	}
	if eps == nil {
		logger.Debugf("proxy EndpointSlice does not yet exist, waiting...")
		return nil
	}

	ips := make([]string, 0)
	for _, ep := range eps.Endpoints {
		ips = append(ips, ep.Addresses...)
	}
	if len(ips) == 0 {
		logger.Debugf("No endpoint addresses found")
		return nil // a new reconcile will be triggered once the EndpointSlice is updated with addresses
	}
	updateFunc := func(cfg *k8soperator.TSHosts) {
		mak.Set(&cfg.Hosts, fqdn, ips)
	}
	if err = dnsRR.updateDNSConfig(ctx, updateFunc); err != nil {
		return fmt.Errorf("error updating DNS records: %w", err)
	}
	return nil
}

func (h *dnsRecordsReconciler) maybeCleanup(ctx context.Context, headlessSvc *corev1.Service, logger *zap.SugaredLogger) error {
	ix := slices.Index(headlessSvc.Finalizers, dnsRecordsRecocilerFinalizer)
	if ix == -1 {
		logger.Debugf("no finalizer, nothing to do")
		return nil
	}
	cm := &corev1.ConfigMap{}
	err := h.Client.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: h.tsNamespace}, cm)
	if apierrors.IsNotFound(err) { // If the ConfigMap with the DNS config does not exist, just remove the finalizer
		logger.Debug("ConfigMap not found")
		return h.removeHeadlessSvcFinalizer(ctx, headlessSvc)
	}
	if err != nil {
		return fmt.Errorf("error retrieving ConfigMap: %w", err)
	}
	_, ok := cm.Data[dnsConfigKey]
	if !ok {
		logger.Debug("ConfigMap contains no records")
		return h.removeHeadlessSvcFinalizer(ctx, headlessSvc)
	}
	fqdn, ok := headlessSvc.GetAnnotations()[annotationTSMagicDNSName]
	if !ok || fqdn == "" {
		return h.removeHeadlessSvcFinalizer(ctx, headlessSvc)
	}
	logger.Infof("removing DNS record for MagicDNS name %s", fqdn)
	updateFunc := func(cfg *k8soperator.TSHosts) {
		delete(cfg.Hosts, fqdn)
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
		if err := dnsRR.Get(ctx, parentName, svc); err != nil {
			return "", err
		}
		return dnsRR.fqdnForDNSRecordFromService(ctx, svc, logger)
	}
	return "", nil
}

func (h *dnsRecordsReconciler) updateDNSConfig(ctx context.Context, update func(*k8soperator.TSHosts)) error {
	cm := &corev1.ConfigMap{}
	if err := h.Client.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: h.tsNamespace}, cm); err != nil {
		return fmt.Errorf("error retrieving nameserver config: %w", err)
	}
	dnsCfg := k8soperator.TSHosts{Hosts: make(map[string][]string)}
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

func (dnsRR *dnsRecordsReconciler) fqdnForDNSRecordFromService(ctx context.Context, svc *corev1.Service, logger *zap.SugaredLogger) (string, error) {
	if tailnetIP := tailnetTargetAnnotation(svc); tailnetIP != "" {
		return dnsRR.tailnetFQDNForIP(ctx, tailnetIP)
	}
	if tailnetFQDN := svc.Annotations[AnnotationTailnetTargetFQDN]; tailnetFQDN != "" {
		return tailnetFQDN, nil
	}
	if isTailscaleLoadBalancerService(svc, dnsRR.isDefaultLoadBalancer) {
		if len(svc.Status.LoadBalancer.Ingress) > 0 {
			return svc.Status.LoadBalancer.Ingress[0].Hostname, nil
		}
		return "", nil
	}
	if hasExposeAnnotation(svc) {
		return dnsRR.fqdnFromSecretData(ctx, svc, logger)
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

func (h *dnsRecordsReconciler) fqdnFromSecretData(ctx context.Context, svc *corev1.Service, logger *zap.SugaredLogger) (string, error) {
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
	if secret == nil || secret.Data == nil {
		logger.Debugf("proxy state Secret does not exist or does not contain device_fqdn data, waiting...")
		return "", nil
	}
	return string(secret.Data["device_fqdn"]), nil
}
