// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	serveConfigKey = "serve-config.json"
	VIPSvcOwnerRef = "tailscale.com/k8s-operator:owned-by:%s"
	// FinalizerNamePG is the finalizer used by the IngressPGReconciler
	FinalizerNamePG = "tailscale.com/ingress-pg-finalizer"

	indexIngressProxyGroup = ".metadata.annotations.ingress-proxy-group"
)

var gaugePGIngressResources = clientmetric.NewGauge(kubetypes.MetricIngressPGResourceCount)

// IngressPGReconciler is a controller that reconciles Tailscale Ingresses should be exposed on an ingress ProxyGroup
// (in HA mode).
type IngressPGReconciler struct {
	client.Client

	recorder    record.EventRecorder
	logger      *zap.SugaredLogger
	tsClient    tsClient
	tsnetServer tsnetServer
	tsNamespace string
	lc          localClient
	defaultTags []string

	mu sync.Mutex // protects following
	// managedIngresses is a set of all ingress resources that we're currently
	// managing. This is only used for metrics.
	managedIngresses set.Slice[types.UID]
}

// Reconcile reconciles Ingresses that should be exposed over Tailscale in HA mode (on a ProxyGroup). It looks at all
// Ingresses with tailscale.com/proxy-group annotation. For each such Ingress, it ensures that a VIPService named after
// the hostname of the Ingress exists and is up to date. It also ensures that the serve config for the ingress
// ProxyGroup is updated to route traffic for the VIPService to the Ingress's backend Services.
// When an Ingress is deleted or unexposed, the VIPService and the associated serve config are cleaned up.
// Ingress hostname change also results in the VIPService for the previous hostname being cleaned up and a new VIPService
// being created for the new hostname.
func (a *IngressPGReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := a.logger.With("Ingress", req.NamespacedName)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	ing := new(networkingv1.Ingress)
	err = a.Get(ctx, req.NamespacedName, ing)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("Ingress not found, assuming it was deleted")
		return res, nil
	} else if err != nil {
		return res, fmt.Errorf("failed to get Ingress: %w", err)
	}

	// hostname is the name of the VIPService that will be created for this Ingress as well as the first label in
	// the MagicDNS name of the Ingress.
	hostname := hostnameForIngress(ing)
	logger = logger.With("hostname", hostname)

	if !ing.DeletionTimestamp.IsZero() || !a.shouldExpose(ing) {
		return res, a.maybeCleanup(ctx, hostname, ing, logger)
	}

	if err := a.maybeProvision(ctx, hostname, ing, logger); err != nil {
		return res, fmt.Errorf("failed to provision: %w", err)
	}
	return res, nil
}

// maybeProvision ensures that the VIPService and serve config for the Ingress are created or updated.
func (a *IngressPGReconciler) maybeProvision(ctx context.Context, hostname string, ing *networkingv1.Ingress, logger *zap.SugaredLogger) error {
	if err := validateIngressClass(ctx, a.Client); err != nil {
		logger.Infof("error validating tailscale IngressClass: %v.", err)
		return nil
	}

	// Get and validate ProxyGroup readiness
	pgName := ing.Annotations[AnnotationProxyGroup]
	if pgName == "" {
		logger.Infof("[unexpected] no ProxyGroup annotation, skipping VIPService provisioning")
		return nil
	}
	pg := &tsapi.ProxyGroup{}
	if err := a.Get(ctx, client.ObjectKey{Name: pgName}, pg); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Infof("ProxyGroup %q does not exist", pgName)
			return nil
		}
		return fmt.Errorf("getting ProxyGroup %q: %w", pgName, err)
	}
	if !tsoperator.ProxyGroupIsReady(pg) {
		// TODO(irbekrm): we need to reconcile ProxyGroup Ingresses on ProxyGroup changes to not miss the status update
		// in this case.
		logger.Infof("ProxyGroup %q is not ready", pgName)
		return nil
	}

	// Validate Ingress configuration
	if err := a.validateIngress(ing, pg); err != nil {
		logger.Infof("invalid Ingress configuration: %v", err)
		a.recorder.Event(ing, corev1.EventTypeWarning, "InvalidIngressConfiguration", err.Error())
		return nil
	}

	if !IsHTTPSEnabledOnTailnet(a.tsnetServer) {
		a.recorder.Event(ing, corev1.EventTypeWarning, "HTTPSNotEnabled", "HTTPS is not enabled on the tailnet; ingress may not work")
	}

	logger = logger.With("proxy-group", pg)

	if !slices.Contains(ing.Finalizers, FinalizerNamePG) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("exposing Ingress over tailscale")
		ing.Finalizers = append(ing.Finalizers, FinalizerNamePG)
		if err := a.Update(ctx, ing); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
		a.mu.Lock()
		a.managedIngresses.Add(ing.UID)
		gaugePGIngressResources.Set(int64(a.managedIngresses.Len()))
		a.mu.Unlock()
	}

	// 1. Ensure that if Ingress' hostname has changed, any VIPService resources corresponding to the old hostname
	// are cleaned up.
	// In practice, this function will ensure that any VIPServices that are associated with the provided ProxyGroup
	// and no longer owned by an Ingress are cleaned up. This is fine- it is not expensive and ensures that in edge
	// cases (a single update changed both hostname and removed ProxyGroup annotation) the VIPService is more likely
	// to be (eventually) removed.
	if err := a.maybeCleanupProxyGroup(ctx, pgName, logger); err != nil {
		return fmt.Errorf("failed to cleanup VIPService resources for ProxyGroup: %w", err)
	}

	// 2. Ensure that there isn't a VIPService with the same hostname already created and not owned by this Ingress.
	// TODO(irbekrm): perhaps in future we could have record names being stored on VIPServices. I am not certain if
	// there might not be edge cases (custom domains, etc?) where attempting to determine the DNS name of the
	// VIPService in this way won't be incorrect.
	tcd, err := a.tailnetCertDomain(ctx)
	if err != nil {
		return fmt.Errorf("error determining DNS name base: %w", err)
	}
	dnsName := hostname + "." + tcd
	serviceName := tailcfg.ServiceName("svc:" + hostname)
	existingVIPSvc, err := a.tsClient.getVIPService(ctx, serviceName)
	// TODO(irbekrm): here and when creating the VIPService, verify if the error is not terminal (and therefore
	// should not be reconciled). For example, if the hostname is already a hostname of a Tailscale node, the GET
	// here will fail.
	if err != nil {
		errResp := &tailscale.ErrResponse{}
		if ok := errors.As(err, errResp); ok && errResp.Status != http.StatusNotFound {
			return fmt.Errorf("error getting VIPService %q: %w", hostname, err)
		}
	}
	if existingVIPSvc != nil && !isVIPServiceForIngress(existingVIPSvc, ing) {
		logger.Infof("VIPService %q for MagicDNS name %q  already exists, but is not owned by this Ingress. Please delete it manually and recreate this Ingress to proceed or create an Ingress for a different MagicDNS name", hostname, dnsName)
		a.recorder.Event(ing, corev1.EventTypeWarning, "ConflictingVIPServiceExists", fmt.Sprintf("VIPService %q for MagicDNS name %q already exists, but is not owned by this Ingress. Please delete it manually to proceed or create an Ingress for a different MagicDNS name", hostname, dnsName))
		return nil
	}

	// 3. Ensure that the serve config for the ProxyGroup contains the VIPService
	cm, cfg, err := a.proxyGroupServeConfig(ctx, pgName)
	if err != nil {
		return fmt.Errorf("error getting ingress serve config: %w", err)
	}
	if cm == nil {
		logger.Infof("no ingress serve config ConfigMap found, unable to update serve config. Ensure that ProxyGroup is healthy.")
		return nil
	}
	ep := ipn.HostPort(fmt.Sprintf("%s:443", dnsName))
	handlers, err := handlersForIngress(ctx, ing, a.Client, a.recorder, dnsName, logger)
	if err != nil {
		return fmt.Errorf("failed to get handlers for ingress: %w", err)
	}
	ingCfg := &ipn.ServiceConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			443: {
				HTTPS: true,
			},
		},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			ep: {
				Handlers: handlers,
			},
		},
	}
	var gotCfg *ipn.ServiceConfig
	if cfg != nil && cfg.Services != nil {
		gotCfg = cfg.Services[serviceName]
	}
	if !reflect.DeepEqual(gotCfg, ingCfg) {
		logger.Infof("Updating serve config")
		mak.Set(&cfg.Services, serviceName, ingCfg)
		cfgBytes, err := json.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("error marshaling serve config: %w", err)
		}
		mak.Set(&cm.BinaryData, serveConfigKey, cfgBytes)
		if err := a.Update(ctx, cm); err != nil {
			return fmt.Errorf("error updating serve config: %w", err)
		}
	}

	// 4. Ensure that the VIPService exists and is up to date.
	tags := a.defaultTags
	if tstr, ok := ing.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}

	vipSvc := &VIPService{
		Name:    serviceName,
		Tags:    tags,
		Ports:   []string{"443"}, // always 443 for Ingress
		Comment: fmt.Sprintf(VIPSvcOwnerRef, ing.UID),
	}
	if existingVIPSvc != nil {
		vipSvc.Addrs = existingVIPSvc.Addrs
	}
	if existingVIPSvc == nil || !reflect.DeepEqual(vipSvc.Tags, existingVIPSvc.Tags) {
		logger.Infof("Ensuring VIPService %q exists and is up to date", hostname)
		if err := a.tsClient.createOrUpdateVIPService(ctx, vipSvc); err != nil {
			logger.Infof("error creating VIPService: %v", err)
			return fmt.Errorf("error creating VIPService: %w", err)
		}
	}

	// 5. Update Ingress status
	oldStatus := ing.Status.DeepCopy()
	// TODO(irbekrm): once we have ingress ProxyGroup, we can determine if instances are ready to route traffic to the VIPService
	ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{
		{
			Hostname: dnsName,
			Ports: []networkingv1.IngressPortStatus{
				{
					Protocol: "TCP",
					Port:     443,
				},
			},
		},
	}
	if apiequality.Semantic.DeepEqual(oldStatus, ing.Status) {
		return nil
	}
	if err := a.Status().Update(ctx, ing); err != nil {
		return fmt.Errorf("failed to update Ingress status: %w", err)
	}
	return nil
}

// maybeCleanupProxyGroup ensures that if an Ingress hostname has changed, any VIPService resources created for the
// Ingress' ProxyGroup corresponding to the old hostname are cleaned up. A run of this function will ensure that any
// VIPServices that are associated with the provided ProxyGroup and no longer owned by an Ingress are cleaned up.
func (a *IngressPGReconciler) maybeCleanupProxyGroup(ctx context.Context, proxyGroupName string, logger *zap.SugaredLogger) error {
	// Get serve config for the ProxyGroup
	cm, cfg, err := a.proxyGroupServeConfig(ctx, proxyGroupName)
	if err != nil {
		return fmt.Errorf("getting serve config: %w", err)
	}
	if cfg == nil {
		return nil // ProxyGroup does not have any VIPServices
	}

	ingList := &networkingv1.IngressList{}
	if err := a.List(ctx, ingList); err != nil {
		return fmt.Errorf("listing Ingresses: %w", err)
	}
	serveConfigChanged := false
	// For each VIPService in serve config...
	for vipServiceName := range cfg.Services {
		// ...check if there is currently an Ingress with this hostname
		found := false
		for _, i := range ingList.Items {
			ingressHostname := hostnameForIngress(&i)
			if ingressHostname == vipServiceName.WithoutPrefix() {
				found = true
				break
			}
		}

		if !found {
			logger.Infof("VIPService %q is not owned by any Ingress, cleaning up", vipServiceName)
			svc, err := a.getVIPService(ctx, vipServiceName, logger)
			if err != nil {
				errResp := &tailscale.ErrResponse{}
				if errors.As(err, &errResp) && errResp.Status == http.StatusNotFound {
					delete(cfg.Services, vipServiceName)
					serveConfigChanged = true
					continue
				}
				return err
			}
			if isVIPServiceForAnyIngress(svc) {
				logger.Infof("cleaning up orphaned VIPService %q", vipServiceName)
				if err := a.tsClient.deleteVIPService(ctx, vipServiceName); err != nil {
					errResp := &tailscale.ErrResponse{}
					if !errors.As(err, &errResp) || errResp.Status != http.StatusNotFound {
						return fmt.Errorf("deleting VIPService %q: %w", vipServiceName, err)
					}
				}
			}
			delete(cfg.Services, vipServiceName)
			serveConfigChanged = true
		}
	}

	if serveConfigChanged {
		cfgBytes, err := json.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("marshaling serve config: %w", err)
		}
		mak.Set(&cm.BinaryData, serveConfigKey, cfgBytes)
		if err := a.Update(ctx, cm); err != nil {
			return fmt.Errorf("updating serve config: %w", err)
		}
	}
	return nil
}

// maybeCleanup ensures that any resources, such as a VIPService created for this Ingress, are cleaned up when the
// Ingress is being deleted or is unexposed.
func (a *IngressPGReconciler) maybeCleanup(ctx context.Context, hostname string, ing *networkingv1.Ingress, logger *zap.SugaredLogger) error {
	logger.Debugf("Ensuring any resources for Ingress are cleaned up")
	ix := slices.Index(ing.Finalizers, FinalizerNamePG)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		a.mu.Lock()
		defer a.mu.Unlock()
		a.managedIngresses.Remove(ing.UID)
		gaugePGIngressResources.Set(int64(a.managedIngresses.Len()))
		return nil
	}

	// 1. Check if there is a VIPService created for this Ingress.
	pg := ing.Annotations[AnnotationProxyGroup]
	cm, cfg, err := a.proxyGroupServeConfig(ctx, pg)
	if err != nil {
		return fmt.Errorf("error getting ProxyGroup serve config: %w", err)
	}
	serviceName := tailcfg.ServiceName("svc:" + hostname)
	// VIPService is always first added to serve config and only then created in the Tailscale API, so if it is not
	// found in the serve config, we can assume that there is no VIPService. TODO(irbekrm): once we have ingress
	// ProxyGroup, we will probably add currently exposed VIPServices to its status. At that point, we can use the
	// status rather than checking the serve config each time.
	if cfg == nil || cfg.Services == nil || cfg.Services[serviceName] == nil {
		return nil
	}
	logger.Infof("Ensuring that VIPService %q configuration is cleaned up", hostname)

	// 2. Delete the VIPService.
	if err := a.deleteVIPServiceIfExists(ctx, serviceName, ing, logger); err != nil {
		return fmt.Errorf("error deleting VIPService: %w", err)
	}

	// 3. Remove the VIPService from the serve config for the ProxyGroup.
	logger.Infof("Removing VIPService %q from serve config for ProxyGroup %q", hostname, pg)
	delete(cfg.Services, serviceName)
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("error marshaling serve config: %w", err)
	}
	mak.Set(&cm.BinaryData, serveConfigKey, cfgBytes)
	if err := a.Update(ctx, cm); err != nil {
		return fmt.Errorf("error updating ConfigMap %q: %w", cm.Name, err)
	}

	if err := a.deleteFinalizer(ctx, ing, logger); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.managedIngresses.Remove(ing.UID)
	gaugePGIngressResources.Set(int64(a.managedIngresses.Len()))
	return nil
}

func (a *IngressPGReconciler) deleteFinalizer(ctx context.Context, ing *networkingv1.Ingress, logger *zap.SugaredLogger) error {
	found := false
	ing.Finalizers = slices.DeleteFunc(ing.Finalizers, func(f string) bool {
		found = true
		return f == FinalizerNamePG
	})
	if !found {
		return nil
	}
	logger.Debug("ensure %q finalizer is removed", FinalizerNamePG)

	if err := a.Update(ctx, ing); err != nil {
		return fmt.Errorf("failed to remove finalizer %q: %w", FinalizerNamePG, err)
	}
	return nil
}

func pgIngressCMName(pg string) string {
	return fmt.Sprintf("%s-ingress-config", pg)
}

func (a *IngressPGReconciler) proxyGroupServeConfig(ctx context.Context, pg string) (cm *corev1.ConfigMap, cfg *ipn.ServeConfig, err error) {
	name := pgIngressCMName(pg)
	cm = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: a.tsNamespace,
		},
	}
	if err := a.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil && !apierrors.IsNotFound(err) {
		return nil, nil, fmt.Errorf("error retrieving ingress serve config ConfigMap %s: %v", name, err)
	}
	if apierrors.IsNotFound(err) {
		return nil, nil, nil
	}
	cfg = &ipn.ServeConfig{}
	if len(cm.BinaryData[serveConfigKey]) != 0 {
		if err := json.Unmarshal(cm.BinaryData[serveConfigKey], cfg); err != nil {
			return nil, nil, fmt.Errorf("error unmarshaling ingress serve config %v: %w", cm.BinaryData[serveConfigKey], err)
		}
	}
	return cm, cfg, nil
}

type localClient interface {
	StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error)
}

// tailnetCertDomain returns the base domain (TCD) of the current tailnet.
func (a *IngressPGReconciler) tailnetCertDomain(ctx context.Context) (string, error) {
	st, err := a.lc.StatusWithoutPeers(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting tailscale status: %w", err)
	}
	return st.CurrentTailnet.MagicDNSSuffix, nil
}

// shouldExpose returns true if the Ingress should be exposed over Tailscale in HA mode (on a ProxyGroup)
func (a *IngressPGReconciler) shouldExpose(ing *networkingv1.Ingress) bool {
	isTSIngress := ing != nil &&
		ing.Spec.IngressClassName != nil &&
		*ing.Spec.IngressClassName == tailscaleIngressClassName
	pgAnnot := ing.Annotations[AnnotationProxyGroup]
	return isTSIngress && pgAnnot != ""
}

func (a *IngressPGReconciler) getVIPService(ctx context.Context, name tailcfg.ServiceName, logger *zap.SugaredLogger) (*VIPService, error) {
	svc, err := a.tsClient.getVIPService(ctx, name)
	if err != nil {
		errResp := &tailscale.ErrResponse{}
		if ok := errors.As(err, errResp); ok && errResp.Status != http.StatusNotFound {
			logger.Infof("error getting VIPService %q: %v", name, err)
			return nil, fmt.Errorf("error getting VIPService %q: %w", name, err)
		}
	}
	return svc, nil
}

func isVIPServiceForIngress(svc *VIPService, ing *networkingv1.Ingress) bool {
	if svc == nil || ing == nil {
		return false
	}
	return strings.EqualFold(svc.Comment, fmt.Sprintf(VIPSvcOwnerRef, ing.UID))
}

func isVIPServiceForAnyIngress(svc *VIPService) bool {
	if svc == nil {
		return false
	}
	return strings.HasPrefix(svc.Comment, "tailscale.com/k8s-operator:owned-by:")
}

// validateIngress validates that the Ingress is properly configured.
// Currently validates:
// - Any tags provided via tailscale.com/tags annotation are valid Tailscale ACL tags
// - The derived hostname is a valid DNS label
// - The referenced ProxyGroup exists and is of type 'ingress'
// - Ingress' TLS block is invalid
func (a *IngressPGReconciler) validateIngress(ing *networkingv1.Ingress, pg *tsapi.ProxyGroup) error {
	var errs []error

	// Validate tags if present
	if tstr, ok := ing.Annotations[AnnotationTags]; ok {
		tags := strings.Split(tstr, ",")
		for _, tag := range tags {
			tag = strings.TrimSpace(tag)
			if err := tailcfg.CheckTag(tag); err != nil {
				errs = append(errs, fmt.Errorf("tailscale.com/tags annotation contains invalid tag %q: %w", tag, err))
			}
		}
	}

	// Validate TLS configuration
	if ing.Spec.TLS != nil && len(ing.Spec.TLS) > 0 && (len(ing.Spec.TLS) > 1 || len(ing.Spec.TLS[0].Hosts) > 1) {
		errs = append(errs, fmt.Errorf("Ingress contains invalid TLS block %v: only a single TLS entry with a single host is allowed", ing.Spec.TLS))
	}

	// Validate that the hostname will be a valid DNS label
	hostname := hostnameForIngress(ing)
	if err := dnsname.ValidLabel(hostname); err != nil {
		errs = append(errs, fmt.Errorf("invalid hostname %q: %w. Ensure that the hostname is a valid DNS label", hostname, err))
	}

	// Validate ProxyGroup type
	if pg.Spec.Type != tsapi.ProxyGroupTypeIngress {
		errs = append(errs, fmt.Errorf("ProxyGroup %q is of type %q but must be of type %q",
			pg.Name, pg.Spec.Type, tsapi.ProxyGroupTypeIngress))
	}

	// Validate ProxyGroup readiness
	if !tsoperator.ProxyGroupIsReady(pg) {
		errs = append(errs, fmt.Errorf("ProxyGroup %q is not ready", pg.Name))
	}

	return errors.Join(errs...)
}

// deleteVIPServiceIfExists attempts to delete the VIPService if it exists and is owned by the given Ingress.
func (a *IngressPGReconciler) deleteVIPServiceIfExists(ctx context.Context, name tailcfg.ServiceName, ing *networkingv1.Ingress, logger *zap.SugaredLogger) error {
	svc, err := a.getVIPService(ctx, name, logger)
	if err != nil {
		return fmt.Errorf("error getting VIPService: %w", err)
	}

	// isVIPServiceForIngress handles nil svc, so we don't need to check it here
	if !isVIPServiceForIngress(svc, ing) {
		return nil
	}

	logger.Infof("Deleting VIPService %q", name)
	if err = a.tsClient.deleteVIPService(ctx, name); err != nil {
		return fmt.Errorf("error deleting VIPService: %w", err)
	}
	return nil
}
