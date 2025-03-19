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
	"time"

	"math/rand/v2"

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
	"tailscale.com/internal/client/tailscale"
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
	// annotationHTTPEndpoint can be used to configure the Ingress to expose an HTTP endpoint to tailnet (as
	// well as the default HTTPS endpoint).
	annotationHTTPEndpoint = "tailscale.com/http-endpoint"
)

var gaugePGIngressResources = clientmetric.NewGauge(kubetypes.MetricIngressPGResourceCount)

// HAIngressReconciler is a controller that reconciles Tailscale Ingresses
// should be exposed on an ingress ProxyGroup (in HA mode).
type HAIngressReconciler struct {
	client.Client

	recorder    record.EventRecorder
	logger      *zap.SugaredLogger
	tsClient    tsClient
	tsnetServer tsnetServer
	tsNamespace string
	lc          localClient
	defaultTags []string
	operatorID  string // stableID of the operator's Tailscale device

	mu sync.Mutex // protects following
	// managedIngresses is a set of all ingress resources that we're currently
	// managing. This is only used for metrics.
	managedIngresses set.Slice[types.UID]
}

// Reconcile reconciles Ingresses that should be exposed over Tailscale in HA
// mode (on a ProxyGroup). It looks at all Ingresses with
// tailscale.com/proxy-group annotation. For each such Ingress, it ensures that
// a VIPService named after the hostname of the Ingress exists and is up to
// date. It also ensures that the serve config for the ingress ProxyGroup is
// updated to route traffic for the VIPService to the Ingress's backend
// Services.  Ingress hostname change also results in the VIPService for the
// previous hostname being cleaned up and a new VIPService being created for the
// new hostname.
// HA Ingresses support multi-cluster Ingress setup.
// Each VIPService contains a list of owner references that uniquely identify
// the Ingress resource and the operator.  When an Ingress that acts as a
// backend is being deleted, the corresponding VIPService is only deleted if the
// only owner reference that it contains is for this Ingress. If other owner
// references are found, then cleanup operation only removes this Ingress' owner
// reference.
func (r *HAIngressReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := r.logger.With("Ingress", req.NamespacedName)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	ing := new(networkingv1.Ingress)
	err = r.Get(ctx, req.NamespacedName, ing)
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

	// needsRequeue is set to true if the underlying VIPService has changed as a result of this reconcile. If that
	// is the case, we reconcile the Ingress one more time to ensure that concurrent updates to the VIPService in a
	// multi-cluster Ingress setup have not resulted in another actor overwriting our VIPService update.
	needsRequeue := false
	if !ing.DeletionTimestamp.IsZero() || !r.shouldExpose(ing) {
		needsRequeue, err = r.maybeCleanup(ctx, hostname, ing, logger)
	} else {
		needsRequeue, err = r.maybeProvision(ctx, hostname, ing, logger)
	}
	if err != nil {
		return res, err
	}
	if needsRequeue {
		res = reconcile.Result{RequeueAfter: requeueInterval()}
	}
	return res, nil
}

// maybeProvision ensures that a VIPService for this Ingress exists and is up to date and that the serve config for the
// corresponding ProxyGroup contains the Ingress backend's definition.
// If a VIPService does not exist, it will be created.
// If a VIPService exists, but only with owner references from other operator instances, an owner reference for this
// operator instance is added.
// If a VIPService exists, but does not have an owner reference from any operator, we error
// out assuming that this is an owner reference created by an unknown actor.
// Returns true if the operation resulted in a VIPService update.
func (r *HAIngressReconciler) maybeProvision(ctx context.Context, hostname string, ing *networkingv1.Ingress, logger *zap.SugaredLogger) (svcsChanged bool, err error) {
	if err := validateIngressClass(ctx, r.Client); err != nil {
		logger.Infof("error validating tailscale IngressClass: %v.", err)
		return false, nil
	}
	// Get and validate ProxyGroup readiness
	pgName := ing.Annotations[AnnotationProxyGroup]
	if pgName == "" {
		logger.Infof("[unexpected] no ProxyGroup annotation, skipping VIPService provisioning")
		return false, nil
	}
	logger = logger.With("ProxyGroup", pgName)

	pg := &tsapi.ProxyGroup{}
	if err := r.Get(ctx, client.ObjectKey{Name: pgName}, pg); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Infof("ProxyGroup does not exist")
			return false, nil
		}
		return false, fmt.Errorf("getting ProxyGroup %q: %w", pgName, err)
	}
	if !tsoperator.ProxyGroupIsReady(pg) {
		logger.Infof("ProxyGroup is not (yet) ready")
		return false, nil
	}

	// Validate Ingress configuration
	if err := r.validateIngress(ctx, ing, pg); err != nil {
		logger.Infof("invalid Ingress configuration: %v", err)
		r.recorder.Event(ing, corev1.EventTypeWarning, "InvalidIngressConfiguration", err.Error())
		return false, nil
	}

	if !IsHTTPSEnabledOnTailnet(r.tsnetServer) {
		r.recorder.Event(ing, corev1.EventTypeWarning, "HTTPSNotEnabled", "HTTPS is not enabled on the tailnet; ingress may not work")
	}

	if !slices.Contains(ing.Finalizers, FinalizerNamePG) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("exposing Ingress over tailscale")
		ing.Finalizers = append(ing.Finalizers, FinalizerNamePG)
		if err := r.Update(ctx, ing); err != nil {
			return false, fmt.Errorf("failed to add finalizer: %w", err)
		}
		r.mu.Lock()
		r.managedIngresses.Add(ing.UID)
		gaugePGIngressResources.Set(int64(r.managedIngresses.Len()))
		r.mu.Unlock()
	}

	// 1. Ensure that if Ingress' hostname has changed, any VIPService
	// resources corresponding to the old hostname are cleaned up.
	// In practice, this function will ensure that any VIPServices that are
	// associated with the provided ProxyGroup and no longer owned by an
	// Ingress are cleaned up. This is fine- it is not expensive and ensures
	// that in edge cases (a single update changed both hostname and removed
	// ProxyGroup annotation) the VIPService is more likely to be
	// (eventually) removed.
	svcsChanged, err = r.maybeCleanupProxyGroup(ctx, pgName, logger)
	if err != nil {
		return false, fmt.Errorf("failed to cleanup VIPService resources for ProxyGroup: %w", err)
	}

	// 2. Ensure that there isn't a VIPService with the same hostname
	// already created and not owned by this Ingress.
	// TODO(irbekrm): perhaps in future we could have record names being
	// stored on VIPServices. I am not certain if there might not be edge
	// cases (custom domains, etc?) where attempting to determine the DNS
	// name of the VIPService in this way won't be incorrect.
	tcd, err := r.tailnetCertDomain(ctx)
	if err != nil {
		return false, fmt.Errorf("error determining DNS name base: %w", err)
	}
	dnsName := hostname + "." + tcd
	serviceName := tailcfg.ServiceName("svc:" + hostname)
	existingVIPSvc, err := r.tsClient.GetVIPService(ctx, serviceName)
	// TODO(irbekrm): here and when creating the VIPService, verify if the
	// error is not terminal (and therefore should not be reconciled). For
	// example, if the hostname is already a hostname of a Tailscale node,
	// the GET here will fail.
	if err != nil {
		errResp := &tailscale.ErrResponse{}
		if ok := errors.As(err, errResp); ok && errResp.Status != http.StatusNotFound {
			return false, fmt.Errorf("error getting VIPService %q: %w", hostname, err)
		}
	}
	// Generate the VIPService comment for new or existing VIPService. This
	// checks and ensures that VIPService's owner references are updated for
	// this Ingress and errors if that is not possible (i.e. because it
	// appears that the VIPService has been created by a non-operator
	// actor).
	svcComment, err := r.ownerRefsComment(existingVIPSvc)
	if err != nil {
		const instr = "To proceed, you can either manually delete the existing VIPService or choose a different MagicDNS name at `.spec.tls.hosts[0] in the Ingress definition"
		msg := fmt.Sprintf("error ensuring ownership of VIPService %s: %v. %s", hostname, err, instr)
		logger.Warn(msg)
		r.recorder.Event(ing, corev1.EventTypeWarning, "InvalidVIPService", msg)
		return false, nil
	}

	// 3. Ensure that the serve config for the ProxyGroup contains the VIPService.
	cm, cfg, err := r.proxyGroupServeConfig(ctx, pgName)
	if err != nil {
		return false, fmt.Errorf("error getting Ingress serve config: %w", err)
	}
	if cm == nil {
		logger.Infof("no Ingress serve config ConfigMap found, unable to update serve config. Ensure that ProxyGroup is healthy.")
		return svcsChanged, nil
	}
	ep := ipn.HostPort(fmt.Sprintf("%s:443", dnsName))
	handlers, err := handlersForIngress(ctx, ing, r.Client, r.recorder, dnsName, logger)
	if err != nil {
		return false, fmt.Errorf("failed to get handlers for Ingress: %w", err)
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

	// Add HTTP endpoint if configured.
	if isHTTPEndpointEnabled(ing) {
		logger.Infof("exposing Ingress over HTTP")
		epHTTP := ipn.HostPort(fmt.Sprintf("%s:80", dnsName))
		ingCfg.TCP[80] = &ipn.TCPPortHandler{
			HTTP: true,
		}
		ingCfg.Web[epHTTP] = &ipn.WebServerConfig{
			Handlers: handlers,
		}
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
			return false, fmt.Errorf("error marshaling serve config: %w", err)
		}
		mak.Set(&cm.BinaryData, serveConfigKey, cfgBytes)
		if err := r.Update(ctx, cm); err != nil {
			return false, fmt.Errorf("error updating serve config: %w", err)
		}
	}

	// 4. Ensure that the VIPService exists and is up to date.
	tags := r.defaultTags
	if tstr, ok := ing.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}

	vipPorts := []string{"443"} // always 443 for Ingress
	if isHTTPEndpointEnabled(ing) {
		vipPorts = append(vipPorts, "80")
	}

	vipSvc := &tailscale.VIPService{
		Name:    serviceName,
		Tags:    tags,
		Ports:   vipPorts,
		Comment: svcComment,
	}
	if existingVIPSvc != nil {
		vipSvc.Addrs = existingVIPSvc.Addrs
	}
	// TODO(irbekrm): right now if two Ingress resources attempt to apply different VIPService configs (different
	// tags, or HTTP endpoint settings) we can end up reconciling those in a loop. We should detect when an Ingress
	// with the same generation number has been reconciled ~more than N times and stop attempting to apply updates.
	if existingVIPSvc == nil ||
		!reflect.DeepEqual(vipSvc.Tags, existingVIPSvc.Tags) ||
		!reflect.DeepEqual(vipSvc.Ports, existingVIPSvc.Ports) ||
		!strings.EqualFold(vipSvc.Comment, existingVIPSvc.Comment) {
		logger.Infof("Ensuring VIPService exists and is up to date")
		if err := r.tsClient.CreateOrUpdateVIPService(ctx, vipSvc); err != nil {
			return false, fmt.Errorf("error creating VIPService: %w", err)
		}
	}

	// 5. Update tailscaled's AdvertiseServices config, which should add the VIPService
	// IPs to the ProxyGroup Pods' AllowedIPs in the next netmap update if approved.
	if err = r.maybeUpdateAdvertiseServicesConfig(ctx, pg.Name, serviceName, true, logger); err != nil {
		return false, fmt.Errorf("failed to update tailscaled config: %w", err)
	}

	// 6. Update Ingress status if ProxyGroup Pods are ready.
	count, err := r.numberPodsAdvertising(ctx, pg.Name, serviceName)
	if err != nil {
		return false, fmt.Errorf("failed to check if any Pods are configured: %w", err)
	}

	oldStatus := ing.Status.DeepCopy()

	switch count {
	case 0:
		ing.Status.LoadBalancer.Ingress = nil
	default:
		ports := []networkingv1.IngressPortStatus{
			{
				Protocol: "TCP",
				Port:     443,
			},
		}
		if isHTTPEndpointEnabled(ing) {
			ports = append(ports, networkingv1.IngressPortStatus{
				Protocol: "TCP",
				Port:     80,
			})
		}
		ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{
			{
				Hostname: dnsName,
				Ports:    ports,
			},
		}
	}
	if apiequality.Semantic.DeepEqual(oldStatus, &ing.Status) {
		return svcsChanged, nil
	}

	const prefix = "Updating Ingress status"
	if count == 0 {
		logger.Infof("%s. No Pods are advertising VIPService yet", prefix)
	} else {
		logger.Infof("%s. %d Pod(s) advertising VIPService", prefix, count)
	}

	if err := r.Status().Update(ctx, ing); err != nil {
		return false, fmt.Errorf("failed to update Ingress status: %w", err)
	}
	return svcsChanged, nil
}

// VIPServices that are associated with the provided ProxyGroup and no longer managed this operator's instance are deleted, if not owned by other operator instances, else the owner reference is cleaned up.
// Returns true if the operation resulted in existing VIPService updates (owner reference removal).
func (r *HAIngressReconciler) maybeCleanupProxyGroup(ctx context.Context, proxyGroupName string, logger *zap.SugaredLogger) (svcsChanged bool, err error) {
	// Get serve config for the ProxyGroup
	cm, cfg, err := r.proxyGroupServeConfig(ctx, proxyGroupName)
	if err != nil {
		return false, fmt.Errorf("getting serve config: %w", err)
	}
	if cfg == nil {
		return false, nil // ProxyGroup does not have any VIPServices
	}

	ingList := &networkingv1.IngressList{}
	if err := r.List(ctx, ingList); err != nil {
		return false, fmt.Errorf("listing Ingresses: %w", err)
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

			// Delete the VIPService from control if necessary.
			svcsChanged, err = r.cleanupVIPService(ctx, vipServiceName, logger)
			if err != nil {
				return false, fmt.Errorf("deleting VIPService %q: %w", vipServiceName, err)
			}

			// Make sure the VIPService is not advertised in tailscaled or serve config.
			if err = r.maybeUpdateAdvertiseServicesConfig(ctx, proxyGroupName, vipServiceName, false, logger); err != nil {
				return false, fmt.Errorf("failed to update tailscaled config services: %w", err)
			}
			delete(cfg.Services, vipServiceName)
			serveConfigChanged = true
		}
	}

	if serveConfigChanged {
		cfgBytes, err := json.Marshal(cfg)
		if err != nil {
			return false, fmt.Errorf("marshaling serve config: %w", err)
		}
		mak.Set(&cm.BinaryData, serveConfigKey, cfgBytes)
		if err := r.Update(ctx, cm); err != nil {
			return false, fmt.Errorf("updating serve config: %w", err)
		}
	}
	return svcsChanged, nil
}

// maybeCleanup ensures that any resources, such as a VIPService created for this Ingress, are cleaned up when the
// Ingress is being deleted or is unexposed. The cleanup is safe for a multi-cluster setup- the VIPService is only
// deleted if it does not contain any other owner references. If it does the cleanup only removes the owner reference
// corresponding to this Ingress.
func (r *HAIngressReconciler) maybeCleanup(ctx context.Context, hostname string, ing *networkingv1.Ingress, logger *zap.SugaredLogger) (svcChanged bool, err error) {
	logger.Debugf("Ensuring any resources for Ingress are cleaned up")
	ix := slices.Index(ing.Finalizers, FinalizerNamePG)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		return false, nil
	}
	logger.Infof("Ensuring that VIPService %q configuration is cleaned up", hostname)

	// Ensure that if cleanup succeeded Ingress finalizers are removed.
	defer func() {
		if err != nil {
			return
		}
		if e := r.deleteFinalizer(ctx, ing, logger); err != nil {
			err = errors.Join(err, e)
		}
	}()

	// 1. Check if there is a VIPService associated with this Ingress.
	pg := ing.Annotations[AnnotationProxyGroup]
	cm, cfg, err := r.proxyGroupServeConfig(ctx, pg)
	if err != nil {
		return false, fmt.Errorf("error getting ProxyGroup serve config: %w", err)
	}
	serviceName := tailcfg.ServiceName("svc:" + hostname)

	// VIPService is always first added to serve config and only then created in the Tailscale API, so if it is not
	// found in the serve config, we can assume that there is no VIPService. (If the serve config does not exist at
	// all, it is possible that the ProxyGroup has been deleted before cleaning up the Ingress, so carry on with
	// cleanup).
	if cfg != nil && cfg.Services != nil && cfg.Services[serviceName] == nil {
		return false, nil
	}

	// 2. Clean up the VIPService resources.
	svcChanged, err = r.cleanupVIPService(ctx, serviceName, logger)
	if err != nil {
		return false, fmt.Errorf("error deleting VIPService: %w", err)
	}
	if cfg == nil || cfg.Services == nil { // user probably deleted the ProxyGroup
		return svcChanged, nil
	}

	// 3. Unadvertise the VIPService in tailscaled config.
	if err = r.maybeUpdateAdvertiseServicesConfig(ctx, pg, serviceName, false, logger); err != nil {
		return false, fmt.Errorf("failed to update tailscaled config services: %w", err)
	}

	// 4. Remove the VIPService from the serve config for the ProxyGroup.
	logger.Infof("Removing VIPService %q from serve config for ProxyGroup %q", hostname, pg)
	delete(cfg.Services, serviceName)
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return false, fmt.Errorf("error marshaling serve config: %w", err)
	}
	mak.Set(&cm.BinaryData, serveConfigKey, cfgBytes)
	return svcChanged, r.Update(ctx, cm)
}

func (r *HAIngressReconciler) deleteFinalizer(ctx context.Context, ing *networkingv1.Ingress, logger *zap.SugaredLogger) error {
	found := false
	ing.Finalizers = slices.DeleteFunc(ing.Finalizers, func(f string) bool {
		found = true
		return f == FinalizerNamePG
	})
	if !found {
		return nil
	}
	logger.Debug("ensure %q finalizer is removed", FinalizerNamePG)

	if err := r.Update(ctx, ing); err != nil {
		return fmt.Errorf("failed to remove finalizer %q: %w", FinalizerNamePG, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.managedIngresses.Remove(ing.UID)
	gaugePGIngressResources.Set(int64(r.managedIngresses.Len()))
	return nil
}

func pgIngressCMName(pg string) string {
	return fmt.Sprintf("%s-ingress-config", pg)
}

func (r *HAIngressReconciler) proxyGroupServeConfig(ctx context.Context, pg string) (cm *corev1.ConfigMap, cfg *ipn.ServeConfig, err error) {
	name := pgIngressCMName(pg)
	cm = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: r.tsNamespace,
		},
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil && !apierrors.IsNotFound(err) {
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
func (r *HAIngressReconciler) tailnetCertDomain(ctx context.Context) (string, error) {
	st, err := r.lc.StatusWithoutPeers(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting tailscale status: %w", err)
	}
	return st.CurrentTailnet.MagicDNSSuffix, nil
}

// shouldExpose returns true if the Ingress should be exposed over Tailscale in HA mode (on a ProxyGroup).
func (r *HAIngressReconciler) shouldExpose(ing *networkingv1.Ingress) bool {
	isTSIngress := ing != nil &&
		ing.Spec.IngressClassName != nil &&
		*ing.Spec.IngressClassName == tailscaleIngressClassName
	pgAnnot := ing.Annotations[AnnotationProxyGroup]
	return isTSIngress && pgAnnot != ""
}

// validateIngress validates that the Ingress is properly configured.
// Currently validates:
// - Any tags provided via tailscale.com/tags annotation are valid Tailscale ACL tags
// - The derived hostname is a valid DNS label
// - The referenced ProxyGroup exists and is of type 'ingress'
// - Ingress' TLS block is invalid
func (r *HAIngressReconciler) validateIngress(ctx context.Context, ing *networkingv1.Ingress, pg *tsapi.ProxyGroup) error {
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

	// It is invalid to have multiple Ingress resources for the same VIPService in one cluster.
	ingList := &networkingv1.IngressList{}
	if err := r.List(ctx, ingList); err != nil {
		errs = append(errs, fmt.Errorf("[unexpected] error listing Ingresses: %w", err))
		return errors.Join(errs...)
	}
	for _, i := range ingList.Items {
		if r.shouldExpose(&i) && hostnameForIngress(&i) == hostname && i.Name != ing.Name {
			errs = append(errs, fmt.Errorf("found duplicate Ingress %q for hostname %q - multiple Ingresses for the same hostname in the same cluster are not allowed", i.Name, hostname))
		}
	}
	return errors.Join(errs...)
}

// cleanupVIPService deletes any VIPService by the provided name if it is not owned by operator instances other than this one.
// If a VIPService is found, but contains other owner references, only removes this operator's owner reference.
// If a VIPService by the given name is not found or does not contain this operator's owner reference, do nothing.
// It returns true if an existing VIPService was updated to remove owner reference, as well as any error that occurred.
func (r *HAIngressReconciler) cleanupVIPService(ctx context.Context, name tailcfg.ServiceName, logger *zap.SugaredLogger) (updated bool, _ error) {
	svc, err := r.tsClient.GetVIPService(ctx, name)
	if err != nil {
		errResp := &tailscale.ErrResponse{}
		if ok := errors.As(err, errResp); ok && errResp.Status == http.StatusNotFound {
			return false, nil
		}

		return false, fmt.Errorf("error getting VIPService: %w", err)
	}
	if svc == nil {
		return false, nil
	}
	c, err := parseComment(svc)
	if err != nil {
		return false, fmt.Errorf("error parsing VIPService comment")
	}
	if c == nil || len(c.OwnerRefs) == 0 {
		return false, nil
	}
	// Comparing with the operatorID only means that we will not be able to
	// clean up VIPServices in cases where the operator was deleted from the
	// cluster before deleting the Ingress. Perhaps the comparison could be
	// 'if or.OperatorID === r.operatorID || or.ingressUID == r.ingressUID'.
	ix := slices.IndexFunc(c.OwnerRefs, func(or OwnerRef) bool {
		return or.OperatorID == r.operatorID
	})
	if ix == -1 {
		return false, nil
	}
	if len(c.OwnerRefs) == 1 {
		logger.Infof("Deleting VIPService %q", name)
		return false, r.tsClient.DeleteVIPService(ctx, name)
	}
	c.OwnerRefs = slices.Delete(c.OwnerRefs, ix, ix+1)
	logger.Infof("Deleting VIPService %q", name)
	json, err := json.Marshal(c)
	if err != nil {
		return false, fmt.Errorf("error marshalling updated VIPService owner reference: %w", err)
	}
	svc.Comment = string(json)
	return true, r.tsClient.CreateOrUpdateVIPService(ctx, svc)
}

// isHTTPEndpointEnabled returns true if the Ingress has been configured to expose an HTTP endpoint to tailnet.
func isHTTPEndpointEnabled(ing *networkingv1.Ingress) bool {
	if ing == nil {
		return false
	}
	return ing.Annotations[annotationHTTPEndpoint] == "enabled"
}

func (a *HAIngressReconciler) maybeUpdateAdvertiseServicesConfig(ctx context.Context, pgName string, serviceName tailcfg.ServiceName, shouldBeAdvertised bool, logger *zap.SugaredLogger) (err error) {
	logger.Debugf("Updating ProxyGroup tailscaled configs to advertise service %q: %v", serviceName, shouldBeAdvertised)

	// Get all config Secrets for this ProxyGroup.
	secrets := &corev1.SecretList{}
	if err := a.List(ctx, secrets, client.InNamespace(a.tsNamespace), client.MatchingLabels(pgSecretLabels(pgName, "config"))); err != nil {
		return fmt.Errorf("failed to list config Secrets: %w", err)
	}

	for _, secret := range secrets.Items {
		var updated bool
		for fileName, confB := range secret.Data {
			var conf ipn.ConfigVAlpha
			if err := json.Unmarshal(confB, &conf); err != nil {
				return fmt.Errorf("error unmarshalling ProxyGroup config: %w", err)
			}

			// Update the services to advertise if required.
			idx := slices.Index(conf.AdvertiseServices, serviceName.String())
			isAdvertised := idx >= 0
			switch {
			case isAdvertised == shouldBeAdvertised:
				// Already up to date.
				continue
			case isAdvertised:
				// Needs to be removed.
				conf.AdvertiseServices = slices.Delete(conf.AdvertiseServices, idx, idx+1)
			case shouldBeAdvertised:
				// Needs to be added.
				conf.AdvertiseServices = append(conf.AdvertiseServices, serviceName.String())
			}

			// Update the Secret.
			confB, err := json.Marshal(conf)
			if err != nil {
				return fmt.Errorf("error marshalling ProxyGroup config: %w", err)
			}
			mak.Set(&secret.Data, fileName, confB)
			updated = true
		}

		if updated {
			if err := a.Update(ctx, &secret); err != nil {
				return fmt.Errorf("error updating ProxyGroup config Secret: %w", err)
			}
		}
	}

	return nil
}

func (a *HAIngressReconciler) numberPodsAdvertising(ctx context.Context, pgName string, serviceName tailcfg.ServiceName) (int, error) {
	// Get all state Secrets for this ProxyGroup.
	secrets := &corev1.SecretList{}
	if err := a.List(ctx, secrets, client.InNamespace(a.tsNamespace), client.MatchingLabels(pgSecretLabels(pgName, "state"))); err != nil {
		return 0, fmt.Errorf("failed to list ProxyGroup %q state Secrets: %w", pgName, err)
	}

	var count int
	for _, secret := range secrets.Items {
		prefs, ok, err := getDevicePrefs(&secret)
		if err != nil {
			return 0, fmt.Errorf("error getting node metadata: %w", err)
		}
		if !ok {
			continue
		}
		if slices.Contains(prefs.AdvertiseServices, serviceName.String()) {
			count++
		}
	}

	return count, nil
}

// OwnerRef is an owner reference that uniquely identifies a Tailscale
// Kubernetes operator instance.
type OwnerRef struct {
	// OperatorID is the stable ID of the operator's Tailscale device.
	OperatorID string `json:"operatorID,omitempty"`
}

// comment is the content of the VIPService.Comment field.
type comment struct {
	// OwnerRefs is a list of owner references that identify all operator
	// instances that manage this VIPService.
	OwnerRefs []OwnerRef `json:"ownerRefs,omitempty"`
}

// ownerRefsComment return VIPService Comment that includes owner reference for this
// operator instance for the provided VIPService. If the VIPService is nil, a
// new comment with owner ref is returned. If the VIPService is not nil, the
// existing comment is returned with the owner reference added, if not already
// present. If the VIPService is not nil, but does not contain a comment we
// return an error as this likely means that the VIPService was created by
// somthing other than a Tailscale Kubernetes operator.
func (r *HAIngressReconciler) ownerRefsComment(svc *tailscale.VIPService) (string, error) {
	ref := OwnerRef{
		OperatorID: r.operatorID,
	}
	if svc == nil {
		c := &comment{OwnerRefs: []OwnerRef{ref}}
		json, err := json.Marshal(c)
		if err != nil {
			return "", fmt.Errorf("[unexpected] unable to marshal VIPService comment contents: %w, please report this", err)
		}
		return string(json), nil
	}
	c, err := parseComment(svc)
	if err != nil {
		return "", fmt.Errorf("error parsing existing VIPService comment: %w", err)
	}
	if c == nil || len(c.OwnerRefs) == 0 {
		return "", fmt.Errorf("VIPService %s exists, but does not contain Comment field with owner references- not proceeding as this is likely a resource created by something other than a Tailscale Kubernetes Operator", svc.Name)
	}
	if slices.Contains(c.OwnerRefs, ref) { // up to date
		return svc.Comment, nil
	}
	c.OwnerRefs = append(c.OwnerRefs, ref)
	json, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("error marshalling updated owner references: %w", err)
	}
	return string(json), nil
}

// parseComment returns VIPService comment or nil if none found or not matching the expected format.
func parseComment(vipSvc *tailscale.VIPService) (*comment, error) {
	if vipSvc.Comment == "" {
		return nil, nil
	}
	c := &comment{}
	if err := json.Unmarshal([]byte(vipSvc.Comment), c); err != nil {
		return nil, fmt.Errorf("error parsing VIPService Comment field %q: %w", vipSvc.Comment, err)
	}
	return c, nil
}

// requeueInterval returns a time duration between 5 and 10 minutes, which is
// the period of time after which an HA Ingress, whose VIPService has been newly
// created or changed, needs to be requeued. This is to protect against
// VIPService owner references being overwritten as a result of concurrent
// updates during multi-clutster Ingress create/update operations.
func requeueInterval() time.Duration {
	return time.Duration(rand.N(5)+5) * time.Minute
}
