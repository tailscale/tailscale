// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
	serveConfigKey       = "serve-config.json"
	TailscaleSvcOwnerRef = "tailscale.com/k8s-operator:owned-by:%s"
	// FinalizerNamePG is the finalizer used by the IngressPGReconciler
	FinalizerNamePG = "tailscale.com/ingress-pg-finalizer"

	indexIngressProxyGroup = ".metadata.annotations.ingress-proxy-group"
	// annotationHTTPEndpoint can be used to configure the Ingress to expose an HTTP endpoint to tailnet (as
	// well as the default HTTPS endpoint).
	annotationHTTPEndpoint = "tailscale.com/http-endpoint"

	labelDomain              = "tailscale.com/domain"
	msgFeatureFlagNotEnabled = "Tailscale Service feature flag is not enabled for this tailnet, skipping provisioning. " +
		"Please contact Tailscale support through https://tailscale.com/contact/support to enable the feature flag, then recreate the operator's Pod."

	warningTailscaleServiceFeatureFlagNotEnabled = "TailscaleServiceFeatureFlagNotEnabled"
	managedTSServiceComment                      = "This Tailscale Service is managed by the Tailscale Kubernetes Operator, do not modify"
)

var gaugePGIngressResources = clientmetric.NewGauge(kubetypes.MetricIngressPGResourceCount)

// HAIngressReconciler is a controller that reconciles Tailscale Ingresses
// should be exposed on an ingress ProxyGroup (in HA mode).
type HAIngressReconciler struct {
	client.Client

	recorder         record.EventRecorder
	logger           *zap.SugaredLogger
	tsClient         tsClient
	tsnetServer      tsnetServer
	tsNamespace      string
	lc               localClient
	defaultTags      []string
	operatorID       string // stableID of the operator's Tailscale device
	ingressClassName string

	mu sync.Mutex // protects following
	// managedIngresses is a set of all ingress resources that we're currently
	// managing. This is only used for metrics.
	managedIngresses set.Slice[types.UID]
}

// Reconcile reconciles Ingresses that should be exposed over Tailscale in HA
// mode (on a ProxyGroup). It looks at all Ingresses with
// tailscale.com/proxy-group annotation. For each such Ingress, it ensures that
// a TailscaleService named after the hostname of the Ingress exists and is up to
// date. It also ensures that the serve config for the ingress ProxyGroup is
// updated to route traffic for the Tailscale Service to the Ingress's backend
// Services.  Ingress hostname change also results in the Tailscale Service for the
// previous hostname being cleaned up and a new Tailscale Service being created for the
// new hostname.
// HA Ingresses support multi-cluster Ingress setup.
// Each Tailscale Service contains a list of owner references that uniquely identify
// the Ingress resource and the operator.  When an Ingress that acts as a
// backend is being deleted, the corresponding Tailscale Service is only deleted if the
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

	// hostname is the name of the Tailscale Service that will be created
	// for this Ingress as well as the first label in the MagicDNS name of
	// the Ingress.
	hostname := hostnameForIngress(ing)
	logger = logger.With("hostname", hostname)

	// needsRequeue is set to true if the underlying Tailscale Service has
	// changed as a result of this reconcile. If that is the case, we
	// reconcile the Ingress one more time to ensure that concurrent updates
	// to the Tailscale Service in a multi-cluster Ingress setup have not
	// resulted in another actor overwriting our Tailscale Service update.
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

// maybeProvision ensures that a Tailscale Service for this Ingress exists and is up to date and that the serve config for the
// corresponding ProxyGroup contains the Ingress backend's definition.
// If a Tailscale Service does not exist, it will be created.
// If a Tailscale Service exists, but only with owner references from other operator instances, an owner reference for this
// operator instance is added.
// If a Tailscale Service exists, but does not have an owner reference from any operator, we error
// out assuming that this is an owner reference created by an unknown actor.
// Returns true if the operation resulted in a Tailscale Service update.
func (r *HAIngressReconciler) maybeProvision(ctx context.Context, hostname string, ing *networkingv1.Ingress, logger *zap.SugaredLogger) (svcsChanged bool, err error) {
	// Currently (2025-05) Tailscale Services are behind an alpha feature flag that
	// needs to be explicitly enabled for a tailnet to be able to use them.
	serviceName := tailcfg.ServiceName("svc:" + hostname)
	existingTSSvc, err := r.tsClient.GetVIPService(ctx, serviceName)
	if err != nil && !isErrorTailscaleServiceNotFound(err) {
		return false, fmt.Errorf("error getting Tailscale Service %q: %w", hostname, err)
	}

	if err := validateIngressClass(ctx, r.Client, r.ingressClassName); err != nil {
		logger.Infof("error validating tailscale IngressClass: %v.", err)
		return false, nil
	}
	// Get and validate ProxyGroup readiness
	pgName := ing.Annotations[AnnotationProxyGroup]
	if pgName == "" {
		logger.Infof("[unexpected] no ProxyGroup annotation, skipping Tailscale Service provisioning")
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
	if !tsoperator.ProxyGroupAvailable(pg) {
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

	// 1. Ensure that if Ingress' hostname has changed, any Tailscale Service
	// resources corresponding to the old hostname are cleaned up.
	// In practice, this function will ensure that any Tailscale Services that are
	// associated with the provided ProxyGroup and no longer owned by an
	// Ingress are cleaned up. This is fine- it is not expensive and ensures
	// that in edge cases (a single update changed both hostname and removed
	// ProxyGroup annotation) the Tailscale Service is more likely to be
	// (eventually) removed.
	svcsChanged, err = r.maybeCleanupProxyGroup(ctx, pgName, logger)
	if err != nil {
		return false, fmt.Errorf("failed to cleanup Tailscale Service resources for ProxyGroup: %w", err)
	}

	// 2. Ensure that there isn't a Tailscale Service with the same hostname
	// already created and not owned by this Ingress.
	// TODO(irbekrm): perhaps in future we could have record names being
	// stored on Tailscale Services. I am not certain if there might not be edge
	// cases (custom domains, etc?) where attempting to determine the DNS
	// name of the Tailscale Service in this way won't be incorrect.

	// Generate the Tailscale Service owner annotation for a new or existing Tailscale Service.
	// This checks and ensures that Tailscale Service's owner references are updated
	// for this Ingress and errors if that is not possible (i.e. because it
	// appears that the Tailscale Service has been created by a non-operator actor).
	updatedAnnotations, err := ownerAnnotations(r.operatorID, existingTSSvc)
	if err != nil {
		const instr = "To proceed, you can either manually delete the existing Tailscale Service or choose a different MagicDNS name at `.spec.tls.hosts[0] in the Ingress definition"
		msg := fmt.Sprintf("error ensuring ownership of Tailscale Service %s: %v. %s", hostname, err, instr)
		logger.Warn(msg)
		r.recorder.Event(ing, corev1.EventTypeWarning, "InvalidTailscaleService", msg)
		return false, nil
	}
	// 3. Ensure that TLS Secret and RBAC exists
	tcd, err := tailnetCertDomain(ctx, r.lc)
	if err != nil {
		return false, fmt.Errorf("error determining DNS name base: %w", err)
	}
	dnsName := hostname + "." + tcd
	if err := r.ensureCertResources(ctx, pg, dnsName, ing); err != nil {
		return false, fmt.Errorf("error ensuring cert resources: %w", err)
	}

	// 4. Ensure that the serve config for the ProxyGroup contains the Tailscale Service.
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

	// 4. Ensure that the Tailscale Service exists and is up to date.
	tags := r.defaultTags
	if tstr, ok := ing.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}

	tsSvcPorts := []string{"tcp:443"} // always 443 for Ingress
	if isHTTPEndpointEnabled(ing) {
		tsSvcPorts = append(tsSvcPorts, "tcp:80")
	}

	tsSvc := &tailscale.VIPService{
		Name:        serviceName,
		Tags:        tags,
		Ports:       tsSvcPorts,
		Comment:     managedTSServiceComment,
		Annotations: updatedAnnotations,
	}
	if existingTSSvc != nil {
		tsSvc.Addrs = existingTSSvc.Addrs
	}
	// TODO(irbekrm): right now if two Ingress resources attempt to apply different Tailscale Service configs (different
	// tags, or HTTP endpoint settings) we can end up reconciling those in a loop. We should detect when an Ingress
	// with the same generation number has been reconciled ~more than N times and stop attempting to apply updates.
	if existingTSSvc == nil ||
		!reflect.DeepEqual(tsSvc.Tags, existingTSSvc.Tags) ||
		!reflect.DeepEqual(tsSvc.Ports, existingTSSvc.Ports) ||
		!ownersAreSetAndEqual(tsSvc, existingTSSvc) {
		logger.Infof("Ensuring Tailscale Service exists and is up to date")
		if err := r.tsClient.CreateOrUpdateVIPService(ctx, tsSvc); err != nil {
			return false, fmt.Errorf("error creating Tailscale Service: %w", err)
		}
	}

	// 5. Update tailscaled's AdvertiseServices config, which should add the Tailscale Service
	// IPs to the ProxyGroup Pods' AllowedIPs in the next netmap update if approved.
	mode := serviceAdvertisementHTTPS
	if isHTTPEndpointEnabled(ing) {
		mode = serviceAdvertisementHTTPAndHTTPS
	}
	if err = r.maybeUpdateAdvertiseServicesConfig(ctx, pg.Name, serviceName, mode, logger); err != nil {
		return false, fmt.Errorf("failed to update tailscaled config: %w", err)
	}

	// 6. Update Ingress status if ProxyGroup Pods are ready.
	count, err := numberPodsAdvertising(ctx, r.Client, r.tsNamespace, pg.Name, serviceName)
	if err != nil {
		return false, fmt.Errorf("failed to check if any Pods are configured: %w", err)
	}

	oldStatus := ing.Status.DeepCopy()

	switch count {
	case 0:
		ing.Status.LoadBalancer.Ingress = nil
	default:
		var ports []networkingv1.IngressPortStatus
		hasCerts, err := hasCerts(ctx, r.Client, r.lc, r.tsNamespace, serviceName)
		if err != nil {
			return false, fmt.Errorf("error checking TLS credentials provisioned for Ingress: %w", err)
		}
		// If TLS certs have not been issued (yet), do not set port 443.
		if hasCerts {
			ports = append(ports, networkingv1.IngressPortStatus{
				Protocol: "TCP",
				Port:     443,
			})
		}
		if isHTTPEndpointEnabled(ing) {
			ports = append(ports, networkingv1.IngressPortStatus{
				Protocol: "TCP",
				Port:     80,
			})
		}
		// Set Ingress status hostname only if either port 443 or 80 is advertised.
		var hostname string
		if len(ports) != 0 {
			hostname = dnsName
		}
		ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{
			{
				Hostname: hostname,
				Ports:    ports,
			},
		}
	}
	if apiequality.Semantic.DeepEqual(oldStatus, &ing.Status) {
		return svcsChanged, nil
	}

	const prefix = "Updating Ingress status"
	if count == 0 {
		logger.Infof("%s. No Pods are advertising Tailscale Service yet", prefix)
	} else {
		logger.Infof("%s. %d Pod(s) advertising Tailscale Service", prefix, count)
	}

	if err := r.Status().Update(ctx, ing); err != nil {
		return false, fmt.Errorf("failed to update Ingress status: %w", err)
	}
	return svcsChanged, nil
}

// maybeCleanupProxyGroup ensures that any Tailscale Services that are
// associated with the provided ProxyGroup and no longer needed for any
// Ingresses exposed on this ProxyGroup are deleted, if not owned by other
// operator instances, else the owner reference is cleaned up.  Returns true if
// the operation resulted in an existing Tailscale Service updates (owner
// reference removal).
func (r *HAIngressReconciler) maybeCleanupProxyGroup(ctx context.Context, proxyGroupName string, logger *zap.SugaredLogger) (svcsChanged bool, err error) {
	// Get serve config for the ProxyGroup
	cm, cfg, err := r.proxyGroupServeConfig(ctx, proxyGroupName)
	if err != nil {
		return false, fmt.Errorf("getting serve config: %w", err)
	}
	if cfg == nil {
		// ProxyGroup does not have any Tailscale Services associated with it.
		return false, nil
	}

	ingList := &networkingv1.IngressList{}
	if err := r.List(ctx, ingList); err != nil {
		return false, fmt.Errorf("listing Ingresses: %w", err)
	}
	serveConfigChanged := false
	// For each Tailscale Service in serve config...
	for tsSvcName := range cfg.Services {
		// ...check if there is currently an Ingress with this hostname
		found := false
		for _, i := range ingList.Items {
			ingressHostname := hostnameForIngress(&i)
			if ingressHostname == tsSvcName.WithoutPrefix() {
				found = true
				break
			}
		}

		if !found {
			logger.Infof("Tailscale Service %q is not owned by any Ingress, cleaning up", tsSvcName)
			tsService, err := r.tsClient.GetVIPService(ctx, tsSvcName)
			if isErrorTailscaleServiceNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, fmt.Errorf("getting Tailscale Service %q: %w", tsSvcName, err)
			}

			// Delete the Tailscale Service from control if necessary.
			svcsChanged, err = r.cleanupTailscaleService(ctx, tsService, logger)
			if err != nil {
				return false, fmt.Errorf("deleting Tailscale Service %q: %w", tsSvcName, err)
			}

			// Make sure the Tailscale Service is not advertised in tailscaled or serve config.
			if err = r.maybeUpdateAdvertiseServicesConfig(ctx, proxyGroupName, tsSvcName, serviceAdvertisementOff, logger); err != nil {
				return false, fmt.Errorf("failed to update tailscaled config services: %w", err)
			}
			_, ok := cfg.Services[tsSvcName]
			if ok {
				logger.Infof("Removing Tailscale Service %q from serve config", tsSvcName)
				delete(cfg.Services, tsSvcName)
				serveConfigChanged = true
			}
			if err := cleanupCertResources(ctx, r.Client, r.lc, r.tsNamespace, proxyGroupName, tsSvcName); err != nil {
				return false, fmt.Errorf("failed to clean up cert resources: %w", err)
			}
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

// maybeCleanup ensures that any resources, such as a Tailscale Service created for this Ingress, are cleaned up when the
// Ingress is being deleted or is unexposed. The cleanup is safe for a multi-cluster setup- the Tailscale Service is only
// deleted if it does not contain any other owner references. If it does the cleanup only removes the owner reference
// corresponding to this Ingress.
func (r *HAIngressReconciler) maybeCleanup(ctx context.Context, hostname string, ing *networkingv1.Ingress, logger *zap.SugaredLogger) (svcChanged bool, err error) {
	logger.Debugf("Ensuring any resources for Ingress are cleaned up")
	ix := slices.Index(ing.Finalizers, FinalizerNamePG)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		return false, nil
	}
	logger.Infof("Ensuring that Tailscale Service %q configuration is cleaned up", hostname)
	serviceName := tailcfg.ServiceName("svc:" + hostname)
	svc, err := r.tsClient.GetVIPService(ctx, serviceName)
	if err != nil && !isErrorTailscaleServiceNotFound(err) {
		return false, fmt.Errorf("error getting Tailscale Service: %w", err)
	}

	// Ensure that if cleanup succeeded Ingress finalizers are removed.
	defer func() {
		if err != nil {
			return
		}
		err = r.deleteFinalizer(ctx, ing, logger)
	}()

	// 1. Check if there is a Tailscale Service associated with this Ingress.
	pg := ing.Annotations[AnnotationProxyGroup]
	cm, cfg, err := r.proxyGroupServeConfig(ctx, pg)
	if err != nil {
		return false, fmt.Errorf("error getting ProxyGroup serve config: %w", err)
	}

	// Tailscale Service is always first added to serve config and only then created in the Tailscale API, so if it is not
	// found in the serve config, we can assume that there is no Tailscale Service. (If the serve config does not exist at
	// all, it is possible that the ProxyGroup has been deleted before cleaning up the Ingress, so carry on with
	// cleanup).
	if cfg != nil && cfg.Services != nil && cfg.Services[serviceName] == nil {
		return false, nil
	}

	// 2. Clean up the Tailscale Service resources.
	svcChanged, err = r.cleanupTailscaleService(ctx, svc, logger)
	if err != nil {
		return false, fmt.Errorf("error deleting Tailscale Service: %w", err)
	}

	// 3. Clean up any cluster resources
	if err := cleanupCertResources(ctx, r.Client, r.lc, r.tsNamespace, pg, serviceName); err != nil {
		return false, fmt.Errorf("failed to clean up cert resources: %w", err)
	}

	if cfg == nil || cfg.Services == nil { // user probably deleted the ProxyGroup
		return svcChanged, nil
	}

	// 4. Unadvertise the Tailscale Service in tailscaled config.
	if err = r.maybeUpdateAdvertiseServicesConfig(ctx, pg, serviceName, serviceAdvertisementOff, logger); err != nil {
		return false, fmt.Errorf("failed to update tailscaled config services: %w", err)
	}

	// 5. Remove the Tailscale Service from the serve config for the ProxyGroup.
	logger.Infof("Removing TailscaleService %q from serve config for ProxyGroup %q", hostname, pg)
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
func tailnetCertDomain(ctx context.Context, lc localClient) (string, error) {
	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting tailscale status: %w", err)
	}
	return st.CurrentTailnet.MagicDNSSuffix, nil
}

// shouldExpose returns true if the Ingress should be exposed over Tailscale in HA mode (on a ProxyGroup).
func (r *HAIngressReconciler) shouldExpose(ing *networkingv1.Ingress) bool {
	isTSIngress := ing != nil &&
		ing.Spec.IngressClassName != nil &&
		*ing.Spec.IngressClassName == r.ingressClassName
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
	violations := tagViolations(ing)
	if len(violations) > 0 {
		errs = append(errs, fmt.Errorf("Ingress contains invalid tags: %v", strings.Join(violations, ",")))
	}

	// Validate TLS configuration
	if len(ing.Spec.TLS) > 0 && (len(ing.Spec.TLS) > 1 || len(ing.Spec.TLS[0].Hosts) > 1) {
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
	if !tsoperator.ProxyGroupAvailable(pg) {
		errs = append(errs, fmt.Errorf("ProxyGroup %q is not ready", pg.Name))
	}

	// It is invalid to have multiple Ingress resources for the same Tailscale Service in one cluster.
	ingList := &networkingv1.IngressList{}
	if err := r.List(ctx, ingList); err != nil {
		errs = append(errs, fmt.Errorf("[unexpected] error listing Ingresses: %w", err))
		return errors.Join(errs...)
	}
	for _, i := range ingList.Items {
		if r.shouldExpose(&i) && hostnameForIngress(&i) == hostname && i.UID != ing.UID {
			errs = append(errs, fmt.Errorf("found duplicate Ingress %q for hostname %q - multiple Ingresses for the same hostname in the same cluster are not allowed", client.ObjectKeyFromObject(&i), hostname))
		}
	}
	return errors.Join(errs...)
}

// cleanupTailscaleService deletes any Tailscale Service by the provided name if it is not owned by operator instances other than this one.
// If a Tailscale Service is found, but contains other owner references, only removes this operator's owner reference.
// If a Tailscale Service by the given name is not found or does not contain this operator's owner reference, do nothing.
// It returns true if an existing Tailscale Service was updated to remove owner reference, as well as any error that occurred.
func (r *HAIngressReconciler) cleanupTailscaleService(ctx context.Context, svc *tailscale.VIPService, logger *zap.SugaredLogger) (updated bool, _ error) {
	if svc == nil {
		return false, nil
	}
	o, err := parseOwnerAnnotation(svc)
	if err != nil {
		return false, fmt.Errorf("error parsing Tailscale Service's owner annotation")
	}
	if o == nil || len(o.OwnerRefs) == 0 {
		return false, nil
	}
	// Comparing with the operatorID only means that we will not be able to
	// clean up Tailscale Service in cases where the operator was deleted from the
	// cluster before deleting the Ingress. Perhaps the comparison could be
	// 'if or.OperatorID === r.operatorID || or.ingressUID == r.ingressUID'.
	ix := slices.IndexFunc(o.OwnerRefs, func(or OwnerRef) bool {
		return or.OperatorID == r.operatorID
	})
	if ix == -1 {
		return false, nil
	}
	if len(o.OwnerRefs) == 1 {
		logger.Infof("Deleting Tailscale Service %q", svc.Name)
		if err = r.tsClient.DeleteVIPService(ctx, svc.Name); err != nil && !isErrorTailscaleServiceNotFound(err) {
			return false, err
		}

		return false, nil
	}

	o.OwnerRefs = slices.Delete(o.OwnerRefs, ix, ix+1)
	logger.Infof("Creating/Updating Tailscale Service %q", svc.Name)
	json, err := json.Marshal(o)
	if err != nil {
		return false, fmt.Errorf("error marshalling updated Tailscale Service owner reference: %w", err)
	}
	svc.Annotations[ownerAnnotation] = string(json)
	return true, r.tsClient.CreateOrUpdateVIPService(ctx, svc)
}

// isHTTPEndpointEnabled returns true if the Ingress has been configured to expose an HTTP endpoint to tailnet.
func isHTTPEndpointEnabled(ing *networkingv1.Ingress) bool {
	if ing == nil {
		return false
	}
	return ing.Annotations[annotationHTTPEndpoint] == "enabled"
}

// serviceAdvertisementMode describes the desired state of a Tailscale Service.
type serviceAdvertisementMode int

const (
	serviceAdvertisementOff          serviceAdvertisementMode = iota // Should not be advertised
	serviceAdvertisementHTTPS                                        // Port 443 should be advertised
	serviceAdvertisementHTTPAndHTTPS                                 // Both ports 80 and 443 should be advertised
)

func (a *HAIngressReconciler) maybeUpdateAdvertiseServicesConfig(ctx context.Context, pgName string, serviceName tailcfg.ServiceName, mode serviceAdvertisementMode, logger *zap.SugaredLogger) (err error) {
	// Get all config Secrets for this ProxyGroup.
	secrets := &corev1.SecretList{}
	if err := a.List(ctx, secrets, client.InNamespace(a.tsNamespace), client.MatchingLabels(pgSecretLabels(pgName, kubetypes.LabelSecretTypeConfig))); err != nil {
		return fmt.Errorf("failed to list config Secrets: %w", err)
	}

	// Verify that TLS cert for the Tailscale Service has been successfully issued
	// before attempting to advertise the service.
	// This is so that in multi-cluster setups where some Ingresses succeed
	// to issue certs and some do not (rate limits), clients are not pinned
	// to a backend that is not able to serve HTTPS.
	// The only exception is Ingresses with an HTTP endpoint enabled - if an
	// Ingress has an HTTP endpoint enabled, it will be advertised even if the
	// TLS cert is not yet provisioned.
	hasCert, err := hasCerts(ctx, a.Client, a.lc, a.tsNamespace, serviceName)
	if err != nil {
		return fmt.Errorf("error checking TLS credentials provisioned for service %q: %w", serviceName, err)
	}
	shouldBeAdvertised := (mode == serviceAdvertisementHTTPAndHTTPS) ||
		(mode == serviceAdvertisementHTTPS && hasCert) // if we only expose port 443 and don't have certs (yet), do not advertise

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

func numberPodsAdvertising(ctx context.Context, cl client.Client, tsNamespace, pgName string, serviceName tailcfg.ServiceName) (int, error) {
	// Get all state Secrets for this ProxyGroup.
	secrets := &corev1.SecretList{}
	if err := cl.List(ctx, secrets, client.InNamespace(tsNamespace), client.MatchingLabels(pgSecretLabels(pgName, kubetypes.LabelSecretTypeState))); err != nil {
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

const ownerAnnotation = "tailscale.com/owner-references"

// ownerAnnotationValue is the content of the TailscaleService.Annotation[ownerAnnotation] field.
type ownerAnnotationValue struct {
	// OwnerRefs is a list of owner references that identify all operator
	// instances that manage this Tailscale Services.
	OwnerRefs []OwnerRef `json:"ownerRefs,omitempty"`
}

// OwnerRef is an owner reference that uniquely identifies a Tailscale
// Kubernetes operator instance.
type OwnerRef struct {
	// OperatorID is the stable ID of the operator's Tailscale device.
	OperatorID string    `json:"operatorID,omitempty"`
	Resource   *Resource `json:"resource,omitempty"` // optional, used to identify the ProxyGroup that owns this Tailscale Service.
}

type Resource struct {
	Kind string `json:"kind,omitempty"` // "ProxyGroup"
	Name string `json:"name,omitempty"` // Name of the ProxyGroup that owns this Tailscale Service. Informational only.
	UID  string `json:"uid,omitempty"`  // UID of the ProxyGroup that owns this Tailscale Service.
}

// ownerAnnotations returns the updated annotations required to ensure this
// instance of the operator is included as an owner. If the Tailscale Service is not
// nil, but does not contain an owner reference we return an error as this likely means
// that the Service was created by somthing other than a Tailscale
// Kubernetes operator.
func ownerAnnotations(operatorID string, svc *tailscale.VIPService) (map[string]string, error) {
	ref := OwnerRef{
		OperatorID: operatorID,
	}
	if svc == nil {
		c := ownerAnnotationValue{OwnerRefs: []OwnerRef{ref}}
		json, err := json.Marshal(c)
		if err != nil {
			return nil, fmt.Errorf("[unexpected] unable to marshal Tailscale Service's owner annotation contents: %w, please report this", err)
		}
		return map[string]string{
			ownerAnnotation: string(json),
		}, nil
	}
	o, err := parseOwnerAnnotation(svc)
	if err != nil {
		return nil, err
	}
	if o == nil || len(o.OwnerRefs) == 0 {
		return nil, fmt.Errorf("Tailscale Service %s exists, but does not contain owner annotation with owner references; not proceeding as this is likely a resource created by something other than the Tailscale Kubernetes operator", svc.Name)
	}
	if slices.Contains(o.OwnerRefs, ref) { // up to date
		return svc.Annotations, nil
	}
	if o.OwnerRefs[0].Resource != nil {
		return nil, fmt.Errorf("Tailscale Service %s is owned by another resource: %#v; cannot be reused for an Ingress", svc.Name, o.OwnerRefs[0].Resource)
	}
	o.OwnerRefs = append(o.OwnerRefs, ref)
	json, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("error marshalling updated owner references: %w", err)
	}

	newAnnots := make(map[string]string, len(svc.Annotations)+1)
	for k, v := range svc.Annotations {
		newAnnots[k] = v
	}
	newAnnots[ownerAnnotation] = string(json)
	return newAnnots, nil
}

// parseOwnerAnnotation returns nil if no valid owner found.
func parseOwnerAnnotation(tsSvc *tailscale.VIPService) (*ownerAnnotationValue, error) {
	if tsSvc.Annotations == nil || tsSvc.Annotations[ownerAnnotation] == "" {
		return nil, nil
	}
	o := &ownerAnnotationValue{}
	if err := json.Unmarshal([]byte(tsSvc.Annotations[ownerAnnotation]), o); err != nil {
		return nil, fmt.Errorf("error parsing Tailscale Service's %s annotation %q: %w", ownerAnnotation, tsSvc.Annotations[ownerAnnotation], err)
	}
	return o, nil
}

func ownersAreSetAndEqual(a, b *tailscale.VIPService) bool {
	return a != nil && b != nil &&
		a.Annotations != nil && b.Annotations != nil &&
		a.Annotations[ownerAnnotation] != "" &&
		b.Annotations[ownerAnnotation] != "" &&
		strings.EqualFold(a.Annotations[ownerAnnotation], b.Annotations[ownerAnnotation])
}

// ensureCertResources ensures that the TLS Secret for an HA Ingress and RBAC
// resources that allow proxies to manage the Secret are created.
// Note that Tailscale Service's name validation matches Kubernetes
// resource name validation, so we can be certain that the Tailscale Service name
// (domain) is a valid Kubernetes resource name.
// https://github.com/tailscale/tailscale/blob/8b1e7f646ee4730ad06c9b70c13e7861b964949b/util/dnsname/dnsname.go#L99
// https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names
func (r *HAIngressReconciler) ensureCertResources(ctx context.Context, pg *tsapi.ProxyGroup, domain string, ing *networkingv1.Ingress) error {
	secret := certSecret(pg.Name, r.tsNamespace, domain, ing)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, secret, func(s *corev1.Secret) {
		// Labels might have changed if the Ingress has been updated to use a
		// different ProxyGroup.
		s.Labels = secret.Labels
	}); err != nil {
		return fmt.Errorf("failed to create or update Secret %s: %w", secret.Name, err)
	}
	role := certSecretRole(pg.Name, r.tsNamespace, domain)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, role, func(r *rbacv1.Role) {
		// Labels might have changed if the Ingress has been updated to use a
		// different ProxyGroup.
		r.Labels = role.Labels
	}); err != nil {
		return fmt.Errorf("failed to create or update Role %s: %w", role.Name, err)
	}
	rolebinding := certSecretRoleBinding(pg, r.tsNamespace, domain)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, rolebinding, func(rb *rbacv1.RoleBinding) {
		// Labels and subjects might have changed if the Ingress has been updated to use a
		// different ProxyGroup.
		rb.Labels = rolebinding.Labels
		rb.Subjects = rolebinding.Subjects
	}); err != nil {
		return fmt.Errorf("failed to create or update RoleBinding %s: %w", rolebinding.Name, err)
	}
	return nil
}

// cleanupCertResources ensures that the TLS Secret and associated RBAC
// resources that allow proxies to read/write to the Secret are deleted.
func cleanupCertResources(ctx context.Context, cl client.Client, lc localClient, tsNamespace, pgName string, serviceName tailcfg.ServiceName) error {
	domainName, err := dnsNameForService(ctx, lc, serviceName)
	if err != nil {
		return fmt.Errorf("error getting DNS name for Tailscale Service %s: %w", serviceName, err)
	}
	labels := certResourceLabels(pgName, domainName)
	if err := cl.DeleteAllOf(ctx, &rbacv1.RoleBinding{}, client.InNamespace(tsNamespace), client.MatchingLabels(labels)); err != nil {
		return fmt.Errorf("error deleting RoleBinding for domain name %s: %w", domainName, err)
	}
	if err := cl.DeleteAllOf(ctx, &rbacv1.Role{}, client.InNamespace(tsNamespace), client.MatchingLabels(labels)); err != nil {
		return fmt.Errorf("error deleting Role for domain name %s: %w", domainName, err)
	}
	if err := cl.DeleteAllOf(ctx, &corev1.Secret{}, client.InNamespace(tsNamespace), client.MatchingLabels(labels)); err != nil {
		return fmt.Errorf("error deleting Secret for domain name %s: %w", domainName, err)
	}
	return nil
}

// requeueInterval returns a time duration between 5 and 10 minutes, which is
// the period of time after which an HA Ingress, whose Tailscale Service has been newly
// created or changed, needs to be requeued. This is to protect against
// Tailscale Service's owner references being overwritten as a result of concurrent
// updates during multi-clutster Ingress create/update operations.
func requeueInterval() time.Duration {
	return time.Duration(rand.N(5)+5) * time.Minute
}

// certSecretRole creates a Role that will allow proxies to manage the TLS
// Secret for the given domain. Domain must be a valid Kubernetes resource name.
func certSecretRole(pgName, namespace, domain string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      domain,
			Namespace: namespace,
			Labels:    certResourceLabels(pgName, domain),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{domain},
				Verbs: []string{
					"get",
					"list",
					"patch",
					"update",
				},
			},
		},
	}
}

// certSecretRoleBinding creates a RoleBinding for Role that will allow proxies
// to manage the TLS Secret for the given domain. Domain must be a valid
// Kubernetes resource name.
func certSecretRoleBinding(pg *tsapi.ProxyGroup, namespace, domain string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      domain,
			Namespace: namespace,
			Labels:    certResourceLabels(pg.Name, domain),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      pgServiceAccountName(pg),
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: domain,
		},
	}
}

// certSecret creates a Secret that will store the TLS certificate and private
// key for the given domain. Domain must be a valid Kubernetes resource name.
func certSecret(pgName, namespace, domain string, parent client.Object) *corev1.Secret {
	labels := certResourceLabels(pgName, domain)
	labels[kubetypes.LabelSecretType] = kubetypes.LabelSecretTypeCerts
	// Labels that let us identify the Ingress resource lets us reconcile
	// the Ingress when the TLS Secret is updated (for example, when TLS
	// certs have been provisioned).
	labels[LabelParentType] = strings.ToLower(parent.GetObjectKind().GroupVersionKind().Kind)
	labels[LabelParentName] = parent.GetName()
	if ns := parent.GetNamespace(); ns != "" {
		labels[LabelParentNamespace] = ns
	}
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      domain,
			Namespace: namespace,
			Labels:    labels,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       nil,
			corev1.TLSPrivateKeyKey: nil,
		},
		Type: corev1.SecretTypeTLS,
	}
}

func certResourceLabels(pgName, domain string) map[string]string {
	return map[string]string{
		kubetypes.LabelManaged: "true",
		labelProxyGroup:        pgName,
		labelDomain:            domain,
	}
}

// dnsNameForService returns the DNS name for the given Tailscale Service's name.
func dnsNameForService(ctx context.Context, lc localClient, svc tailcfg.ServiceName) (string, error) {
	s := svc.WithoutPrefix()
	tcd, err := tailnetCertDomain(ctx, lc)
	if err != nil {
		return "", fmt.Errorf("error determining DNS name base: %w", err)
	}
	return s + "." + tcd, nil
}

// hasCerts checks if the TLS Secret for the given service has non-zero cert and key data.
func hasCerts(ctx context.Context, cl client.Client, lc localClient, ns string, svc tailcfg.ServiceName) (bool, error) {
	domain, err := dnsNameForService(ctx, lc, svc)
	if err != nil {
		return false, fmt.Errorf("failed to get DNS name for service: %w", err)
	}
	secret := &corev1.Secret{}
	err = cl.Get(ctx, client.ObjectKey{
		Namespace: ns,
		Name:      domain,
	}, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get TLS Secret: %w", err)
	}

	cert := secret.Data[corev1.TLSCertKey]
	key := secret.Data[corev1.TLSPrivateKeyKey]

	return len(cert) > 0 && len(key) > 0, nil
}

func isErrorTailscaleServiceNotFound(err error) bool {
	var errResp tailscale.ErrResponse
	ok := errors.As(err, &errResp)
	return ok && errResp.Status == http.StatusNotFound
}

func tagViolations(obj client.Object) []string {
	var violations []string
	if obj == nil {
		return nil
	}
	tags, ok := obj.GetAnnotations()[AnnotationTags]
	if !ok {
		return nil
	}

	for _, tag := range strings.Split(tags, ",") {
		tag = strings.TrimSpace(tag)
		if err := tailcfg.CheckTag(tag); err != nil {
			violations = append(violations, fmt.Sprintf("invalid tag %q: %v", tag, err))
		}
	}
	return violations
}
