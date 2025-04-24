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
	"net/netip"
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
	"tailscale.com/internal/client/tailscale"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/ingressservices"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

// var gaugePGServiceResources = clientmetric.NewGauge(kubetypes.MetricServicePGResourceCount)

// HAServiceReconciler is a controller that reconciles kubernetes services with tailscale annotations
// should be exposed on an ingress ProxyGroup (in HA mode).
type HAServiceReconciler struct {
	client.Client

	isDefaultLoadBalancer bool
	recorder              record.EventRecorder
	logger                *zap.SugaredLogger
	tsClient              tsClient
	tsnetServer           tsnetServer
	tsNamespace           string
	lc                    localClient
	defaultTags           []string
	operatorID            string // stableID of the operator's Tailscale device

	clock tstime.Clock

	mu sync.Mutex // protects following
	// managedServices is a set of all service resources that we're currently
	// managing. This is only used for metrics.
	// NOTE (ChaosInTheCRD): Do we need this
	managedServices set.Slice[types.UID]
}

func (r *HAServiceReconciler) isTailscaleService(svc *corev1.Service) bool {
	proxyGroup := svc.Annotations[AnnotationProxyGroup]
	return r.shouldExpose(svc) && proxyGroup != ""
}

func (r *HAServiceReconciler) shouldExpose(svc *corev1.Service) bool {
	return r.shouldExposeClusterIP(svc)
}

func (r *HAServiceReconciler) shouldExposeClusterIP(svc *corev1.Service) bool {
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return false
	}
	return isTailscaleLoadBalancerService(svc, r.isDefaultLoadBalancer) || hasExposeAnnotation(svc)
}

// Reconcile reconciles Services that should be exposed over Tailscale in HA
// mode (on a ProxyGroup). It looks at all Servicees with
// tailscale.com/proxy-group annotation. For each such Service, it ensures that
// a VIPService named after the hostname of the Service exists and is up to
// date. It also ensures that the serve config for the ingress ProxyGroup is
// updated to route traffic for the VIPService to the Service's backend
// Services.  Service hostname change also results in the VIPService for the
// previous hostname being cleaned up and a new VIPService being created for the
// new hostname.
// HA Servicees support multi-cluster Service setup.
// Each VIPService contains a list of owner references that uniquely identify
// the Service resource and the operator.  When an Service that acts as a
// backend is being deleted, the corresponding VIPService is only deleted if the
// only owner reference that it contains is for this Service. If other owner
// references are found, then cleanup operation only removes this Service' owner
// reference.
func (r *HAServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := r.logger.With("Service", req.NamespacedName)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	svc := new(corev1.Service)
	err = r.Get(ctx, req.NamespacedName, svc)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("Service not found, assuming it was deleted")
		return res, nil
	} else if err != nil {
		return res, fmt.Errorf("failed to get Service: %w", err)
	}

	hostname := nameForService(svc)
	logger = logger.With("hostname", hostname)

	if !svc.DeletionTimestamp.IsZero() || !r.isTailscaleService(svc) {
		logger.Debugf("service is being deleted or is (no longer) referring to Tailscale ingress/egress, ensuring any created resources are cleaned up")
		return reconcile.Result{}, nil
		// return reconcile.Result{}, a.maybeCleanup(ctx, logger, svc)
	}

	// needsRequeue is set to true if the underlying VIPService has changed as a result of this reconcile. If that
	// is the case, we reconcile the Ingress one more time to ensure that concurrent updates to the VIPService in a
	// multi-cluster Ingress setup have not resulted in another actor overwriting our VIPService update.
	// needsRequeue := false
	// if !svc.DeletionTimestamp.IsZero() {
	// 	needsRequeue, err = r.maybeCleanup(ctx, hostname, ing, logger)
	// } else {
	// 	needsRequeue, err = r.maybeProvision(ctx, hostname, ing, logger)
	// }
	// if err != nil {
	// 	return res, err
	// }
	// if needsRequeue {
	// 	res = reconcile.Result{RequeueAfter: requeueInterval()}
	// }
	if _, err := r.maybeProvision(ctx, hostname, svc, logger); err != nil {
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			logger.Infof("optimistic lock error, retrying: %s", err)
		} else {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// maybeProvision ensures that a VIPService for this Ingress exists and is up to date and that the serve config for the
// corresponding ProxyGroup contains the Ingress backend's definition.
// If a VIPService does not exist, it will be created.
// If a VIPService exists, but only with owner references from other operator instances, an owner reference for this
// operator instance is added.
// If a VIPService exists, but does not have an owner reference from any operator, we error
// out assuming that this is an owner reference created by an unknown actor.
// Returns true if the operation resulted in a VIPService update.
func (r *HAServiceReconciler) maybeProvision(ctx context.Context, hostname string, svc *corev1.Service, logger *zap.SugaredLogger) (svcsChanged bool, err error) {
	oldSvcStatus := svc.Status.DeepCopy()
	defer func() {
		if !apiequality.Semantic.DeepEqual(oldSvcStatus, &svc.Status) {
			// An error encountered here should get returned by the Reconcile function.
			err = errors.Join(err, r.Client.Status().Update(ctx, svc))
		}
	}()

	pgName := svc.Annotations[AnnotationProxyGroup]
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

	// Validate Service configuration
	if violations := validateService(svc); len(violations) > 0 {
		msg := fmt.Sprintf("unable to provision proxy resources: invalid Service: %s", strings.Join(violations, ", "))
		r.recorder.Event(svc, corev1.EventTypeWarning, "INVALIDSERVICE", msg)
		r.logger.Error(msg)
		tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyInvalid, msg, r.clock, logger)
		return false, nil
	}

	// TODO (ChaosInTheCRD): Write cleanup logic
	// if !slices.Contains(ing.Finalizers, FinalizerNamePG) {
	// 	// This log line is printed exactly once during initial provisioning,
	// 	// because once the finalizer is in place this block gets skipped. So,
	// 	// this is a nice place to tell the operator that the high level,
	// 	// multi-reconcile operation is underway.
	// 	logger.Infof("exposing Ingress over tailscale")
	// 	ing.Finalizers = append(ing.Finalizers, FinalizerNamePG)
	// 	if err := r.Update(ctx, ing); err != nil {
	// 		return false, fmt.Errorf("failed to add finalizer: %w", err)
	// 	}
	// 	r.mu.Lock()
	// 	r.managedIngresses.Add(ing.UID)
	// 	gaugePGIngressResources.Set(int64(r.managedIngresses.Len()))
	// 	r.mu.Unlock()
	// }
	//
	// 1. Ensure that if Ingress' hostname has changed, any VIPService
	// resources corresponding to the old hostname are cleaned up.
	// In practice, this function will ensure that any VIPServices that are
	// associated with the provided ProxyGroup and no longer owned by an
	// Ingress are cleaned up. This is fine- it is not expensive and ensures
	// that in edge cases (a single update changed both hostname and removed
	// ProxyGroup annotation) the VIPService is more likely to be
	// (eventually) removed.
	// svcsChanged, err = r.maybeCleanupProxyGroup(ctx, pgName, logger)
	// if err != nil {
	// 	return false, fmt.Errorf("failed to cleanup VIPService resources for ProxyGroup: %w", err)
	// }
	//
	// 2. Ensure that there isn't a VIPService with the same hostname
	// already created and not owned by this Service.
	// TODO(irbekrm): perhaps in future we could have record names being
	// stored on VIPServices. I am not certain if there might not be edge
	// cases (custom domains, etc?) where attempting to determine the DNS
	// name of the VIPService in this way won't be incorrect.

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

	// Generate the VIPService owner annotation for new or existing VIPService.
	// This checks and ensures that VIPService's owner references are updated
	// for this Service and errors if that is not possible (i.e. because it
	// appears that the VIPService has been created by a non-operator actor).
	updatedAnnotations, err := r.ownerAnnotations(existingVIPSvc)
	if err != nil {
		instr := fmt.Sprintf("To proceed, you can either manually delete the existing VIPService or choose a different hostname with the '%s' annnotaion", AnnotationHostname)
		msg := fmt.Sprintf("error ensuring ownership of VIPService %s: %v. %s", hostname, err, instr)
		logger.Warn(msg)
		r.recorder.Event(svc, corev1.EventTypeWarning, "InvalidVIPService", msg)
		return false, nil
	}

	tags := r.defaultTags
	if tstr, ok := svc.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}

	vipSvc := &tailscale.VIPService{
		Name:        serviceName,
		Tags:        tags,
		Ports:       []string{"do-not-validate"}, // we don't want to validate ports
		Comment:     managedVIPServiceComment,
		Annotations: updatedAnnotations,
	}
	if existingVIPSvc != nil {
		vipSvc.Addrs = existingVIPSvc.Addrs
	}

	// TODO(irbekrm): right now if two Ingress resources attempt to apply different VIPService configs (different
	// tags, or HTTP endpoint settings) we can end up reconciling those in a loop. We should detect when an Ingress
	// with the same generation number has been reconciled ~more than N times and stop attempting to apply updates.
	if existingVIPSvc == nil ||
		!reflect.DeepEqual(vipSvc.Tags, existingVIPSvc.Tags) ||
		!ownersAreSetAndEqual(vipSvc, existingVIPSvc) {
		logger.Infof("Ensuring VIPService exists and is up to date")
		if err := r.tsClient.CreateOrUpdateVIPService(ctx, vipSvc); err != nil {
			return false, fmt.Errorf("error creating VIPService: %w", err)
		}
	}

	cm, cfgs, err := ingressSvcsConfigs(ctx, r.Client, pgName, r.tsNamespace)
	if err != nil {
		return false, fmt.Errorf("error retrieving ingress services configuration: %w", err)
	}
	if cm == nil {
		logger.Info("ConfigMap not yet created, waiting..")
		return false, nil
	}

	if existingVIPSvc.Addrs == nil {
		existingVIPSvc, err = r.tsClient.GetVIPService(ctx, vipSvc.Name)
		if err != nil {
			return false, fmt.Errorf("error getting VIPService: %w", err)
		}
		if existingVIPSvc.Addrs == nil {
			// TODO: this should be a retry
			return false, fmt.Errorf("unexpected: VIPService addresses not populated")
		}
	}

	var vipv4 netip.Addr
	var vipv6 netip.Addr
	for _, vip := range existingVIPSvc.Addrs {
		ip, err := netip.ParseAddr(vip)
		if err != nil {
			return false, fmt.Errorf("error parsing cluster ip address: %w", err)
		}

		if ip.Is4() {
			vipv4 = ip
		} else if ip.Is6() {
			vipv6 = ip
		}
	}

	cfg := ingressservices.Config{}
	for _, cip := range svc.Spec.ClusterIPs {
		ip, err := netip.ParseAddr(cip)
		if err != nil {
			return false, fmt.Errorf("error parsing cluster ip address: %w", err)
		}

		if ip.Is4() {
			mak.Set(&cfg.IPv4Mapping, vipv4, ip)
		} else if ip.Is6() {
			mak.Set(&cfg.IPv6Mapping, vipv6, ip)
		}
	}

	existingCfg := cfgs[serviceName.String()]
	if !reflect.DeepEqual(existingCfg, cfg) {
		logger.Infof("Updating ingress config")
		mak.Set(&cfgs, serviceName.String(), cfg)
		cfgBytes, err := json.Marshal(cfg)
		if err != nil {
			return false, fmt.Errorf("error marshaling ingress config: %w", err)
		}
		mak.Set(&cm.BinaryData, ingressservices.IngressConfigKey, cfgBytes)
		if err := r.Update(ctx, cm); err != nil {
			return false, fmt.Errorf("error updating ingress config: %w", err)
		}
	}

	// 5. Update tailscaled's AdvertiseServices config, which should add the VIPService
	// IPs to the ProxyGroup Pods' AllowedIPs in the next netmap update if approved.
	// if err = r.maybeUpdateAdvertiseServicesConfig(ctx, pg.Name, serviceName, mode, logger); err != nil {
	// 	return false, fmt.Errorf("failed to update tailscaled config: %w", err)
	// }

	// 6. Update Ingress status if ProxyGroup Pods are ready.
	// count, err := r.numberPodsAdvertising(ctx, pg.Name, serviceName)
	// if err != nil {
	// 	return false, fmt.Errorf("failed to check if any Pods are configured: %w", err)
	// }

	// oldStatus := ing.Status.DeepCopy()
	//
	// switch count {
	// case 0:
	// 	ing.Status.LoadBalancer.Ingress = nil
	// default:
	// 	var ports []networkingv1.IngressPortStatus
	// 	hasCerts, err := r.hasCerts(ctx, serviceName)
	// 	if err != nil {
	// 		return false, fmt.Errorf("error checking TLS credentials provisioned for Ingress: %w", err)
	// 	}
	// 	// If TLS certs have not been issued (yet), do not set port 443.
	// 	if hasCerts {
	// 		ports = append(ports, networkingv1.IngressPortStatus{
	// 			Protocol: "TCP",
	// 			Port:     443,
	// 		})
	// 	}
	// 	if isHTTPEndpointEnabled(ing) {
	// 		ports = append(ports, networkingv1.IngressPortStatus{
	// 			Protocol: "TCP",
	// 			Port:     80,
	// 		})
	// 	}
	// 	// Set Ingress status hostname only if either port 443 or 80 is advertised.
	// 	var hostname string
	// 	if len(ports) != 0 {
	// 		hostname = dnsName
	// 	}
	// 	ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{
	// 		{
	// 			Hostname: hostname,
	// 			Ports:    ports,
	// 		},
	// 	}
	// }
	// if apiequality.Semantic.DeepEqual(oldStatus, &ing.Status) {
	// 	return svcsChanged, nil
	// }
	//
	// const prefix = "Updating Ingress status"
	// if count == 0 {
	// 	logger.Infof("%s. No Pods are advertising VIPService yet", prefix)
	// } else {
	// 	logger.Infof("%s. %d Pod(s) advertising VIPService", prefix, count)
	// }
	//
	// if err := r.Status().Update(ctx, ing); err != nil {
	// 	return false, fmt.Errorf("failed to update Ingress status: %w", err)
	// }
	return svcsChanged, nil
}

// VIPServices that are associated with the provided ProxyGroup and no longer managed this operator's instance are deleted, if not owned by other operator instances, else the owner reference is cleaned up.
// Returns true if the operation resulted in existing VIPService updates (owner reference removal).
func (r *HAServiceReconciler) maybeCleanupProxyGroup(ctx context.Context, proxyGroupName string, logger *zap.SugaredLogger) (svcsChanged bool, err error) {
	// Get serve config for the ProxyGroup
	// cm, cfg, err := r.proxyGroupServeConfig(ctx, proxyGroupName)
	// if err != nil {
	// 	return false, fmt.Errorf("getting serve config: %w", err)
	// }
	// if cfg == nil {
	// 	return false, nil // ProxyGroup does not have any VIPServices
	// }
	//
	// ingList := &networkingv1.IngressList{}
	// if err := r.List(ctx, ingList); err != nil {
	// 	return false, fmt.Errorf("listing Ingresses: %w", err)
	// }
	// serveConfigChanged := false
	// // For each VIPService in serve config...
	// for vipServiceName := range cfg.Services {
	// 	// ...check if there is currently an Ingress with this hostname
	// 	found := false
	// 	for _, i := range ingList.Items {
	// 		ingressHostname := hostnameForIngress(&i)
	// 		if ingressHostname == vipServiceName.WithoutPrefix() {
	// 			found = true
	// 			break
	// 		}
	// 	}
	//
	// 	if !found {
	// 		logger.Infof("VIPService %q is not owned by any Ingress, cleaning up", vipServiceName)
	//
	// 		// Delete the VIPService from control if necessary.
	// 		svcsChanged, err = r.cleanupVIPService(ctx, vipServiceName, logger)
	// 		if err != nil {
	// 			return false, fmt.Errorf("deleting VIPService %q: %w", vipServiceName, err)
	// 		}
	//
	// 		// Make sure the VIPService is not advertised in tailscaled or serve config.
	// 		if err = r.maybeUpdateAdvertiseServicesConfig(ctx, proxyGroupName, vipServiceName, serviceAdvertisementOff, logger); err != nil {
	// 			return false, fmt.Errorf("failed to update tailscaled config services: %w", err)
	// 		}
	// 		_, ok := cfg.Services[vipServiceName]
	// 		if ok {
	// 			logger.Infof("Removing VIPService %q from serve config", vipServiceName)
	// 			delete(cfg.Services, vipServiceName)
	// 			serveConfigChanged = true
	// 		}
	// 		if err := r.cleanupCertResources(ctx, proxyGroupName, vipServiceName); err != nil {
	// 			return false, fmt.Errorf("failed to clean up cert resources: %w", err)
	// 		}
	// 	}
	// }
	//
	// if serveConfigChanged {
	// 	cfgBytes, err := json.Marshal(cfg)
	// 	if err != nil {
	// 		return false, fmt.Errorf("marshaling serve config: %w", err)
	// 	}
	// 	mak.Set(&cm.BinaryData, serveConfigKey, cfgBytes)
	// 	if err := r.Update(ctx, cm); err != nil {
	// 		return false, fmt.Errorf("updating serve config: %w", err)
	// 	}
	// }
	return svcsChanged, nil
}

// maybeCleanup ensures that any resources, such as a VIPService created for this Ingress, are cleaned up when the
// Ingress is being deleted or is unexposed. The cleanup is safe for a multi-cluster setup- the VIPService is only
// deleted if it does not contain any other owner references. If it does the cleanup only removes the owner reference
// corresponding to this Ingress.
func (r *HAServiceReconciler) maybeCleanup(ctx context.Context, hostname string, ing *networkingv1.Ingress, logger *zap.SugaredLogger) (svcChanged bool, err error) {
	// logger.Debugf("Ensuring any resources for Ingress are cleaned up")
	// ix := slices.Index(ing.Finalizers, FinalizerNamePG)
	// if ix < 0 {
	// 	logger.Debugf("no finalizer, nothing to do")
	// 	return false, nil
	// }
	// logger.Infof("Ensuring that VIPService %q configuration is cleaned up", hostname)
	//
	// // Ensure that if cleanup succeeded Ingress finalizers are removed.
	// defer func() {
	// 	if err != nil {
	// 		return
	// 	}
	// 	if e := r.deleteFinalizer(ctx, ing, logger); err != nil {
	// 		err = errors.Join(err, e)
	// 	}
	// }()
	//
	// // 1. Check if there is a VIPService associated with this Ingress.
	// pg := ing.Annotations[AnnotationProxyGroup]
	// cm, cfg, err := r.proxyGroupServeConfig(ctx, pg)
	// if err != nil {
	// 	return false, fmt.Errorf("error getting ProxyGroup serve config: %w", err)
	// }
	// serviceName := tailcfg.ServiceName("svc:" + hostname)
	//
	// // VIPService is always first added to serve config and only then created in the Tailscale API, so if it is not
	// // found in the serve config, we can assume that there is no VIPService. (If the serve config does not exist at
	// // all, it is possible that the ProxyGroup has been deleted before cleaning up the Ingress, so carry on with
	// // cleanup).
	// if cfg != nil && cfg.Services != nil && cfg.Services[serviceName] == nil {
	// 	return false, nil
	// }
	//
	// // 2. Clean up the VIPService resources.
	// svcChanged, err = r.cleanupVIPService(ctx, serviceName, logger)
	// if err != nil {
	// 	return false, fmt.Errorf("error deleting VIPService: %w", err)
	// }
	//
	// // 3. Clean up any cluster resources
	// if err := r.cleanupCertResources(ctx, pg, serviceName); err != nil {
	// 	return false, fmt.Errorf("failed to clean up cert resources: %w", err)
	// }
	//
	// if cfg == nil || cfg.Services == nil { // user probably deleted the ProxyGroup
	// 	return svcChanged, nil
	// }
	//
	// // 4. Unadvertise the VIPService in tailscaled config.
	// if err = r.maybeUpdateAdvertiseServicesConfig(ctx, pg, serviceName, serviceAdvertisementOff, logger); err != nil {
	// 	return false, fmt.Errorf("failed to update tailscaled config services: %w", err)
	// }
	//
	// // 5. Remove the VIPService from the serve config for the ProxyGroup.
	// logger.Infof("Removing VIPService %q from serve config for ProxyGroup %q", hostname, pg)
	// delete(cfg.Services, serviceName)
	// cfgBytes, err := json.Marshal(cfg)
	// if err != nil {
	// 	return false, fmt.Errorf("error marshaling serve config: %w", err)
	// }
	// mak.Set(&cm.BinaryData, serveConfigKey, cfgBytes)
	// return svcChanged, r.Update(ctx, cm)
	return svcChanged, nil
}

func (r *HAServiceReconciler) deleteFinalizer(ctx context.Context, ing *networkingv1.Ingress, logger *zap.SugaredLogger) error {
	// found := false
	// ing.Finalizers = slices.DeleteFunc(ing.Finalizers, func(f string) bool {
	// 	found = true
	// 	return f == FinalizerNamePG
	// })
	// if !found {
	// 	return nil
	// }
	// logger.Debug("ensure %q finalizer is removed", FinalizerNamePG)
	//
	// if err := r.Update(ctx, ing); err != nil {
	// 	return fmt.Errorf("failed to remove finalizer %q: %w", FinalizerNamePG, err)
	// }
	// r.mu.Lock()
	// defer r.mu.Unlock()
	// r.managedIngresses.Remove(ing.UID)
	// gaugePGIngressResources.Set(int64(r.managedIngresses.Len()))
	return nil
}

// tailnetCertDomain returns the base domain (TCD) of the current tailnet.
func (r *HAServiceReconciler) tailnetCertDomain(ctx context.Context) (string, error) {
	st, err := r.lc.StatusWithoutPeers(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting tailscale status: %w", err)
	}
	return st.CurrentTailnet.MagicDNSSuffix, nil
}

// cleanupVIPService deletes any VIPService by the provided name if it is not owned by operator instances other than this one.
// If a VIPService is found, but contains other owner references, only removes this operator's owner reference.
// If a VIPService by the given name is not found or does not contain this operator's owner reference, do nothing.
// It returns true if an existing VIPService was updated to remove owner reference, as well as any error that occurred.
func (r *HAServiceReconciler) cleanupVIPService(ctx context.Context, name tailcfg.ServiceName, logger *zap.SugaredLogger) (updated bool, _ error) {
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
	o, err := parseOwnerAnnotation(svc)
	if err != nil {
		return false, fmt.Errorf("error parsing VIPService owner annotation")
	}
	if o == nil || len(o.OwnerRefs) == 0 {
		return false, nil
	}
	// Comparing with the operatorID only means that we will not be able to
	// clean up VIPServices in cases where the operator was deleted from the
	// cluster before deleting the Ingress. Perhaps the comparison could be
	// 'if or.OperatorID === r.operatorID || or.ingressUID == r.ingressUID'.
	ix := slices.IndexFunc(o.OwnerRefs, func(or OwnerRef) bool {
		return or.OperatorID == r.operatorID
	})
	if ix == -1 {
		return false, nil
	}
	if len(o.OwnerRefs) == 1 {
		logger.Infof("Deleting VIPService %q", name)
		return false, r.tsClient.DeleteVIPService(ctx, name)
	}
	o.OwnerRefs = slices.Delete(o.OwnerRefs, ix, ix+1)
	logger.Infof("Deleting VIPService %q", name)
	json, err := json.Marshal(o)
	if err != nil {
		return false, fmt.Errorf("error marshalling updated VIPService owner reference: %w", err)
	}
	svc.Annotations[ownerAnnotation] = string(json)
	return true, r.tsClient.CreateOrUpdateVIPService(ctx, svc)
}

func (a *HAServiceReconciler) maybeUpdateAdvertiseServicesConfig(ctx context.Context, pgName string, serviceName tailcfg.ServiceName, mode serviceAdvertisementMode, logger *zap.SugaredLogger) (err error) {
	// Get all config Secrets for this ProxyGroup.
	secrets := &corev1.SecretList{}
	if err := a.List(ctx, secrets, client.InNamespace(a.tsNamespace), client.MatchingLabels(pgSecretLabels(pgName, "config"))); err != nil {
		return fmt.Errorf("failed to list config Secrets: %w", err)
	}

	// for _, secret := range secrets.Items {
	// 	var updated bool
	// 	for fileName, confB := range secret.Data {
	// 		var conf ipn.ConfigVAlpha
	// 		if err := json.Unmarshal(confB, &conf); err != nil {
	// 			return fmt.Errorf("error unmarshalling ProxyGroup config: %w", err)
	// 		}
	//
	// 		// Update the services to advertise if required.
	// 		idx := slices.Index(conf.AdvertiseServices, serviceName.String())
	// 		isAdvertised := idx >= 0
	// 		switch {
	// 		case isAdvertised == shouldBeAdvertised:
	// 			// Already up to date.
	// 			continue
	// 		case isAdvertised:
	// 			// Needs to be removed.
	// 			conf.AdvertiseServices = slices.Delete(conf.AdvertiseServices, idx, idx+1)
	// 		case shouldBeAdvertised:
	// 			// Needs to be added.
	// 			conf.AdvertiseServices = append(conf.AdvertiseServices, serviceName.String())
	// 		}
	//
	// 		// Update the Secret.
	// 		confB, err := json.Marshal(conf)
	// 		if err != nil {
	// 			return fmt.Errorf("error marshalling ProxyGroup config: %w", err)
	// 		}
	// 		mak.Set(&secret.Data, fileName, confB)
	// 		updated = true
	// 	}
	//
	// 	if updated {
	// 		if err := a.Update(ctx, &secret); err != nil {
	// 			return fmt.Errorf("error updating ProxyGroup config Secret: %w", err)
	// 		}
	// 	}
	// }

	return nil
}

func (a *HAServiceReconciler) numberPodsAdvertising(ctx context.Context, pgName string, serviceName tailcfg.ServiceName) (int, error) {
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

// ownerAnnotations returns the updated annotations required to ensure this
// instance of the operator is included as an owner. If the VIPService is not
// nil, but does not contain an owner we return an error as this likely means
// that the VIPService was created by somthing other than a Tailscale
// Kubernetes operator.
func (r *HAServiceReconciler) ownerAnnotations(svc *tailscale.VIPService) (map[string]string, error) {
	ref := OwnerRef{
		OperatorID: r.operatorID,
	}
	if svc == nil {
		c := ownerAnnotationValue{OwnerRefs: []OwnerRef{ref}}
		json, err := json.Marshal(c)
		if err != nil {
			return nil, fmt.Errorf("[unexpected] unable to marshal VIPService owner annotation contents: %w, please report this", err)
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
		return nil, fmt.Errorf("VIPService %s exists, but does not contain owner annotation with owner references; not proceeding as this is likely a resource created by something other than the Tailscale Kubernetes operator", svc.Name)
	}
	if slices.Contains(o.OwnerRefs, ref) { // up to date
		return svc.Annotations, nil
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

// dnsNameForService returns the DNS name for the given VIPService name.
func (r *HAServiceReconciler) dnsNameForService(ctx context.Context, svc tailcfg.ServiceName) (string, error) {
	s := svc.WithoutPrefix()
	tcd, err := r.tailnetCertDomain(ctx)
	if err != nil {
		return "", fmt.Errorf("error determining DNS name base: %w", err)
	}
	return s + "." + tcd, nil
}

// ingressSvcsConfig returns a ConfigMap that contains ingress services configuration for the provided ProxyGroup as well
// as unmarshalled configuration from the ConfigMap.
func ingressSvcsConfigs(ctx context.Context, cl client.Client, proxyGroupName, tsNamespace string) (cm *corev1.ConfigMap, cfgs ingressservices.Configs, err error) {
	name := pgIngressCMName(proxyGroupName)
	cm = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tsNamespace,
		},
	}
	err = cl.Get(ctx, client.ObjectKeyFromObject(cm), cm)
	if apierrors.IsNotFound(err) { // ProxyGroup resources have not been created (yet)
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error retrieving ingress services ConfigMap %s: %v", name, err)
	}
	cfgs = ingressservices.Configs{}
	if len(cm.BinaryData[ingressservices.IngressConfigKey]) != 0 {
		if err := json.Unmarshal(cm.BinaryData[ingressservices.IngressConfigKey], &cfgs); err != nil {
			return nil, nil, fmt.Errorf("error unmarshaling ingress services config %v: %w", cm.BinaryData[ingressservices.IngressConfigKey], err)
		}
	}
	return cm, cfgs, nil
}
