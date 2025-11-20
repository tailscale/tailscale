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
	discoveryv1 "k8s.io/api/discovery/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/ingressservices"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	svcPGFinalizerName = "tailscale.com/service-pg-finalizer"

	reasonIngressSvcInvalid              = "IngressSvcInvalid"
	reasonIngressSvcValid                = "IngressSvcValid"
	reasonIngressSvcConfigured           = "IngressSvcConfigured"
	reasonIngressSvcNoBackendsConfigured = "IngressSvcNoBackendsConfigured"
	reasonIngressSvcCreationFailed       = "IngressSvcCreationFailed"
)

var gaugePGServiceResources = clientmetric.NewGauge(kubetypes.MetricServicePGResourceCount)

// HAServiceReconciler is a controller that reconciles Tailscale Kubernetes
// Services that should be exposed on an ingress ProxyGroup (in HA mode).
type HAServiceReconciler struct {
	client.Client
	isDefaultLoadBalancer bool
	recorder              record.EventRecorder
	logger                *zap.SugaredLogger
	tsClient              tsClient
	tsNamespace           string
	lc                    localClient
	defaultTags           []string
	operatorID            string // stableID of the operator's Tailscale device

	clock tstime.Clock

	mu sync.Mutex // protects following
	// managedServices is a set of all Service resources that we're currently
	// managing. This is only used for metrics.
	managedServices set.Slice[types.UID]
}

// Reconcile reconciles Services that should be exposed over Tailscale in HA
// mode (on a ProxyGroup). It looks at all Services with
// tailscale.com/proxy-group annotation. For each such Service, it ensures that
// a Tailscale Service named after the hostname of the Service exists and is up to
// date.
// HA Servicees support multi-cluster Service setup.
// Each Tailscale Service contains a list of owner references that uniquely identify
// the operator.  When an Service that acts as a
// backend is being deleted, the corresponding Tailscale Service is only deleted if the
// only owner reference that it contains is for this operator. If other owner
// references are found, then cleanup operation only removes this operator's owner
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
		logger.Debugf("Service is being deleted or is (no longer) referring to Tailscale ingress/egress, ensuring any created resources are cleaned up")
		_, err = r.maybeCleanup(ctx, hostname, svc, logger)
		return res, err
	}

	// needsRequeue is set to true if the underlying Tailscale Service has changed as a result of this reconcile. If that
	// is the case, we reconcile the Ingress one more time to ensure that concurrent updates to the Tailscale Service in a
	// multi-cluster Ingress setup have not resulted in another actor overwriting our Tailscale Service update.
	needsRequeue := false
	needsRequeue, err = r.maybeProvision(ctx, hostname, svc, logger)
	if err != nil {
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			logger.Infof("optimistic lock error, retrying: %s", err)
		} else {
			return reconcile.Result{}, err
		}
	}
	if needsRequeue {
		res = reconcile.Result{RequeueAfter: requeueInterval()}
	}

	return reconcile.Result{}, nil
}

// maybeProvision ensures that a Tailscale Service for this Ingress exists and is up to date and that the serve config for the
// corresponding ProxyGroup contains the Ingress backend's definition.
// If a Tailscale Service does not exist, it will be created.
// If a Tailscale Service exists, but only with owner references from other operator instances, an owner reference for this
// operator instance is added.
// If a Tailscale Service exists, but does not have an owner reference from any operator, we error
// out assuming that this is an owner reference created by an unknown actor.
// Returns true if the operation resulted in a Tailscale Service update.
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
		logger.Infof("[unexpected] no ProxyGroup annotation, skipping Tailscale Service provisioning")
		return false, nil
	}

	logger = logger.With("ProxyGroup", pgName)

	pg := &tsapi.ProxyGroup{}
	if err := r.Get(ctx, client.ObjectKey{Name: pgName}, pg); err != nil {
		if apierrors.IsNotFound(err) {
			msg := fmt.Sprintf("ProxyGroup %q does not exist", pgName)
			logger.Warnf(msg)
			r.recorder.Event(svc, corev1.EventTypeWarning, "ProxyGroupNotFound", msg)
			return false, nil
		}
		return false, fmt.Errorf("getting ProxyGroup %q: %w", pgName, err)
	}
	if !tsoperator.ProxyGroupAvailable(pg) {
		logger.Infof("ProxyGroup is not (yet) ready")
		return false, nil
	}

	if err := r.validateService(ctx, svc, pg); err != nil {
		r.recorder.Event(svc, corev1.EventTypeWarning, reasonIngressSvcInvalid, err.Error())
		tsoperator.SetServiceCondition(svc, tsapi.IngressSvcValid, metav1.ConditionFalse, reasonIngressSvcInvalid, err.Error(), r.clock, logger)
		return false, nil
	}

	if !slices.Contains(svc.Finalizers, svcPGFinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("exposing Service over tailscale")
		svc.Finalizers = append(svc.Finalizers, svcPGFinalizerName)
		if err := r.Update(ctx, svc); err != nil {
			return false, fmt.Errorf("failed to add finalizer: %w", err)
		}
		r.mu.Lock()
		r.managedServices.Add(svc.UID)
		gaugePGServiceResources.Set(int64(r.managedServices.Len()))
		r.mu.Unlock()
	}

	// 1. Ensure that if Service's hostname/name has changed, any Tailscale Service
	// resources corresponding to the old hostname are cleaned up.
	// In practice, this function will ensure that any Tailscale Services that are
	// associated with the provided ProxyGroup and no longer owned by a
	// Service are cleaned up. This is fine- it is not expensive and ensures
	// that in edge cases (a single update changed both hostname and removed
	// ProxyGroup annotation) the Tailscale Service is more likely to be
	// (eventually) removed.
	svcsChanged, err = r.maybeCleanupProxyGroup(ctx, pgName, logger)
	if err != nil {
		return false, fmt.Errorf("failed to cleanup Tailscale Service resources for ProxyGroup: %w", err)
	}

	// 2. Ensure that there isn't a Tailscale Service with the same hostname
	// already created and not owned by this Service.
	serviceName := tailcfg.ServiceName("svc:" + hostname)
	existingTSSvc, err := r.tsClient.GetVIPService(ctx, serviceName)
	if err != nil && !isErrorTailscaleServiceNotFound(err) {
		return false, fmt.Errorf("error getting Tailscale Service %q: %w", hostname, err)
	}

	// 3. Generate the Tailscale Service owner annotation for new or existing Tailscale Service.
	// This checks and ensures that Tailscale Service's owner references are updated
	// for this Service and errors if that is not possible (i.e. because it
	// appears that the Tailscale Service has been created by a non-operator actor).
	updatedAnnotations, err := ownerAnnotations(r.operatorID, existingTSSvc)
	if err != nil {
		instr := fmt.Sprintf("To proceed, you can either manually delete the existing Tailscale Service or choose a different hostname with the '%s' annotaion", AnnotationHostname)
		msg := fmt.Sprintf("error ensuring ownership of Tailscale Service %s: %v. %s", hostname, err, instr)
		logger.Warn(msg)
		r.recorder.Event(svc, corev1.EventTypeWarning, "InvalidTailscaleService", msg)
		tsoperator.SetServiceCondition(svc, tsapi.IngressSvcValid, metav1.ConditionFalse, reasonIngressSvcInvalid, msg, r.clock, logger)
		return false, nil
	}

	tags := r.defaultTags
	if tstr, ok := svc.Annotations[AnnotationTags]; ok && tstr != "" {
		tags = strings.Split(tstr, ",")
	}

	tsSvc := &tailscale.VIPService{
		Name:        serviceName,
		Tags:        tags,
		Ports:       []string{"do-not-validate"}, // we don't want to validate ports
		Comment:     managedTSServiceComment,
		Annotations: updatedAnnotations,
	}
	if existingTSSvc != nil {
		tsSvc.Addrs = existingTSSvc.Addrs
	}

	// TODO(irbekrm): right now if two Service resources attempt to apply different Tailscale Service configs (different
	// tags) we can end up reconciling those in a loop. We should detect when a Service
	// with the same generation number has been reconciled ~more than N times and stop attempting to apply updates.
	if existingTSSvc == nil ||
		!reflect.DeepEqual(tsSvc.Tags, existingTSSvc.Tags) ||
		!ownersAreSetAndEqual(tsSvc, existingTSSvc) {
		logger.Infof("Ensuring Tailscale Service exists and is up to date")
		if err := r.tsClient.CreateOrUpdateVIPService(ctx, tsSvc); err != nil {
			return false, fmt.Errorf("error creating Tailscale Service: %w", err)
		}
		existingTSSvc = tsSvc
	}

	cm, cfgs, err := ingressSvcsConfigs(ctx, r.Client, pgName, r.tsNamespace)
	if err != nil {
		return false, fmt.Errorf("error retrieving ingress services configuration: %w", err)
	}
	if cm == nil {
		logger.Info("ConfigMap not yet created, waiting..")
		return false, nil
	}

	if existingTSSvc.Addrs == nil {
		existingTSSvc, err = r.tsClient.GetVIPService(ctx, tsSvc.Name)
		if err != nil {
			return false, fmt.Errorf("error getting Tailscale Service: %w", err)
		}
		if existingTSSvc.Addrs == nil {
			// TODO(irbekrm): this should be a retry
			return false, fmt.Errorf("unexpected: Tailscale Service addresses not populated")
		}
	}

	var tsSvcIPv4 netip.Addr
	var tsSvcIPv6 netip.Addr
	for _, tsip := range existingTSSvc.Addrs {
		ip, err := netip.ParseAddr(tsip)
		if err != nil {
			return false, fmt.Errorf("error parsing Tailscale Service address: %w", err)
		}

		if ip.Is4() {
			tsSvcIPv4 = ip
		} else if ip.Is6() {
			tsSvcIPv6 = ip
		}
	}

	cfg := ingressservices.Config{}
	for _, cip := range svc.Spec.ClusterIPs {
		ip, err := netip.ParseAddr(cip)
		if err != nil {
			return false, fmt.Errorf("error parsing Kubernetes Service address: %w", err)
		}

		if ip.Is4() {
			cfg.IPv4Mapping = &ingressservices.Mapping{
				ClusterIP:          ip,
				TailscaleServiceIP: tsSvcIPv4,
			}
		} else if ip.Is6() {
			cfg.IPv6Mapping = &ingressservices.Mapping{
				ClusterIP:          ip,
				TailscaleServiceIP: tsSvcIPv6,
			}
		}
	}

	existingCfg := cfgs[serviceName.String()]
	if !reflect.DeepEqual(existingCfg, cfg) {
		mak.Set(&cfgs, serviceName.String(), cfg)
		cfgBytes, err := json.Marshal(cfgs)
		if err != nil {
			return false, fmt.Errorf("error marshaling ingress config: %w", err)
		}
		mak.Set(&cm.BinaryData, ingressservices.IngressConfigKey, cfgBytes)
		if err := r.Update(ctx, cm); err != nil {
			return false, fmt.Errorf("error updating ingress config: %w", err)
		}
	}

	logger.Infof("updating AdvertiseServices config")
	// 4. Update tailscaled's AdvertiseServices config, which should add the Tailscale Service
	// IPs to the ProxyGroup Pods' AllowedIPs in the next netmap update if approved.
	if err = r.maybeUpdateAdvertiseServicesConfig(ctx, svc, pg.Name, serviceName, &cfg, true, logger); err != nil {
		return false, fmt.Errorf("failed to update tailscaled config: %w", err)
	}

	count, err := r.numberPodsAdvertising(ctx, pgName, serviceName)
	if err != nil {
		return false, fmt.Errorf("failed to get number of advertised Pods: %w", err)
	}

	// TODO(irbekrm): here and when creating the Tailscale Service, verify if the
	// error is not terminal (and therefore should not be reconciled). For
	// example, if the hostname is already a hostname of a Tailscale node,
	// the GET here will fail.
	// If there are no Pods advertising the Tailscale Service (yet), we want to set 'svc.Status.LoadBalancer.Ingress' to nil"
	var lbs []corev1.LoadBalancerIngress
	conditionStatus := metav1.ConditionFalse
	conditionType := tsapi.IngressSvcConfigured
	conditionReason := reasonIngressSvcNoBackendsConfigured
	conditionMessage := fmt.Sprintf("%d/%d proxy backends ready and advertising", count, pgReplicas(pg))
	if count != 0 {
		dnsName, err := r.dnsNameForService(ctx, serviceName)
		if err != nil {
			return false, fmt.Errorf("error getting DNS name for Service: %w", err)
		}

		lbs = []corev1.LoadBalancerIngress{
			{
				Hostname: dnsName,
				IP:       tsSvcIPv4.String(),
			},
		}

		conditionStatus = metav1.ConditionTrue
		conditionReason = reasonIngressSvcConfigured
	}

	tsoperator.SetServiceCondition(svc, conditionType, conditionStatus, conditionReason, conditionMessage, r.clock, logger)
	svc.Status.LoadBalancer.Ingress = lbs

	return svcsChanged, nil
}

// maybeCleanup ensures that any resources, such as a Tailscale Service created for this Service, are cleaned up when the
// Service is being deleted or is unexposed. The cleanup is safe for a multi-cluster setup- the Tailscale Service is only
// deleted if it does not contain any other owner references. If it does the cleanup only removes the owner reference
// corresponding to this Service.
func (r *HAServiceReconciler) maybeCleanup(ctx context.Context, hostname string, svc *corev1.Service, logger *zap.SugaredLogger) (svcChanged bool, err error) {
	logger.Debugf("Ensuring any resources for Service are cleaned up")
	ix := slices.Index(svc.Finalizers, svcPGFinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		return false, nil
	}
	logger.Infof("Ensuring that Tailscale Service %q configuration is cleaned up", hostname)

	defer func() {
		if err != nil {
			return
		}
		err = r.deleteFinalizer(ctx, svc, logger)
	}()

	serviceName := tailcfg.ServiceName("svc:" + hostname)
	//  1. Clean up the Tailscale Service.
	svcChanged, err = cleanupTailscaleService(ctx, r.tsClient, serviceName, r.operatorID, logger)
	if err != nil {
		return false, fmt.Errorf("error deleting Tailscale Service: %w", err)
	}

	// 2. Unadvertise the Tailscale Service.
	pgName := svc.Annotations[AnnotationProxyGroup]
	if err = r.maybeUpdateAdvertiseServicesConfig(ctx, svc, pgName, serviceName, nil, false, logger); err != nil {
		return false, fmt.Errorf("failed to update tailscaled config services: %w", err)
	}

	// TODO: maybe wait for the service to be unadvertised, only then remove the backend routing

	// 3. Clean up ingress config (routing rules).
	cm, cfgs, err := ingressSvcsConfigs(ctx, r.Client, pgName, r.tsNamespace)
	if err != nil {
		return false, fmt.Errorf("error retrieving ingress services configuration: %w", err)
	}
	if cm == nil || cfgs == nil {
		return true, nil
	}
	logger.Infof("Removing Tailscale Service %q from ingress config for ProxyGroup %q", hostname, pgName)
	delete(cfgs, serviceName.String())
	cfgBytes, err := json.Marshal(cfgs)
	if err != nil {
		return false, fmt.Errorf("error marshaling ingress config: %w", err)
	}
	mak.Set(&cm.BinaryData, ingressservices.IngressConfigKey, cfgBytes)
	return true, r.Update(ctx, cm)
}

// Tailscale Services that are associated with the provided ProxyGroup and no longer managed this operator's instance are deleted, if not owned by other operator instances, else the owner reference is cleaned up.
// Returns true if the operation resulted in existing Tailscale Service updates (owner reference removal).
func (r *HAServiceReconciler) maybeCleanupProxyGroup(ctx context.Context, proxyGroupName string, logger *zap.SugaredLogger) (svcsChanged bool, err error) {
	cm, config, err := ingressSvcsConfigs(ctx, r.Client, proxyGroupName, r.tsNamespace)
	if err != nil {
		return false, fmt.Errorf("failed to get ingress service config: %s", err)
	}

	svcList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, svcList, client.MatchingFields{indexIngressProxyGroup: proxyGroupName}); err != nil {
		return false, fmt.Errorf("failed to find Services for ProxyGroup %q: %w", proxyGroupName, err)
	}

	ingressConfigChanged := false
	for tsSvcName, cfg := range config {
		found := false
		for _, svc := range svcList.Items {
			if strings.EqualFold(fmt.Sprintf("svc:%s", nameForService(&svc)), tsSvcName) {
				found = true
				break
			}
		}
		if !found {
			logger.Infof("Tailscale Service %q is not owned by any Service, cleaning up", tsSvcName)

			// Make sure the Tailscale Service is not advertised in tailscaled or serve config.
			if err = r.maybeUpdateAdvertiseServicesConfig(ctx, nil, proxyGroupName, tailcfg.ServiceName(tsSvcName), &cfg, false, logger); err != nil {
				return false, fmt.Errorf("failed to update tailscaled config services: %w", err)
			}

			svcsChanged, err = cleanupTailscaleService(ctx, r.tsClient, tailcfg.ServiceName(tsSvcName), r.operatorID, logger)
			if err != nil {
				return false, fmt.Errorf("deleting Tailscale Service %q: %w", tsSvcName, err)
			}

			_, ok := config[tsSvcName]
			if ok {
				logger.Infof("Removing Tailscale Service %q from serve config", tsSvcName)
				delete(config, tsSvcName)
				ingressConfigChanged = true
			}
		}
	}

	if ingressConfigChanged {
		configBytes, err := json.Marshal(config)
		if err != nil {
			return false, fmt.Errorf("marshaling serve config: %w", err)
		}
		mak.Set(&cm.BinaryData, ingressservices.IngressConfigKey, configBytes)
		if err := r.Update(ctx, cm); err != nil {
			return false, fmt.Errorf("updating serve config: %w", err)
		}
	}

	return svcsChanged, nil
}

func (r *HAServiceReconciler) deleteFinalizer(ctx context.Context, svc *corev1.Service, logger *zap.SugaredLogger) error {
	svc.Finalizers = slices.DeleteFunc(svc.Finalizers, func(f string) bool {
		return f == svcPGFinalizerName
	})
	logger.Debugf("ensure %q finalizer is removed", svcPGFinalizerName)

	if err := r.Update(ctx, svc); err != nil {
		return fmt.Errorf("failed to remove finalizer %q: %w", svcPGFinalizerName, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.managedServices.Remove(svc.UID)
	gaugePGServiceResources.Set(int64(r.managedServices.Len()))
	return nil
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

// tailnetCertDomain returns the base domain (TCD) of the current tailnet.
func (r *HAServiceReconciler) tailnetCertDomain(ctx context.Context) (string, error) {
	st, err := r.lc.StatusWithoutPeers(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting tailscale status: %w", err)
	}
	return st.CurrentTailnet.MagicDNSSuffix, nil
}

// cleanupTailscaleService deletes any Tailscale Service by the provided name if it is not owned by operator instances other than this one.
// If a Tailscale Service is found, but contains other owner references, only removes this operator's owner reference.
// If a Tailscale Service by the given name is not found or does not contain this operator's owner reference, do nothing.
// It returns true if an existing Tailscale Service was updated to remove owner reference, as well as any error that occurred.
func cleanupTailscaleService(ctx context.Context, tsClient tsClient, name tailcfg.ServiceName, operatorID string, logger *zap.SugaredLogger) (updated bool, err error) {
	svc, err := tsClient.GetVIPService(ctx, name)
	if err != nil {
		errResp := &tailscale.ErrResponse{}
		ok := errors.As(err, errResp)
		if ok && errResp.Status == http.StatusNotFound {
			return false, nil
		}
		if !ok {
			return false, fmt.Errorf("unexpected error getting Tailscale Service %q: %w", name.String(), err)
		}

		return false, fmt.Errorf("error getting Tailscale Service: %w", err)
	}
	if svc == nil {
		return false, nil
	}
	o, err := parseOwnerAnnotation(svc)
	if err != nil {
		return false, fmt.Errorf("error parsing Tailscale Service owner annotation: %w", err)
	}
	if o == nil || len(o.OwnerRefs) == 0 {
		return false, nil
	}
	// Comparing with the operatorID only means that we will not be able to
	// clean up Tailscale Services in cases where the operator was deleted from the
	// cluster before deleting the Ingress. Perhaps the comparison could be
	// 'if or.OperatorID == r.operatorID || or.ingressUID == r.ingressUID'.
	ix := slices.IndexFunc(o.OwnerRefs, func(or OwnerRef) bool {
		return or.OperatorID == operatorID
	})
	if ix == -1 {
		return false, nil
	}
	if len(o.OwnerRefs) == 1 {
		logger.Infof("Deleting Tailscale Service %q", name)
		return false, tsClient.DeleteVIPService(ctx, name)
	}
	o.OwnerRefs = slices.Delete(o.OwnerRefs, ix, ix+1)
	logger.Infof("Updating Tailscale Service %q", name)
	json, err := json.Marshal(o)
	if err != nil {
		return false, fmt.Errorf("error marshalling updated Tailscale Service owner reference: %w", err)
	}
	svc.Annotations[ownerAnnotation] = string(json)
	return true, tsClient.CreateOrUpdateVIPService(ctx, svc)
}

func (a *HAServiceReconciler) backendRoutesSetup(ctx context.Context, serviceName, replicaName, pgName string, wantsCfg *ingressservices.Config, logger *zap.SugaredLogger) (bool, error) {
	logger.Debugf("checking backend routes for service '%s'", serviceName)
	pod := &corev1.Pod{}
	err := a.Get(ctx, client.ObjectKey{Namespace: a.tsNamespace, Name: replicaName}, pod)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Pod %q not found", replicaName)
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get Pod: %w", err)
	}
	secret := &corev1.Secret{}
	err = a.Get(ctx, client.ObjectKey{Namespace: a.tsNamespace, Name: replicaName}, secret)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Secret %q not found", replicaName)
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get Secret: %w", err)
	}
	if len(secret.Data) == 0 || secret.Data[ingressservices.IngressConfigKey] == nil {
		return false, nil
	}
	gotCfgB := secret.Data[ingressservices.IngressConfigKey]
	var gotCfgs ingressservices.Status
	if err := json.Unmarshal(gotCfgB, &gotCfgs); err != nil {
		return false, fmt.Errorf("error unmarshalling ingress config: %w", err)
	}
	statusUpToDate, err := isCurrentStatus(gotCfgs, pod, logger)
	if err != nil {
		return false, fmt.Errorf("error checking ingress config status: %w", err)
	}
	if !statusUpToDate || !reflect.DeepEqual(gotCfgs.Configs.GetConfig(serviceName), wantsCfg) {
		logger.Debugf("Pod %q is not ready to advertise Tailscale Service", pod.Name)
		return false, nil
	}
	return true, nil
}

func isCurrentStatus(gotCfgs ingressservices.Status, pod *corev1.Pod, logger *zap.SugaredLogger) (bool, error) {
	ips := pod.Status.PodIPs
	if len(ips) == 0 {
		logger.Debugf("Pod %q does not yet have IPs, unable to determine if status is up to date", pod.Name)
		return false, nil
	}

	if len(ips) > 2 {
		return false, fmt.Errorf("pod 'status.PodIPs' can contain at most 2 IPs, got %d (%v)", len(ips), ips)
	}
	var podIPv4, podIPv6 string
	for _, ip := range ips {
		parsed, err := netip.ParseAddr(ip.IP)
		if err != nil {
			return false, fmt.Errorf("error parsing IP address %s: %w", ip.IP, err)
		}
		if parsed.Is4() {
			podIPv4 = parsed.String()
			continue
		}
		podIPv6 = parsed.String()
	}
	if podIPv4 != gotCfgs.PodIPv4 || podIPv6 != gotCfgs.PodIPv6 {
		return false, nil
	}
	return true, nil
}

func (a *HAServiceReconciler) maybeUpdateAdvertiseServicesConfig(ctx context.Context, svc *corev1.Service, pgName string, serviceName tailcfg.ServiceName, cfg *ingressservices.Config, shouldBeAdvertised bool, logger *zap.SugaredLogger) (err error) {
	logger.Debugf("checking advertisement for service '%s'", serviceName)
	// Get all config Secrets for this ProxyGroup.
	// Get all Pods
	secrets := &corev1.SecretList{}
	if err := a.List(ctx, secrets, client.InNamespace(a.tsNamespace), client.MatchingLabels(pgSecretLabels(pgName, kubetypes.LabelSecretTypeConfig))); err != nil {
		return fmt.Errorf("failed to list config Secrets: %w", err)
	}

	if svc != nil && shouldBeAdvertised {
		shouldBeAdvertised, err = a.checkEndpointsReady(ctx, svc, logger)
		if err != nil {
			return fmt.Errorf("failed to check readiness of Service '%s' endpoints: %w", svc.Name, err)
		}
	}

	for _, secret := range secrets.Items {
		var updated bool
		for fileName, confB := range secret.Data {
			var conf ipn.ConfigVAlpha
			if err := json.Unmarshal(confB, &conf); err != nil {
				return fmt.Errorf("error unmarshalling ProxyGroup config: %w", err)
			}

			idx := slices.Index(conf.AdvertiseServices, serviceName.String())
			isAdvertised := idx >= 0
			switch {
			case !isAdvertised && !shouldBeAdvertised:
				logger.Debugf("service %q shouldn't be advertised", serviceName)
				continue
			case isAdvertised && shouldBeAdvertised:
				logger.Debugf("service %q is already advertised", serviceName)
				continue
			case isAdvertised && !shouldBeAdvertised:
				logger.Debugf("deleting advertisement for service %q", serviceName)
				conf.AdvertiseServices = slices.Delete(conf.AdvertiseServices, idx, idx+1)
			case shouldBeAdvertised:
				replicaName, ok := strings.CutSuffix(secret.Name, "-config")
				if !ok {
					logger.Infof("[unexpected] unable to determine replica name from config Secret name %q, unable to determine if backend routing has been configured", secret.Name)
					return nil
				}
				ready, err := a.backendRoutesSetup(ctx, serviceName.String(), replicaName, pgName, cfg, logger)
				if err != nil {
					return fmt.Errorf("error checking backend routes: %w", err)
				}
				if !ready {
					logger.Debugf("service %q is not ready to be advertised", serviceName)
					continue
				}

				conf.AdvertiseServices = append(conf.AdvertiseServices, serviceName.String())
			}
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

func (a *HAServiceReconciler) numberPodsAdvertising(ctx context.Context, pgName string, serviceName tailcfg.ServiceName) (int, error) {
	// Get all state Secrets for this ProxyGroup.
	secrets := &corev1.SecretList{}
	if err := a.List(ctx, secrets, client.InNamespace(a.tsNamespace), client.MatchingLabels(pgSecretLabels(pgName, kubetypes.LabelSecretTypeState))); err != nil {
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

// dnsNameForService returns the DNS name for the given Tailscale Service name.
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

func (r *HAServiceReconciler) getEndpointSlicesForService(ctx context.Context, svc *corev1.Service, logger *zap.SugaredLogger) ([]discoveryv1.EndpointSlice, error) {
	logger.Debugf("looking for endpoint slices for svc with name '%s' in namespace '%s' matching label '%s=%s'", svc.Name, svc.Namespace, discoveryv1.LabelServiceName, svc.Name)
	// https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	labels := map[string]string{discoveryv1.LabelServiceName: svc.Name}
	eps := new(discoveryv1.EndpointSliceList)
	if err := r.List(ctx, eps, client.InNamespace(svc.Namespace), client.MatchingLabels(labels)); err != nil {
		return nil, fmt.Errorf("error listing EndpointSlices: %w", err)
	}

	if len(eps.Items) == 0 {
		logger.Debugf("Service '%s' EndpointSlice does not yet exist. We will reconcile again once it's created", svc.Name)
		return nil, nil
	}

	return eps.Items, nil
}

func (r *HAServiceReconciler) checkEndpointsReady(ctx context.Context, svc *corev1.Service, logger *zap.SugaredLogger) (bool, error) {
	epss, err := r.getEndpointSlicesForService(ctx, svc, logger)
	if err != nil {
		return false, fmt.Errorf("failed to list EndpointSlices for Service %q: %w", svc.Name, err)
	}
	for _, eps := range epss {
		for _, ep := range eps.Endpoints {
			if *ep.Conditions.Ready {
				return true, nil
			}
		}
	}

	logger.Debugf("could not find any ready Endpoints in EndpointSlice")
	return false, nil
}

func (r *HAServiceReconciler) validateService(ctx context.Context, svc *corev1.Service, pg *tsapi.ProxyGroup) error {
	var errs []error
	if pg.Spec.Type != tsapi.ProxyGroupTypeIngress {
		errs = append(errs, fmt.Errorf("ProxyGroup %q is of type %q but must be of type %q",
			pg.Name, pg.Spec.Type, tsapi.ProxyGroupTypeIngress))
	}
	if violations := validateService(svc); len(violations) > 0 {
		errs = append(errs, fmt.Errorf("invalid Service: %s", strings.Join(violations, ", ")))
	}
	svcList := &corev1.ServiceList{}
	if err := r.List(ctx, svcList); err != nil {
		errs = append(errs, fmt.Errorf("[unexpected] error listing Services: %w", err))
		return errors.Join(errs...)
	}
	svcName := nameForService(svc)
	for _, s := range svcList.Items {
		if r.shouldExpose(&s) && nameForService(&s) == svcName && s.UID != svc.UID {
			errs = append(errs, fmt.Errorf("found duplicate Service %q for hostname %q - multiple HA Services for the same hostname in the same cluster are not allowed", client.ObjectKeyFromObject(&s), svcName))
		}
	}
	return errors.Join(errs...)
}
