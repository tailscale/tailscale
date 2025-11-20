// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/internal/client/tailscale"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
)

const (
	proxyPGFinalizerName = "tailscale.com/kube-apiserver-finalizer"

	// Reasons for KubeAPIServerProxyValid condition.
	reasonKubeAPIServerProxyInvalid = "KubeAPIServerProxyInvalid"
	reasonKubeAPIServerProxyValid   = "KubeAPIServerProxyValid"

	// Reasons for KubeAPIServerProxyConfigured condition.
	reasonKubeAPIServerProxyConfigured = "KubeAPIServerProxyConfigured"
	reasonKubeAPIServerProxyNoBackends = "KubeAPIServerProxyNoBackends"
)

// KubeAPIServerTSServiceReconciler reconciles the Tailscale Services required for an
// HA deployment of the API Server Proxy.
type KubeAPIServerTSServiceReconciler struct {
	client.Client
	recorder    record.EventRecorder
	logger      *zap.SugaredLogger
	tsClient    tsClient
	tsNamespace string
	lc          localClient
	defaultTags []string
	operatorID  string // stableID of the operator's Tailscale device

	clock tstime.Clock
}

// Reconcile is the entry point for the controller.
func (r *KubeAPIServerTSServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := r.logger.With("ProxyGroup", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	pg := new(tsapi.ProxyGroup)
	err = r.Get(ctx, req.NamespacedName, pg)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("ProxyGroup not found, assuming it was deleted")
		return res, nil
	} else if err != nil {
		return res, fmt.Errorf("failed to get ProxyGroup: %w", err)
	}

	serviceName := serviceNameForAPIServerProxy(pg)
	logger = logger.With("Tailscale Service", serviceName)

	if markedForDeletion(pg) {
		logger.Debugf("ProxyGroup is being deleted, ensuring any created resources are cleaned up")
		if err = r.maybeCleanup(ctx, serviceName, pg, logger); err != nil && strings.Contains(err.Error(), optimisticLockErrorMsg) {
			logger.Infof("optimistic lock error, retrying: %s", err)
			return res, nil
		}

		return res, err
	}

	err = r.maybeProvision(ctx, serviceName, pg, logger)
	if err != nil {
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			logger.Infof("optimistic lock error, retrying: %s", err)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// maybeProvision ensures that a Tailscale Service for this ProxyGroup exists
// and is up to date.
//
// Returns true if the operation resulted in a Tailscale Service update.
func (r *KubeAPIServerTSServiceReconciler) maybeProvision(ctx context.Context, serviceName tailcfg.ServiceName, pg *tsapi.ProxyGroup, logger *zap.SugaredLogger) (err error) {
	var dnsName string
	oldPGStatus := pg.Status.DeepCopy()
	defer func() {
		podsAdvertising, podsErr := numberPodsAdvertising(ctx, r.Client, r.tsNamespace, pg.Name, serviceName)
		if podsErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to get number of advertised Pods: %w", podsErr))
			// Continue, updating the status with the best available information.
		}

		// Update the ProxyGroup status with the Tailscale Service information
		// Update the condition based on how many pods are advertising the service
		conditionStatus := metav1.ConditionFalse
		conditionReason := reasonKubeAPIServerProxyNoBackends
		conditionMessage := fmt.Sprintf("%d/%d proxy backends ready and advertising", podsAdvertising, pgReplicas(pg))

		pg.Status.URL = ""
		if podsAdvertising > 0 {
			// At least one pod is advertising the service, consider it configured
			conditionStatus = metav1.ConditionTrue
			conditionReason = reasonKubeAPIServerProxyConfigured
			if dnsName != "" {
				pg.Status.URL = "https://" + dnsName
			}
		}

		tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyConfigured, conditionStatus, conditionReason, conditionMessage, pg.Generation, r.clock, logger)

		if !apiequality.Semantic.DeepEqual(oldPGStatus, &pg.Status) {
			// An error encountered here should get returned by the Reconcile function.
			err = errors.Join(err, r.Client.Status().Update(ctx, pg))
		}
	}()

	if !tsoperator.ProxyGroupAvailable(pg) {
		return nil
	}

	if !slices.Contains(pg.Finalizers, proxyPGFinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Info("provisioning Tailscale Service for ProxyGroup")
		pg.Finalizers = append(pg.Finalizers, proxyPGFinalizerName)
		if err := r.Update(ctx, pg); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// 1. Check there isn't a Tailscale Service with the same hostname
	// already created and not owned by this ProxyGroup.
	existingTSSvc, err := r.tsClient.GetVIPService(ctx, serviceName)
	if err != nil && !isErrorTailscaleServiceNotFound(err) {
		return fmt.Errorf("error getting Tailscale Service %q: %w", serviceName, err)
	}

	updatedAnnotations, err := exclusiveOwnerAnnotations(pg, r.operatorID, existingTSSvc)
	if err != nil {
		const instr = "To proceed, you can either manually delete the existing Tailscale Service or choose a different Service name in the ProxyGroup's spec.kubeAPIServer.serviceName field"
		msg := fmt.Sprintf("error ensuring exclusive ownership of Tailscale Service %s: %v. %s", serviceName, err, instr)
		logger.Warn(msg)
		r.recorder.Event(pg, corev1.EventTypeWarning, "InvalidTailscaleService", msg)
		tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyValid, metav1.ConditionFalse, reasonKubeAPIServerProxyInvalid, msg, pg.Generation, r.clock, logger)
		return nil
	}

	// After getting this far, we know the Tailscale Service is valid.
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyValid, metav1.ConditionTrue, reasonKubeAPIServerProxyValid, reasonKubeAPIServerProxyValid, pg.Generation, r.clock, logger)

	// Service tags are limited to matching the ProxyGroup's tags until we have
	// support for querying peer caps for a Service-bound request.
	serviceTags := r.defaultTags
	if len(pg.Spec.Tags) > 0 {
		serviceTags = pg.Spec.Tags.Stringify()
	}

	tsSvc := &tailscale.VIPService{
		Name:        serviceName,
		Tags:        serviceTags,
		Ports:       []string{"tcp:443"},
		Comment:     managedTSServiceComment,
		Annotations: updatedAnnotations,
	}
	if existingTSSvc != nil {
		tsSvc.Addrs = existingTSSvc.Addrs
	}

	// 2. Ensure the Tailscale Service exists and is up to date.
	if existingTSSvc == nil ||
		!slices.Equal(tsSvc.Tags, existingTSSvc.Tags) ||
		!ownersAreSetAndEqual(tsSvc, existingTSSvc) ||
		!slices.Equal(tsSvc.Ports, existingTSSvc.Ports) {
		logger.Infof("Ensuring Tailscale Service exists and is up to date")
		if err := r.tsClient.CreateOrUpdateVIPService(ctx, tsSvc); err != nil {
			return fmt.Errorf("error creating Tailscale Service: %w", err)
		}
	}

	// 3. Ensure that TLS Secret and RBAC exists.
	tcd, err := tailnetCertDomain(ctx, r.lc)
	if err != nil {
		return fmt.Errorf("error determining DNS name base: %w", err)
	}
	dnsName = serviceName.WithoutPrefix() + "." + tcd
	if err = r.ensureCertResources(ctx, pg, dnsName); err != nil {
		return fmt.Errorf("error ensuring cert resources: %w", err)
	}

	// 4. Configure the Pods to advertise the Tailscale Service.
	if err = r.maybeAdvertiseServices(ctx, pg, serviceName, logger); err != nil {
		return fmt.Errorf("error updating advertised Tailscale Services: %w", err)
	}

	// 5. Clean up any stale Tailscale Services from previous resource versions.
	if err = r.maybeDeleteStaleServices(ctx, pg, logger); err != nil {
		return fmt.Errorf("failed to delete stale Tailscale Services: %w", err)
	}

	return nil
}

// maybeCleanup ensures that any resources, such as a Tailscale Service created for this Service, are cleaned up when the
// Service is being deleted or is unexposed. The cleanup is safe for a multi-cluster setup- the Tailscale Service is only
// deleted if it does not contain any other owner references. If it does, the cleanup only removes the owner reference
// corresponding to this Service.
func (r *KubeAPIServerTSServiceReconciler) maybeCleanup(ctx context.Context, serviceName tailcfg.ServiceName, pg *tsapi.ProxyGroup, logger *zap.SugaredLogger) (err error) {
	ix := slices.Index(pg.Finalizers, proxyPGFinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		return nil
	}
	logger.Infof("Ensuring that Service %q is cleaned up", serviceName)

	defer func() {
		if err == nil {
			err = r.deleteFinalizer(ctx, pg, logger)
		}
	}()

	if _, err = cleanupTailscaleService(ctx, r.tsClient, serviceName, r.operatorID, logger); err != nil {
		return fmt.Errorf("error deleting Tailscale Service: %w", err)
	}

	if err = cleanupCertResources(ctx, r.Client, r.lc, r.tsNamespace, pg.Name, serviceName); err != nil {
		return fmt.Errorf("failed to clean up cert resources: %w", err)
	}

	return nil
}

// maybeDeleteStaleServices deletes Services that have previously been created for
// this ProxyGroup but are no longer needed.
func (r *KubeAPIServerTSServiceReconciler) maybeDeleteStaleServices(ctx context.Context, pg *tsapi.ProxyGroup, logger *zap.SugaredLogger) error {
	serviceName := serviceNameForAPIServerProxy(pg)

	svcs, err := r.tsClient.ListVIPServices(ctx)
	if err != nil {
		return fmt.Errorf("error listing Tailscale Services: %w", err)
	}

	for _, svc := range svcs.VIPServices {
		if svc.Name == serviceName {
			continue
		}

		owners, err := parseOwnerAnnotation(&svc)
		if err != nil {
			logger.Warnf("error parsing owner annotation for Tailscale Service %s: %v", svc.Name, err)
			continue
		}
		if owners == nil || len(owners.OwnerRefs) != 1 || owners.OwnerRefs[0].OperatorID != r.operatorID {
			continue
		}

		owner := owners.OwnerRefs[0]
		if owner.Resource == nil || owner.Resource.Kind != "ProxyGroup" || owner.Resource.UID != string(pg.UID) {
			continue
		}

		logger.Infof("Deleting Tailscale Service %s", svc.Name)
		if err := r.tsClient.DeleteVIPService(ctx, svc.Name); err != nil && !isErrorTailscaleServiceNotFound(err) {
			return fmt.Errorf("error deleting Tailscale Service %s: %w", svc.Name, err)
		}

		if err = cleanupCertResources(ctx, r.Client, r.lc, r.tsNamespace, pg.Name, svc.Name); err != nil {
			return fmt.Errorf("failed to clean up cert resources: %w", err)
		}
	}

	return nil
}

func (r *KubeAPIServerTSServiceReconciler) deleteFinalizer(ctx context.Context, pg *tsapi.ProxyGroup, logger *zap.SugaredLogger) error {
	pg.Finalizers = slices.DeleteFunc(pg.Finalizers, func(f string) bool {
		return f == proxyPGFinalizerName
	})
	logger.Debugf("ensure %q finalizer is removed", proxyPGFinalizerName)

	if err := r.Update(ctx, pg); err != nil {
		return fmt.Errorf("failed to remove finalizer %q: %w", proxyPGFinalizerName, err)
	}
	return nil
}

func (r *KubeAPIServerTSServiceReconciler) ensureCertResources(ctx context.Context, pg *tsapi.ProxyGroup, domain string) error {
	secret := certSecret(pg.Name, r.tsNamespace, domain, pg)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, secret, func(s *corev1.Secret) {
		s.Labels = secret.Labels
	}); err != nil {
		return fmt.Errorf("failed to create or update Secret %s: %w", secret.Name, err)
	}
	role := certSecretRole(pg.Name, r.tsNamespace, domain)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, role, func(r *rbacv1.Role) {
		r.Labels = role.Labels
		r.Rules = role.Rules
	}); err != nil {
		return fmt.Errorf("failed to create or update Role %s: %w", role.Name, err)
	}
	rolebinding := certSecretRoleBinding(pg, r.tsNamespace, domain)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, rolebinding, func(rb *rbacv1.RoleBinding) {
		rb.Labels = rolebinding.Labels
		rb.Subjects = rolebinding.Subjects
		rb.RoleRef = rolebinding.RoleRef
	}); err != nil {
		return fmt.Errorf("failed to create or update RoleBinding %s: %w", rolebinding.Name, err)
	}
	return nil
}

func (r *KubeAPIServerTSServiceReconciler) maybeAdvertiseServices(ctx context.Context, pg *tsapi.ProxyGroup, serviceName tailcfg.ServiceName, logger *zap.SugaredLogger) error {
	// Get all config Secrets for this ProxyGroup
	cfgSecrets := &corev1.SecretList{}
	if err := r.List(ctx, cfgSecrets, client.InNamespace(r.tsNamespace), client.MatchingLabels(pgSecretLabels(pg.Name, kubetypes.LabelSecretTypeConfig))); err != nil {
		return fmt.Errorf("failed to list config Secrets: %w", err)
	}

	// Only advertise a Tailscale Service once the TLS certs required for
	// serving it are available.
	shouldBeAdvertised, err := hasCerts(ctx, r.Client, r.lc, r.tsNamespace, serviceName)
	if err != nil {
		return fmt.Errorf("error checking TLS credentials provisioned for Tailscale Service %q: %w", serviceName, err)
	}
	var advertiseServices []string
	if shouldBeAdvertised {
		advertiseServices = []string{serviceName.String()}
	}

	for _, s := range cfgSecrets.Items {
		if len(s.Data[kubetypes.KubeAPIServerConfigFile]) == 0 {
			continue
		}

		// Parse the existing config.
		cfg, err := conf.Load(s.Data[kubetypes.KubeAPIServerConfigFile])
		if err != nil {
			return fmt.Errorf("error loading config from Secret %q: %w", s.Name, err)
		}

		if cfg.Parsed.APIServerProxy == nil {
			return fmt.Errorf("config Secret %q does not contain APIServerProxy config", s.Name)
		}

		existingCfgSecret := s.DeepCopy()

		var updated bool
		if cfg.Parsed.APIServerProxy.ServiceName == nil || *cfg.Parsed.APIServerProxy.ServiceName != serviceName {
			cfg.Parsed.APIServerProxy.ServiceName = &serviceName
			updated = true
		}

		// Update the services to advertise if required.
		if !slices.Equal(cfg.Parsed.AdvertiseServices, advertiseServices) {
			cfg.Parsed.AdvertiseServices = advertiseServices
			updated = true
		}

		if !updated {
			continue
		}

		// Update the config Secret.
		cfgB, err := json.Marshal(conf.VersionedConfig{
			Version:        "v1alpha1",
			ConfigV1Alpha1: &cfg.Parsed,
		})
		if err != nil {
			return err
		}

		s.Data[kubetypes.KubeAPIServerConfigFile] = cfgB
		if !apiequality.Semantic.DeepEqual(existingCfgSecret, s) {
			logger.Debugf("Updating the Tailscale Services in ProxyGroup config Secret %s", s.Name)
			if err := r.Update(ctx, &s); err != nil {
				return err
			}
		}
	}

	return nil
}

func serviceNameForAPIServerProxy(pg *tsapi.ProxyGroup) tailcfg.ServiceName {
	if pg.Spec.KubeAPIServer != nil && pg.Spec.KubeAPIServer.Hostname != "" {
		return tailcfg.ServiceName("svc:" + pg.Spec.KubeAPIServer.Hostname)
	}

	return tailcfg.ServiceName("svc:" + pg.Name)
}

// exclusiveOwnerAnnotations returns the updated annotations required to ensure this
// instance of the operator is the exclusive owner. If the Tailscale Service is not
// nil, but does not contain an owner reference we return an error as this likely means
// that the Service was created by something other than a Tailscale Kubernetes operator.
// We also error if it is already owned by another operator instance, as we do not
// want to load balance a kube-apiserver ProxyGroup across multiple clusters.
func exclusiveOwnerAnnotations(pg *tsapi.ProxyGroup, operatorID string, svc *tailscale.VIPService) (map[string]string, error) {
	ref := OwnerRef{
		OperatorID: operatorID,
		Resource: &Resource{
			Kind: "ProxyGroup",
			Name: pg.Name,
			UID:  string(pg.UID),
		},
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
	if len(o.OwnerRefs) > 1 || o.OwnerRefs[0].OperatorID != operatorID {
		return nil, fmt.Errorf("Tailscale Service %s is already owned by other operator(s) and cannot be shared across multiple clusters; configure a difference Service name to continue", svc.Name)
	}
	if o.OwnerRefs[0].Resource == nil {
		return nil, fmt.Errorf("Tailscale Service %s exists, but does not reference an owning resource; not proceeding as this is likely a Service already owned by an Ingress", svc.Name)
	}
	if o.OwnerRefs[0].Resource.Kind != "ProxyGroup" || o.OwnerRefs[0].Resource.UID != string(pg.UID) {
		return nil, fmt.Errorf("Tailscale Service %s is already owned by another resource: %#v; configure a difference Service name to continue", svc.Name, o.OwnerRefs[0].Resource)
	}
	if o.OwnerRefs[0].Resource.Name != pg.Name {
		// ProxyGroup name can be updated in place.
		o.OwnerRefs[0].Resource.Name = pg.Name
	}

	oBytes, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}

	newAnnots := make(map[string]string, len(svc.Annotations)+1)
	maps.Copy(newAnnots, svc.Annotations)
	newAnnots[ownerAnnotation] = string(oBytes)

	return newAnnots, nil
}
