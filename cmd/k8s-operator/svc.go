// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	reasonInvalidTailscaleService = "InvalidTailscaleService"
	conditionTailscaleStatus      = "TailscaleStatus"
)

// Clock is defined as a package var so it can be stubbed out during tests.
var Clock clock.Clock = clock.RealClock{}

type ServiceReconciler struct {
	client.Client
	ssr                   *tailscaleSTSReconciler
	logger                *zap.SugaredLogger
	isDefaultLoadBalancer bool
}

func childResourceLabels(name, ns, typ string) map[string]string {
	// You might wonder why we're using owner references, since they seem to be
	// built for exactly this. Unfortunately, Kubernetes does not support
	// cross-namespace ownership, by design. This means we cannot make the
	// service being exposed the owner of the implementation details of the
	// proxying. Instead, we have to do our own filtering and tracking with
	// labels.
	return map[string]string{
		LabelManaged:         "true",
		LabelParentName:      name,
		LabelParentNamespace: ns,
		LabelParentType:      typ,
	}
}

func (a *ServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := a.logger.With("service-ns", req.Namespace, "service-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	svc := new(corev1.Service)
	err = a.Get(ctx, req.NamespacedName, svc)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("service not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get svc: %w", err)
	}
	if !svc.DeletionTimestamp.IsZero() || !a.shouldExpose(svc) && !a.hasTailnetTargetAnnotation(svc) {
		logger.Debugf("service is being deleted or is (no longer) referring to Tailscale ingress/egress, ensuring any created resources are cleaned up")
		return reconcile.Result{}, a.maybeCleanup(ctx, logger, svc)
	}

	return reconcile.Result{}, a.maybeProvision(ctx, logger, svc)
}

// maybeCleanup removes any existing resources related to serving svc over tailscale.
//
// This function is responsible for removing the finalizer from the service,
// once all associated resources are gone.
func (a *ServiceReconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) error {
	ix := slices.Index(svc.Finalizers, FinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		return nil
	}

	if done, err := a.ssr.Cleanup(ctx, logger, childResourceLabels(svc.Name, svc.Namespace, "svc")); err != nil {
		return fmt.Errorf("failed to cleanup: %w", err)
	} else if !done {
		logger.Debugf("cleanup not done yet, waiting for next reconcile")
		return nil
	}

	svc.Finalizers = append(svc.Finalizers[:ix], svc.Finalizers[ix+1:]...)

	if err := a.Update(ctx, svc); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	removeTailscaleCondition(svc, logger)
	if err := a.Status().Update(ctx, svc); err != nil {
		return fmt.Errorf("failed to remove Tailscale condition: %w", err)
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("unexposed service from tailnet")
	return nil
}

// maybeProvision ensures that svc is exposed over tailscale, taking any actions
// necessary to reach that state.
//
// This function adds a finalizer to svc, ensuring that we can handle orderly
// deprovisioning later.
func (a *ServiceReconciler) maybeProvision(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) error {
	hostname, err := nameForService(svc)
	if err != nil {
		return err
	}

	if !slices.Contains(svc.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("exposing service over tailscale")
		svc.Finalizers = append(svc.Finalizers, FinalizerName)
		if err := a.Update(ctx, svc); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	isInvalid, msg := a.isInvalid(svc)
	if isInvalid {
		logger.Infof("Service is an invalid Tailscale proxy Service: %s", msg)

		// TODO (irbekrm): Service status conditions update should be a deferred
		// function -we want to ensure that status gets updated
		// correctly in both success and failure cases
		oldSvc := svc.DeepCopy()
		setServiceCondition(svc, metav1.ConditionFalse, conditionTailscaleStatus, reasonInvalidTailscaleService, msg)

		if !apiequality.Semantic.DeepEqual(oldSvc.Status, svc.Status) {
			logger.Info("udpating Service status")
			if err := a.Status().Update(ctx, svc); err != nil {
				logger.Errorf("Failed to update Service status: %v", err)
				return err
			}
		}
		// we will reconcile the Service when the user fixes it
		return nil
	}

	crl := childResourceLabels(svc.Name, svc.Namespace, "svc")
	var tags []string
	if tstr, ok := svc.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}

	sts := &tailscaleSTSConfig{
		ParentResourceName:  svc.Name,
		ParentResourceUID:   string(svc.UID),
		ClusterTargetIP:     svc.Spec.ClusterIP,
		Hostname:            hostname,
		Tags:                tags,
		ChildResourceLabels: crl,
		TailnetTargetIP:     svc.Annotations[AnnotationTailnetTargetIP],
	}

	var hsvc *corev1.Service
	if hsvc, err = a.ssr.Provision(ctx, logger, sts); err != nil {
		return fmt.Errorf("failed to provision: %w", err)
	}

	if a.hasTailnetTargetAnnotation(svc) {
		headlessSvcName := hsvc.Name + "." + hsvc.Namespace + ".svc"
		if svc.Spec.ExternalName != headlessSvcName || svc.Spec.Type != corev1.ServiceTypeExternalName {
			svc.Spec.ExternalName = headlessSvcName
			svc.Spec.Selector = nil
			svc.Spec.Type = corev1.ServiceTypeExternalName
			if err := a.Update(ctx, svc); err != nil {
				return fmt.Errorf("failed to update service: %w", err)
			}
		}
		return nil
	}

	if !a.hasLoadBalancerClass(svc) {
		logger.Debugf("service is not a LoadBalancer, so not updating ingress")
		return nil
	}

	_, tsHost, tsIPs, err := a.ssr.DeviceInfo(ctx, crl)
	if err != nil {
		return fmt.Errorf("failed to get device ID: %w", err)
	}
	if tsHost == "" {
		logger.Debugf("no Tailscale hostname known yet, waiting for proxy pod to finish auth")
		// No hostname yet. Wait for the proxy pod to auth.
		svc.Status.LoadBalancer.Ingress = nil
		if err := a.Status().Update(ctx, svc); err != nil {
			return fmt.Errorf("failed to update service status: %w", err)
		}
		return nil
	}

	logger.Debugf("setting ingress to %q, %s", tsHost, strings.Join(tsIPs, ", "))
	ingress := []corev1.LoadBalancerIngress{
		{Hostname: tsHost},
	}
	clusterIPAddr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		return fmt.Errorf("failed to parse cluster IP: %w", err)
	}
	for _, ip := range tsIPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if addr.Is4() == clusterIPAddr.Is4() { // only add addresses of the same family
			ingress = append(ingress, corev1.LoadBalancerIngress{IP: ip})
		}
	}
	svc.Status.LoadBalancer.Ingress = ingress
	if err := a.Status().Update(ctx, svc); err != nil {
		return fmt.Errorf("failed to update service status: %w", err)
	}

	return nil
}

// hasViolations reports whether the given Service represents an invalid
// Tailscale egress/ingress service. Also returns a message describing the first
// found violation.
func (a *ServiceReconciler) isInvalid(svc *corev1.Service) (isInvalid bool, msg string) {
	if !a.shouldExpose(svc) && !a.hasTailnetTargetAnnotation(svc) {
		return false, ""
	}
	if a.hasTailnetTargetAnnotation(svc) && a.hasLoadBalancerClass(svc) {
		return true, "Service has both tailscale.com/tailnet-target-ip annotation and tailscale load balancer class set."
	}
	if a.hasTailnetTargetAnnotation(svc) && a.hasExposeAnnotation(svc) {
		return true, "Service has both tailscale.com/tailnet-target-ip and tailscale.com/expose annotation set."
	}
	if a.hasTailnetTargetAnnotation(svc) {
		if svc.Spec.Type != corev1.ServiceTypeExternalName {
			return true, fmt.Sprintf("Service has tailscale.com/tailnet-target-ip annotation, but service type is %s. Only Services of type External Name can be used.", svc.Spec.Type)
		}
		if a.hasTailnetTargetAnnotation(svc) && len(svc.Spec.Ports) > 0 {
			return true, "Service has tailscale.com/tailnet-target-ip annotation, and has ports defined. Ports are not allowed."
		}
		if a.hasTailnetTargetAnnotation(svc) && len(svc.Spec.Ports) > 0 {
			return true, "Service has tailscale.com/tailnet-target-ip annotation, and has ports defined. Ports are not allowed."
		}
		if a.hasLoadBalancerClass(svc) && svc.Spec.Selector != nil {
			return true, "Service has tailscale.com/tailnet-target-ip annotation, and has ports defined. Selector is not allowed."
		}

	}
	return false, ""
}

func (a *ServiceReconciler) shouldExpose(svc *corev1.Service) bool {
	// Headless services can't be exposed, since there is no ClusterIP to
	// forward to.
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return false
	}

	return a.hasLoadBalancerClass(svc) || a.hasExposeAnnotation(svc)
}

func (a *ServiceReconciler) hasLoadBalancerClass(svc *corev1.Service) bool {
	return svc != nil &&
		svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		(svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass == "tailscale" ||
			svc.Spec.LoadBalancerClass == nil && a.isDefaultLoadBalancer)
}

// hasExposeAnnotation reports whether Service has the tailscale.com/expose
// annotation set
func (a *ServiceReconciler) hasExposeAnnotation(svc *corev1.Service) bool {
	return svc != nil && svc.Annotations[AnnotationExpose] == "true"
}

// hasTailnetTargetAnnotation reports whether Service has a
// tailscale.com/ts-tailnet-target-ip annotation set
func (a *ServiceReconciler) hasTailnetTargetAnnotation(svc *corev1.Service) bool {
	return svc != nil && svc.Annotations[AnnotationTailnetTargetIP] != ""
}

// conditon-related logic inspired by
// https://github.com/cert-manager/cert-manager/blob/v1.12.3/pkg/api/util/conditions.go
func setServiceCondition(svc *corev1.Service, status metav1.ConditionStatus, typ, reason, msg string) {
	newCond := metav1.Condition{
		Type:    typ,
		Status:  status,
		Reason:  reason,
		Message: msg,
	}
	nowTime := metav1.NewTime(Clock.Now())
	newCond.LastTransitionTime = nowTime

	for idx, cond := range svc.Status.Conditions {
		if cond.Type != typ {
			continue
		}
		if cond.Status == status {
			newCond.LastTransitionTime = cond.LastTransitionTime
		}
		svc.Status.Conditions[idx] = newCond
		return
	}
	svc.Status.Conditions = append(svc.Status.Conditions, newCond)
}

func removeTailscaleCondition(svc *corev1.Service, logger *zap.SugaredLogger) {
	newConds := make([]metav1.Condition, 0)
	for _, cond := range svc.Status.Conditions {
		if cond.Type == conditionTailscaleStatus {
			logger.Info("removing %s condition from Service", conditionTailscaleStatus)
			continue
		}
		newConds = append(newConds, cond)
	}
	svc.Status.Conditions = newConds
}
