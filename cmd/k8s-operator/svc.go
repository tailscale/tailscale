// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

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
	if !svc.DeletionTimestamp.IsZero() || !a.shouldExpose(svc) {
		logger.Debugf("service is being deleted or should not be exposed, cleaning up")
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
	crl := childResourceLabels(svc.Name, svc.Namespace, "svc")
	var tags []string
	if tstr, ok := svc.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}

	sts := &tailscaleSTSConfig{
		ParentResourceName:  svc.Name,
		ParentResourceUID:   string(svc.UID),
		TargetIP:            svc.Spec.ClusterIP,
		Hostname:            hostname,
		Tags:                tags,
		ChildResourceLabels: crl,
	}

	if err := a.ssr.Provision(ctx, logger, sts); err != nil {
		return fmt.Errorf("failed to provision: %w", err)
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
	for _, ip := range tsIPs {
		ingress = append(ingress, corev1.LoadBalancerIngress{IP: ip})
	}
	svc.Status.LoadBalancer.Ingress = ingress
	if err := a.Status().Update(ctx, svc); err != nil {
		return fmt.Errorf("failed to update service status: %w", err)
	}
	return nil
}

func (a *ServiceReconciler) shouldExpose(svc *corev1.Service) bool {
	// Headless services can't be exposed, since there is no ClusterIP to
	// forward to.
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return false
	}

	return a.hasLoadBalancerClass(svc) || a.hasAnnotation(svc)
}

func (a *ServiceReconciler) hasLoadBalancerClass(svc *corev1.Service) bool {
	return svc != nil &&
		svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		(svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass == "tailscale" ||
			svc.Spec.LoadBalancerClass == nil && a.isDefaultLoadBalancer)
}

func (a *ServiceReconciler) hasAnnotation(svc *corev1.Service) bool {
	return svc != nil &&
		svc.Annotations[AnnotationExpose] == "true"
}
