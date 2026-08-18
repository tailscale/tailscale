// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

const (
	reasonProxyCreated = "ProxyCreated"
	reasonProxyInvalid = "ProxyInvalid"
	reasonProxyFailed  = "ProxyFailed"
	reasonProxyPending = "ProxyPending"
)

type ServiceReconciler struct {
	client.Client
	ssr                   *tailscaleSTSReconciler
	logger                *zap.SugaredLogger
	isDefaultLoadBalancer bool

	mu sync.Mutex // protects following

	// managedIngressProxies is a set of all ingress proxies that we're
	// currently managing. This is only used for metrics.
	managedIngressProxies set.Slice[types.UID]
	// managedEgressProxies is a set of all egress proxies that we're currently
	// managing. This is only used for metrics.
	managedEgressProxies set.Slice[types.UID]

	recorder record.EventRecorder

	tsNamespace string

	clock tstime.Clock

	defaultProxyClass string
}

var (
	// gaugeEgressProxies tracks the number of egress proxies that we're
	// currently managing.
	gaugeEgressProxies = clientmetric.NewGauge(kubetypes.MetricEgressProxyCount)
	// gaugeIngressProxies tracks the number of ingress proxies that we're
	// currently managing.
	gaugeIngressProxies = clientmetric.NewGauge(kubetypes.MetricIngressProxyCount)
)

func childResourceLabels(name, ns, typ string) map[string]string {
	// You might wonder why we're using owner references, since they seem to be
	// built for exactly this. Unfortunately, Kubernetes does not support
	// cross-namespace ownership, by design. This means we cannot make the
	// service being exposed the owner of the implementation details of the
	// proxying. Instead, we have to do our own filtering and tracking with
	// labels.
	return map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentName:        name,
		LabelParentNamespace:   ns,
		LabelParentType:        typ,
	}
}

func (a *ServiceReconciler) isTailscaleService(svc *corev1.Service) bool {
	targetIP := tailnetTargetAnnotation(svc)
	targetFQDN := svc.Annotations[AnnotationTailnetTargetFQDN]
	return shouldExpose(svc, a.isDefaultLoadBalancer) || targetIP != "" || targetFQDN != ""
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

	if _, ok := svc.Annotations[AnnotationProxyGroup]; ok {
		return reconcile.Result{}, nil // this reconciler should not look at Services for ProxyGroup
	}

	if !svc.DeletionTimestamp.IsZero() || !a.isTailscaleService(svc) {
		logger.Debugf("service is being deleted or is (no longer) referring to Tailscale ingress/egress, ensuring any created resources are cleaned up")
		return reconcile.Result{}, a.maybeCleanup(ctx, logger, svc)
	}

	if err := a.maybeProvision(ctx, logger, svc); err != nil {
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			logger.Infof("optimistic lock error, retrying: %s", err)
		} else {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// maybeCleanup removes any existing resources related to serving svc over tailscale.
//
// This function is responsible for removing the finalizer from the service,
// once all associated resources are gone.
func (a *ServiceReconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) (err error) {
	oldSvcStatus := svc.Status.DeepCopy()
	defer func() {
		if !apiequality.Semantic.DeepEqual(oldSvcStatus, &svc.Status) {
			// An error encountered here should get returned by the Reconcile function.
			err = errors.Join(err, a.Client.Status().Update(ctx, svc))
		}
	}()
	ix := slices.Index(svc.Finalizers, FinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		a.mu.Lock()
		defer a.mu.Unlock()
		a.managedIngressProxies.Remove(svc.UID)
		a.managedEgressProxies.Remove(svc.UID)
		gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
		gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))

		if !a.isTailscaleService(svc) {
			reconciler.RemoveServiceCondition(svc, tsapi.ProxyReady)
		}
		return nil
	}

	proxyTyp := proxyTypeEgress
	if shouldExpose(svc, a.isDefaultLoadBalancer) {
		proxyTyp = proxyTypeIngressService
	}

	if done, err := a.ssr.Cleanup(ctx, operatorTailnet, logger, childResourceLabels(svc.Name, svc.Namespace, "svc"), proxyTyp); err != nil {
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
	logger.Infof("unexposed Service from tailnet")

	a.mu.Lock()
	defer a.mu.Unlock()
	a.managedIngressProxies.Remove(svc.UID)
	a.managedEgressProxies.Remove(svc.UID)
	gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
	gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))

	if !a.isTailscaleService(svc) {
		reconciler.RemoveServiceCondition(svc, tsapi.ProxyReady)
	}
	return nil
}

// maybeProvision ensures that svc is exposed over tailscale, taking any actions
// necessary to reach that state.
//
// This function adds a finalizer to svc, ensuring that we can handle orderly
// deprovisioning later.
func (a *ServiceReconciler) maybeProvision(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) (err error) {
	oldSvcStatus := svc.Status.DeepCopy()
	defer func() {
		if !apiequality.Semantic.DeepEqual(oldSvcStatus, &svc.Status) {
			// An error encountered here should get returned by the Reconcile function.
			err = errors.Join(err, a.Client.Status().Update(ctx, svc))
		}
	}()

	// Run for proxy config related validations here as opposed to running
	// them earlier. This is to prevent cleanup being blocked on a
	// misconfigured proxy param.
	if err := a.ssr.validate(); err != nil {
		msg := fmt.Sprintf("unable to provision proxy resources: invalid config: %v", err)
		a.recorder.Event(svc, corev1.EventTypeWarning, "INVALIDCONFIG", msg)
		a.logger.Error(msg)
		reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyInvalid, msg, a.clock, logger)
		return nil
	}
	if violations := reconciler.ValidateService(svc); len(violations) > 0 {
		msg := fmt.Sprintf("unable to provision proxy resources: invalid Service: %s", strings.Join(violations, ", "))
		a.recorder.Event(svc, corev1.EventTypeWarning, "INVALIDSERVICE", msg)
		a.logger.Error(msg)
		reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyInvalid, msg, a.clock, logger)
		return nil
	}

	proxyClass := proxyClassForObject(svc, a.defaultProxyClass)
	if proxyClass != "" {
		if ready, err := proxyClassIsReady(ctx, proxyClass, a.Client); err != nil {
			errMsg := fmt.Errorf("error verifying ProxyClass for Service: %w", err)
			reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, errMsg.Error(), a.clock, logger)
			return errMsg
		} else if !ready {
			msg := fmt.Sprintf("ProxyClass %s specified for the Service, but is not (yet) Ready, waiting..", proxyClass)
			reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyPending, msg, a.clock, logger)
			logger.Info(msg)
			return nil
		}
	}

	if !slices.Contains(svc.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("exposing service over tailscale")
		svc.Finalizers = append(svc.Finalizers, FinalizerName)
		if err := a.Update(ctx, svc); err != nil {
			errMsg := fmt.Errorf("failed to add finalizer: %w", err)
			reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, errMsg.Error(), a.clock, logger)
			return errMsg
		}
	}
	crl := childResourceLabels(svc.Name, svc.Namespace, "svc")
	var tags []string
	if tstr, ok := svc.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}

	sts := &tailscaleSTSConfig{
		Replicas:            1,
		ParentResourceName:  svc.Name,
		ParentResourceUID:   string(svc.UID),
		Hostname:            reconciler.NameForService(svc),
		Tags:                tags,
		ChildResourceLabels: crl,
		ProxyClassName:      proxyClass,
		LoginServer:         a.ssr.loginServer,
	}
	sts.proxyType = proxyTypeEgress
	if shouldExpose(svc, a.isDefaultLoadBalancer) {
		sts.proxyType = proxyTypeIngressService
	}

	a.mu.Lock()
	if shouldExposeClusterIP(svc, a.isDefaultLoadBalancer) {
		sts.ClusterTargetIP = svc.Spec.ClusterIP
		a.managedIngressProxies.Add(svc.UID)
		gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
	} else if shouldExposeDNSName(svc) {
		sts.ClusterTargetDNSName = svc.Spec.ExternalName
		a.managedIngressProxies.Add(svc.UID)
		gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
	} else if ip := tailnetTargetAnnotation(svc); ip != "" {
		sts.TailnetTargetIP = ip
		a.managedEgressProxies.Add(svc.UID)
		gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))
	} else if fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]; fqdn != "" {
		fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]
		if !strings.HasSuffix(fqdn, ".") {
			fqdn = fqdn + "."
		}
		sts.TailnetTargetFQDN = fqdn
		a.managedEgressProxies.Add(svc.UID)
		gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))
	}
	a.mu.Unlock()

	var hsvc *corev1.Service
	if hsvc, err = a.ssr.Provision(ctx, logger, sts); err != nil {
		errMsg := fmt.Errorf("failed to provision: %w", err)
		reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, errMsg.Error(), a.clock, logger)
		return errMsg
	}

	if sts.TailnetTargetIP != "" || sts.TailnetTargetFQDN != "" { // if an egress proxy
		clusterDomain := reconciler.ClusterDomain(a.tsNamespace, logger)
		headlessSvcName := hsvc.Name + "." + hsvc.Namespace + ".svc." + clusterDomain
		if svc.Spec.ExternalName != headlessSvcName || svc.Spec.Type != corev1.ServiceTypeExternalName {
			svc.Spec.ExternalName = headlessSvcName
			svc.Spec.Selector = nil
			svc.Spec.Type = corev1.ServiceTypeExternalName
			if err := a.Update(ctx, svc); err != nil {
				errMsg := fmt.Errorf("failed to update service: %w", err)
				reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, errMsg.Error(), a.clock, logger)
				return errMsg
			}
		}
		reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionTrue, reasonProxyCreated, reasonProxyCreated, a.clock, logger)
		return nil
	}

	if !isTailscaleLoadBalancerService(svc, a.isDefaultLoadBalancer) {
		logger.Debugf("service is not a LoadBalancer, so not updating ingress")
		reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionTrue, reasonProxyCreated, reasonProxyCreated, a.clock, logger)
		return nil
	}

	devices, err := a.ssr.DeviceInfo(ctx, crl, logger)
	if err != nil {
		return fmt.Errorf("failed to get device ID: %w", err)
	}

	if len(devices) == 0 || devices[0].hostname == "" {
		msg := "no Tailscale hostname known yet, waiting for proxy pod to finish auth"
		logger.Debug(msg)
		// No hostname yet. Wait for the proxy pod to auth.
		svc.Status.LoadBalancer.Ingress = nil
		reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyPending, msg, a.clock, logger)
		return nil
	}

	dev := devices[0]
	logger.Debugf("setting Service LoadBalancer status to %q, %s", dev.hostname, strings.Join(dev.ips, ", "))

	ingress := []corev1.LoadBalancerIngress{
		{Hostname: dev.hostname},
	}

	clusterIPAddr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		msg := fmt.Sprintf("failed to parse cluster IP: %v", err)
		reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, msg, a.clock, logger)
		return errors.New(msg)
	}

	for _, ip := range dev.ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if addr.Is4() == clusterIPAddr.Is4() { // only add addresses of the same family
			ingress = append(ingress, corev1.LoadBalancerIngress{IP: ip})
		}
	}

	svc.Status.LoadBalancer.Ingress = ingress
	reconciler.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionTrue, reasonProxyCreated, reasonProxyCreated, a.clock, logger)
	return nil
}

func shouldExpose(svc *corev1.Service, isDefaultLoadBalancer bool) bool {
	return shouldExposeClusterIP(svc, isDefaultLoadBalancer) || shouldExposeDNSName(svc)
}

func shouldExposeDNSName(svc *corev1.Service) bool {
	return hasExposeAnnotation(svc) && svc.Spec.Type == corev1.ServiceTypeExternalName && svc.Spec.ExternalName != ""
}

func shouldExposeClusterIP(svc *corev1.Service, isDefaultLoadBalancer bool) bool {
	if svc.Spec.ClusterIP == "" {
		return false
	}
	return isTailscaleLoadBalancerService(svc, isDefaultLoadBalancer) || hasExposeAnnotation(svc)
}

func isTailscaleLoadBalancerService(svc *corev1.Service, isDefaultLoadBalancer bool) bool {
	return svc != nil &&
		svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		(svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass == "tailscale" ||
			svc.Spec.LoadBalancerClass == nil && isDefaultLoadBalancer)
}

// hasExposeAnnotation reports whether Service has the tailscale.com/expose
// annotation set
func hasExposeAnnotation(svc *corev1.Service) bool {
	return svc != nil && svc.Annotations[AnnotationExpose] == "true"
}

// tailnetTargetAnnotation returns the value of tailscale.com/tailnet-ip
// annotation or of the deprecated tailscale.com/ts-tailnet-target-ip
// annotation. If neither is set, it returns an empty string. If both are set,
// it returns the value of the new annotation.
func tailnetTargetAnnotation(svc *corev1.Service) string {
	if svc == nil {
		return ""
	}
	if ip := svc.Annotations[AnnotationTailnetTargetIP]; ip != "" {
		return ip
	}
	return svc.Annotations[annotationTailnetTargetIPOld]
}

func proxyClassIsReady(ctx context.Context, name string, cl client.Client) (bool, error) {
	proxyClass := new(tsapi.ProxyClass)
	if err := cl.Get(ctx, types.NamespacedName{Name: name}, proxyClass); err != nil {
		return false, fmt.Errorf("error getting ProxyClass %s: %w", name, err)
	}
	return reconciler.ProxyClassIsReady(proxyClass), nil
}
