// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/ipn"
	"tailscale.com/types/opt"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

type IngressReconciler struct {
	client.Client

	recorder record.EventRecorder
	ssr      *tailscaleSTSReconciler
	logger   *zap.SugaredLogger

	mu sync.Mutex // protects following

	// managedIngresses is a set of all ingress resources that we're currently
	// managing. This is only used for metrics.
	managedIngresses set.Slice[types.UID]
}

var (
	// gaugeIngressResources tracks the number of ingress resources that we're
	// currently managing.
	gaugeIngressResources = clientmetric.NewGauge("k8s_ingress_resources")
)

func (a *IngressReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := a.logger.With("ingress-ns", req.Namespace, "ingress-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	ing := new(networkingv1.Ingress)
	err = a.Get(ctx, req.NamespacedName, ing)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("ingress not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get ing: %w", err)
	}
	if !ing.DeletionTimestamp.IsZero() || !a.shouldExpose(ing) {
		logger.Debugf("ingress is being deleted or should not be exposed, cleaning up")
		return reconcile.Result{}, a.maybeCleanup(ctx, logger, ing)
	}

	return reconcile.Result{}, a.maybeProvision(ctx, logger, ing)
}

func (a *IngressReconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, ing *networkingv1.Ingress) error {
	ix := slices.Index(ing.Finalizers, FinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		a.mu.Lock()
		defer a.mu.Unlock()
		a.managedIngresses.Remove(ing.UID)
		gaugeIngressResources.Set(int64(a.managedIngresses.Len()))
		return nil
	}

	if done, err := a.ssr.Cleanup(ctx, logger, childResourceLabels(ing.Name, ing.Namespace, "ingress")); err != nil {
		return fmt.Errorf("failed to cleanup: %w", err)
	} else if !done {
		logger.Debugf("cleanup not done yet, waiting for next reconcile")
		return nil
	}

	ing.Finalizers = append(ing.Finalizers[:ix], ing.Finalizers[ix+1:]...)
	if err := a.Update(ctx, ing); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("unexposed ingress from tailnet")
	a.mu.Lock()
	defer a.mu.Unlock()
	a.managedIngresses.Remove(ing.UID)
	gaugeIngressResources.Set(int64(a.managedIngresses.Len()))
	return nil
}

// maybeProvision ensures that ing is exposed over tailscale, taking any actions
// necessary to reach that state.
//
// This function adds a finalizer to ing, ensuring that we can handle orderly
// deprovisioning later.
func (a *IngressReconciler) maybeProvision(ctx context.Context, logger *zap.SugaredLogger, ing *networkingv1.Ingress) error {
	if !slices.Contains(ing.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("exposing ingress over tailscale")
		ing.Finalizers = append(ing.Finalizers, FinalizerName)
		if err := a.Update(ctx, ing); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}
	a.mu.Lock()
	a.managedIngresses.Add(ing.UID)
	gaugeIngressResources.Set(int64(a.managedIngresses.Len()))
	a.mu.Unlock()

	if !a.ssr.IsHTTPSEnabledOnTailnet() {
		a.recorder.Event(ing, corev1.EventTypeWarning, "HTTPSNotEnabled", "HTTPS is not enabled on the tailnet; ingress may not work")
	}

	// magic443 is a fake hostname that we can use to tell containerboot to swap
	// out with the real hostname once it's known.
	const magic443 = "${TS_CERT_DOMAIN}:443"
	sc := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			443: {
				HTTPS: true,
			},
		},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			magic443: {
				Handlers: map[string]*ipn.HTTPHandler{},
			},
		},
	}
	if opt.Bool(ing.Annotations[AnnotationFunnel]).EqualBool(true) {
		sc.AllowFunnel = map[ipn.HostPort]bool{
			magic443: true,
		}
	}

	web := sc.Web[magic443]
	addIngressBackend := func(b *networkingv1.IngressBackend, path string) {
		if b == nil {
			return
		}
		if b.Service == nil {
			a.recorder.Eventf(ing, corev1.EventTypeWarning, "InvalidIngressBackend", "backend for path %q is missing service", path)
			return
		}
		var svc corev1.Service
		if err := a.Get(ctx, types.NamespacedName{Namespace: ing.Namespace, Name: b.Service.Name}, &svc); err != nil {
			a.recorder.Eventf(ing, corev1.EventTypeWarning, "InvalidIngressBackend", "failed to get service %q for path %q: %v", b.Service.Name, path, err)
			return
		}
		if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
			a.recorder.Eventf(ing, corev1.EventTypeWarning, "InvalidIngressBackend", "backend for path %q has invalid ClusterIP", path)
			return
		}
		var port int32
		if b.Service.Port.Name != "" {
			for _, p := range svc.Spec.Ports {
				if p.Name == b.Service.Port.Name {
					port = p.Port
					break
				}
			}
		} else {
			port = b.Service.Port.Number
		}
		if port == 0 {
			a.recorder.Eventf(ing, corev1.EventTypeWarning, "InvalidIngressBackend", "backend for path %q has invalid port", path)
			return
		}
		proto := "http://"
		if port == 443 || b.Service.Port.Name == "https" {
			proto = "https+insecure://"
		}
		web.Handlers[path] = &ipn.HTTPHandler{
			Proxy: proto + svc.Spec.ClusterIP + ":" + fmt.Sprint(port) + path,
		}
	}
	addIngressBackend(ing.Spec.DefaultBackend, "/")
	for _, rule := range ing.Spec.Rules {
		if rule.Host != "" {
			a.recorder.Eventf(ing, corev1.EventTypeWarning, "InvalidIngressBackend", "rule with host %q ignored, unsupported", rule.Host)
			continue
		}
		for _, p := range rule.HTTP.Paths {
			addIngressBackend(&p.Backend, p.Path)
		}
	}

	crl := childResourceLabels(ing.Name, ing.Namespace, "ingress")
	var tags []string
	if tstr, ok := ing.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}
	hostname := ing.Namespace + "-" + ing.Name + "-ingress"
	if ing.Spec.TLS != nil && len(ing.Spec.TLS) > 0 && len(ing.Spec.TLS[0].Hosts) > 0 {
		hostname, _, _ = strings.Cut(ing.Spec.TLS[0].Hosts[0], ".")
	}

	sts := &tailscaleSTSConfig{
		Hostname:            hostname,
		ParentResourceName:  ing.Name,
		ParentResourceUID:   string(ing.UID),
		ServeConfig:         sc,
		Tags:                tags,
		ChildResourceLabels: crl,
	}

	if _, err := a.ssr.Provision(ctx, logger, sts); err != nil {
		return fmt.Errorf("failed to provision: %w", err)
	}

	_, tsHost, _, err := a.ssr.DeviceInfo(ctx, crl)
	if err != nil {
		return fmt.Errorf("failed to get device ID: %w", err)
	}
	if tsHost == "" {
		logger.Debugf("no Tailscale hostname known yet, waiting for proxy pod to finish auth")
		// No hostname yet. Wait for the proxy pod to auth.
		ing.Status.LoadBalancer.Ingress = nil
		if err := a.Status().Update(ctx, ing); err != nil {
			return fmt.Errorf("failed to update ingress status: %w", err)
		}
		return nil
	}

	logger.Debugf("setting ingress hostname to %q", tsHost)
	ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{
		{
			Hostname: tsHost,
			Ports: []networkingv1.IngressPortStatus{
				{
					Protocol: "TCP",
					Port:     443,
				},
			},
		},
	}
	if err := a.Status().Update(ctx, ing); err != nil {
		return fmt.Errorf("failed to update ingress status: %w", err)
	}
	return nil
}

func (a *IngressReconciler) shouldExpose(ing *networkingv1.Ingress) bool {
	return ing != nil &&
		ing.Spec.IngressClassName != nil &&
		*ing.Spec.IngressClassName == "tailscale"
}
