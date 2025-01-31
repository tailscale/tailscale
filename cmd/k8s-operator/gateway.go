// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	"tailscale.com/ipn"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

const (
	tailscaleGatewayClassName      = "tailscale"                // gatewayClass.metadata.name for tailscale GatewayClass resource
	tailscaleGatewayControllerName = "tailscale.com/ts-gateway" // gatewayClass.spec.controllerName for tailscale GatewayClass resource
)

type GatewayReconciler struct {
	client.Client

	recorder record.EventRecorder
	ssr      *tailscaleSTSReconciler
	logger   *zap.SugaredLogger

	mu sync.Mutex // protects following

	// managedGateways is a set of all gateway resources that we're currently
	// managing. This is only used for metrics.
	managedGateways set.Slice[types.UID]

	defaultProxyClass string
}

var (
	// gaugeGatewayResources tracks the number of gateway resources that we're
	// currently managing.
	gaugeGatewayResources = clientmetric.NewGauge(kubetypes.MetricGatewayResourceCount)
)

func (a *GatewayReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := a.logger.With("gateway-ns", req.Namespace, "gateway-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	gate := new(gatewayv1.Gateway)
	err = a.Get(ctx, req.NamespacedName, gate)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("gateway not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get gate: %w", err)
	}
	if !gate.DeletionTimestamp.IsZero() || !a.shouldExpose(gate) {
		logger.Debugf("gateway is being deleted or should not be exposed, cleaning up")
		return reconcile.Result{}, a.maybeCleanup(ctx, logger, gate)
	}

	if err := a.maybeProvision(ctx, logger, gate); err != nil {
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			logger.Infof("optimistic lock error, retrying: %s", err)
		} else {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

func (a *GatewayReconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, gate *gatewayv1.Gateway) error {
	ix := slices.Index(gate.Finalizers, FinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		a.mu.Lock()
		defer a.mu.Unlock()
		a.managedGateways.Remove(gate.UID)
		gaugeGatewayResources.Set(int64(a.managedGateways.Len()))
		return nil
	}

	if done, err := a.ssr.Cleanup(ctx, logger, childResourceLabels(gate.Name, gate.Namespace, "gateway"), proxyTypeGatewayResource); err != nil {
		return fmt.Errorf("failed to cleanup: %w", err)
	} else if !done {
		logger.Debugf("cleanup not done yet, waiting for next reconcile")
		return nil
	}

	gate.Finalizers = append(gate.Finalizers[:ix], gate.Finalizers[ix+1:]...)
	if err := a.Update(ctx, gate); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("unexposed gateway from tailnet")
	a.mu.Lock()
	defer a.mu.Unlock()
	a.managedGateways.Remove(gate.UID)
	gaugeGatewayResources.Set(int64(a.managedGateways.Len()))
	return nil
}

// maybeProvision ensures that gate is exposed over tailscale, taking any actions
// necessary to reach that state.
//
// This function adds a finalizer to gate, ensuring that we can handle orderly
// deprovisioning later.
func (a *GatewayReconciler) maybeProvision(ctx context.Context, logger *zap.SugaredLogger, gate *gatewayv1.Gateway) error {
	if err := a.validateGatewayClass(ctx); err != nil {
		logger.Warnf("error validating tailscale GatewayClass: %v. In future this might be a terminal error.", err)

	}
	if !slices.Contains(gate.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("exposing gateway over tailscale")
		gate.Finalizers = append(gate.Finalizers, FinalizerName)
		if err := a.Update(ctx, gate); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	proxyClass := proxyClassForObject(gate, a.defaultProxyClass)
	if proxyClass != "" {
		if ready, err := proxyClassIsReady(ctx, proxyClass, a.Client); err != nil {
			return fmt.Errorf("error verifying ProxyClass for Gateway: %w", err)
		} else if !ready {
			logger.Infof("ProxyClass %s specified for the Gateway, but is not (yet) Ready, waiting..", proxyClass)
			return nil
		}
	}

	a.mu.Lock()
	a.managedGateways.Add(gate.UID)
	gaugeGatewayResources.Set(int64(a.managedGateways.Len()))
	a.mu.Unlock()

	if !IsHTTPSEnabledOnTailnet(a.ssr.tsnetServer) {
		a.recorder.Event(gate, corev1.EventTypeWarning, "HTTPSNotEnabled", "HTTPS is not enabled on the tailnet; gateway may not work")
	}

	sc := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{},
	}
	if err := a.addListeners(gate, sc, logger); err != nil {
		return fmt.Errorf("failed to configure TCP ports: %w", err)
	}
	if err := a.configureHTTPRoutes(ctx, gate, sc); err != nil {
		return fmt.Errorf("failed to configure HTTP routes: %w", err)
	}
	if err := a.configureTCPRoutes(ctx, gate, sc); err != nil {
		return fmt.Errorf("failed to configure TCP routes: %w", err)
	}

	var tlsHost string // hostname or FQDN or empty
	if gate.Spec.Addresses != nil && len(gate.Spec.Addresses) > 0 {
		tlsHost = gate.Spec.Addresses[0].Value
	}

	crl := childResourceLabels(gate.Name, gate.Namespace, "gateway")
	var tags []string
	if tstr, ok := gate.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}
	hostname := gate.Namespace + "-" + gate.Name + "-gateway"
	if tlsHost != "" {
		hostname, _, _ = strings.Cut(tlsHost, ".")
	}

	sts := &tailscaleSTSConfig{
		Hostname:            hostname,
		ParentResourceName:  gate.Name,
		ParentResourceUID:   string(gate.UID),
		ServeConfig:         sc,
		Tags:                tags,
		ChildResourceLabels: crl,
		ProxyClassName:      proxyClass,
		proxyType:           proxyTypeGatewayResource,
	}

	if val := gate.GetAnnotations()[AnnotationExperimentalForwardClusterTrafficViaL7IngresProxy]; val == "true" {
		sts.ForwardClusterTrafficViaL7IngressProxy = true
	}

	if _, err := a.ssr.Provision(ctx, logger, sts); err != nil {
		return fmt.Errorf("failed to provision: %w", err)
	}

	dev, err := a.ssr.DeviceInfo(ctx, crl, logger)
	if err != nil {
		return fmt.Errorf("failed to retrieve Gateway HTTPS endpoint status: %w", err)
	}

	logger.Debugf("setting Gateway hostname to %q", dev.ingressDNSName)
	gate.Status.Addresses = []gatewayv1.GatewayStatusAddress{
		{
			Type:  ptr.To(gatewayv1.HostnameAddressType),
			Value: dev.ingressDNSName,
		},
	}
	if err := a.Status().Update(ctx, gate); err != nil {
		return fmt.Errorf("failed to update gateway status: %w", err)
	}
	return nil
}

func (a *GatewayReconciler) addListeners(gate *gatewayv1.Gateway, sc *ipn.ServeConfig, logger *zap.SugaredLogger) error {
	for _, lis := range gate.Spec.Listeners {
		switch lis.Protocol {
		case gatewayv1.HTTPProtocolType:
			sc.TCP[uint16(lis.Port)] = &ipn.TCPPortHandler{
				HTTP: true,
			}
			a.addWebListener(gate, &lis, sc)
		case gatewayv1.HTTPSProtocolType:
			sc.TCP[uint16(lis.Port)] = &ipn.TCPPortHandler{
				HTTPS: true,
			}
			a.addWebListener(gate, &lis, sc)
		case gatewayv1.TCPProtocolType:
			sc.TCP[uint16(lis.Port)] = &ipn.TCPPortHandler{}
		default:
			logger.Warnf("unsupported protocol %s, skipping", lis.Protocol)
			continue
		}
	}
	return nil
}

func (a *GatewayReconciler) addWebListener(gate *gatewayv1.Gateway, lis *gatewayv1.Listener, sc *ipn.ServeConfig) {
	port := HostPortFromListener(lis)
	sc.Web[port] = &ipn.WebServerConfig{
		Handlers: map[string]*ipn.HTTPHandler{},
	}
	if opt.Bool(gate.Annotations[AnnotationFunnel]).EqualBool(true) {
		sc.AllowFunnel = map[ipn.HostPort]bool{
			port: true,
		}
	}
}

func (a *GatewayReconciler) configureHTTPRoutes(ctx context.Context, gate *gatewayv1.Gateway, sc *ipn.ServeConfig) error {
	hrs := &gatewayv1.HTTPRouteList{}
	err := a.List(ctx, hrs, client.InNamespace(gate.Namespace))
	if err != nil {
		return fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}

	for _, hr := range hrs.Items {
		if hr.Spec.ParentRefs == nil || len(hr.Spec.ParentRefs) == 0 {
			a.recorder.Eventf(&hr, corev1.EventTypeWarning, "InvalidGatewayParentRef", "no parent refs specified")
			continue
		}
		for _, parentRef := range hr.Spec.ParentRefs {
			if !a.isGatewayMatchingParentRef(gate, parentRef) {
				a.recorder.Eventf(&hr, corev1.EventTypeWarning, "InvalidGatewayParentRef", "parent ref %s does not match Gateway", parentRef.Name)
				continue
			}
			for _, rule := range hr.Spec.Rules {
				for _, br := range rule.BackendRefs {
					if err := a.validateHTTPBackendRef(br); err != nil {
						a.recorder.Eventf(&hr, corev1.EventTypeWarning, "InvalidGatewayBackend", "invalid backend ref %v: %v", br, err)
						continue
					}
					var ns string
					if br.Namespace != nil {
						ns = string(*br.Namespace)
					} else {
						ns = gate.Namespace
					}
					var svc corev1.Service
					if err := a.Get(ctx, types.NamespacedName{Namespace: ns, Name: string(br.Name)}, &svc); err != nil {
						a.recorder.Eventf(&hr, corev1.EventTypeWarning, "InvalidGatewayBackend", "failed to get service %q: %v", br.Name, err)
						continue
					}
					if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
						a.recorder.Eventf(&hr, corev1.EventTypeWarning, "InvalidGatewayBackend", "backend %s has invalid ClusterIP", br.Name)
						continue
					}
					var port int32
					if br.Port == nil || *br.Port == 0 {
						a.recorder.Eventf(&hr, corev1.EventTypeWarning, "InvalidIngressBackend", "backend %q has invalid port", br.Name)
						continue
					}
					for _, p := range svc.Spec.Ports {
						if gatewayv1.PortNumber(p.Port) == *br.Port {
							port = p.Port
							break
						}
					}
					proto := "http://"
					if port == 443 {
						proto = "https+insecure://"
					}
					for _, match := range rule.Matches {
						if match.Path != nil {
							if match.Path.Type != nil && *match.Path.Type != gatewayv1.PathMatchPathPrefix {
								a.recorder.Eventf(&hr, corev1.EventTypeWarning, "InvalidGatewayBackend", "backend %q path match type %s is not supported", br.Name, match.Path.Type)
								continue
							}
							if match.Path.Value == nil {
								a.recorder.Eventf(&hr, corev1.EventTypeWarning, "InvalidGatewayBackend", "backend %q path match value is nil", br.Name)
								continue
							}
							sc.Web[HostPortFromParentRef(parentRef)].Handlers[*match.Path.Value] = &ipn.HTTPHandler{
								Proxy: proto + svc.Spec.ClusterIP + ":" + fmt.Sprint(*br.Port) + *match.Path.Value,
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func (a *GatewayReconciler) configureTCPRoutes(ctx context.Context, gate *gatewayv1.Gateway, sc *ipn.ServeConfig) error {
	trs := &gatewayv1alpha2.TCPRouteList{}
	err := a.List(ctx, trs, client.InNamespace(gate.Namespace))
	if err != nil {
		return fmt.Errorf("failed to list TCPRoutes: %w", err)
	}

	for _, tr := range trs.Items {
		if tr.Spec.ParentRefs == nil || len(tr.Spec.ParentRefs) == 0 {
			a.recorder.Eventf(&tr, corev1.EventTypeWarning, "InvalidGatewayParentRef", "no parent refs specified")
			continue
		}
		for _, pr := range tr.Spec.ParentRefs {
			if !a.isGatewayMatchingParentRef(gate, pr) {
				a.recorder.Eventf(&tr, corev1.EventTypeWarning, "InvalidGatewayParentRef", "parent ref %s does not match Gateway", pr.Name)
				continue
			}
			for _, rule := range tr.Spec.Rules {
				for _, br := range rule.BackendRefs {
					if err := a.validateBackendRef(br); err != nil {
						a.recorder.Eventf(&tr, corev1.EventTypeWarning, "InvalidGatewayBackend", "invalid backend ref %v: %v", br, err)
						continue
					}
					var ns string
					if br.Namespace != nil {
						ns = string(*br.Namespace)
					} else {
						ns = gate.Namespace
					}
					var svc corev1.Service
					if err := a.Get(ctx, types.NamespacedName{Namespace: ns, Name: string(br.Name)}, &svc); err != nil {
						a.recorder.Eventf(&tr, corev1.EventTypeWarning, "InvalidGatewayBackend", "failed to get service %q: %v", br.Name, err)
						continue
					}
					if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
						a.recorder.Eventf(&tr, corev1.EventTypeWarning, "InvalidGatewayBackend", "backend %s has invalid ClusterIP", br.Name)
						continue
					}
					var port int32
					if br.Name != "" {
						for _, p := range svc.Spec.Ports {
							if gatewayv1.ObjectName(p.Name) == br.Name {
								port = p.Port
								break
							}
						}
					} else {
						port = int32(*br.Port)
					}
					if port == 0 {
						a.recorder.Eventf(&tr, corev1.EventTypeWarning, "InvalidIngressBackend", "backend %q has invalid port", br.Name)
						continue
					}
					if pr.Port != nil {
						sc.TCP[uint16(*pr.Port)].TCPForward = fmt.Sprintf("%s:%d", svc.Spec.ClusterIP, *br.Port)
					}
				}
			}
		}
	}
	return nil
}

func (a *GatewayReconciler) shouldExpose(gate *gatewayv1.Gateway) bool {
	return gate != nil &&
		gate.Spec.GatewayClassName == tailscaleGatewayClassName
}

// validateGatewayClass attempts to validate that 'tailscale' GatewayClass
// included in Tailscale installation manifests exists and has not been modified
// to attempt to enable features that we do not support.
func (a *GatewayReconciler) validateGatewayClass(ctx context.Context) error {
	ic := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: tailscaleGatewayClassName,
		},
	}
	if err := a.Get(ctx, client.ObjectKeyFromObject(ic), ic); apierrors.IsNotFound(err) {
		return errors.New("Tailscale GatewayClass not found in cluster. Latest installation manifests include a tailscale GatewayClass - please update")
	} else if err != nil {
		return fmt.Errorf("error retrieving 'tailscale' GatewayClass: %w", err)
	}
	if ic.Spec.ControllerName != tailscaleGatewayControllerName {
		return fmt.Errorf("Tailscale Gateway class controller name %s does not match tailscale Gateway controller name %s. Ensure that you are using 'tailscale' GatewayClass from latest Tailscale installation manifests", ic.Spec.ControllerName, tailscaleGatewayControllerName)
	}
	return nil
}

func (a *GatewayReconciler) validateHTTPBackendRef(backendRef gatewayv1.HTTPBackendRef) error {
	if backendRef.Group != nil && *backendRef.Group != gatewayv1.Group("") {
		return fmt.Errorf("backend %s group is not supported", *backendRef.Group)
	}
	if backendRef.Kind != nil && *backendRef.Kind != gatewayv1.Kind("Service") {
		return fmt.Errorf("backend %s kind is not supported", *backendRef.Kind)
	}
	return nil
}

func (a *GatewayReconciler) validateBackendRef(backendRef gatewayv1.BackendRef) error {
	if backendRef.Group != nil && *backendRef.Group != gatewayv1alpha2.Group("") {
		return fmt.Errorf("backend %s group is not supported", *backendRef.Group)
	}
	if backendRef.Kind != nil && *backendRef.Kind != gatewayv1alpha2.Kind("Service") {
		return fmt.Errorf("backend %s kind is not supported", *backendRef.Kind)
	}
	return nil
}

func (a *GatewayReconciler) isGatewayMatchingParentRef(gate *gatewayv1.Gateway, parentRef gatewayv1.ParentReference) bool {
	if parentRef.Name == gatewayv1.ObjectName(gate.Name) &&
		(parentRef.Namespace == nil || *parentRef.Namespace == gatewayv1.Namespace(gate.Namespace)) &&
		(parentRef.Group == nil || *parentRef.Group == gatewayv1.Group(gate.APIVersion)) &&
		(parentRef.Kind == nil || *parentRef.Kind == gatewayv1.Kind(gate.Kind)) {
		return true
	}
	if parentRef.Port != nil {
		for _, listener := range gate.Spec.Listeners {
			if listener.Port == *parentRef.Port {
				return true
			}
		}
	}
	return false
}

func HostPortFromListener(lis *gatewayv1.Listener) ipn.HostPort {
	return ipn.HostPort(fmt.Sprintf("${TS_CERT_DOMAIN}:%d", lis.Port))
}

func HostPortFromParentRef(parentRef gatewayv1.ParentReference) ipn.HostPort {
	return ipn.HostPort(fmt.Sprintf("${TS_CERT_DOMAIN}:%d", *parentRef.Port))
}
