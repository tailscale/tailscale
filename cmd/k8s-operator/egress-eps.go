// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	discoveryac "k8s.io/client-go/applyconfigurations/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/kube/egressservices"
)

// egressEpsReconciler reconciles EndpointSlices for tailnet services exposed to cluster via egress ProxyGroup proxies.
type egressEpsReconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	tsNamespace string
}

// Reconcile reconciles an EndpointSlice for a tailnet service. It updates the EndpointSlice with the endpoints of
// those ProxyGroup Pods that are ready to route traffic to the tailnet service.
// It compares tailnet service state stored in egress proxy state Secrets by containerboot with the desired
// configuration stored in proxy-cfg ConfigMap to determine if the endpoint is ready.
func (er *egressEpsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	lg := er.logger.With("Service", req.NamespacedName)
	lg.Debugf("starting reconcile")
	defer lg.Debugf("reconcile finished")

	eps := new(discoveryv1.EndpointSlice)
	err = er.Get(ctx, req.NamespacedName, eps)
	if apierrors.IsNotFound(err) {
		lg.Debugf("EndpointSlice not found")
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get EndpointSlice: %w", err)
	}
	if !eps.DeletionTimestamp.IsZero() {
		lg.Debugf("EnpointSlice is being deleted")
		return res, nil
	}

	// Get the user-created ExternalName Service and use its status conditions to determine whether cluster
	// resources are set up for this tailnet service.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      eps.Labels[LabelParentName],
			Namespace: eps.Labels[LabelParentNamespace],
		},
	}
	err = er.Get(ctx, client.ObjectKeyFromObject(svc), svc)
	if apierrors.IsNotFound(err) {
		lg.Infof("ExternalName Service %s/%s not found, perhaps it was deleted", svc.Namespace, svc.Name)
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("error retrieving ExternalName Service: %w", err)
	}

	// TODO(irbekrm): currently this reconcile loop runs all the checks every time it's triggered, which is
	// wasteful. Once we have a Ready condition for ExternalName Services for ProxyGroup, use the condition to
	// determine if a reconcile is needed.

	tailnetSvc := tailnetSvcName(svc)
	lg = lg.With("tailnet-service-name", tailnetSvc)

	// Retrieve the desired tailnet service configuration from the ConfigMap.
	proxyGroupName := eps.Labels[labelProxyGroup]
	_, cfgs, err := egressSvcsConfigs(ctx, er.Client, proxyGroupName, er.tsNamespace)
	if err != nil {
		return res, fmt.Errorf("error retrieving tailnet services configuration: %w", err)
	}
	if cfgs == nil {
		// TODO(irbekrm): this path would be hit if egress service was once exposed on a ProxyGroup that later
		// got deleted. Probably the EndpointSlices then need to be deleted too- need to rethink this flow.
		lg.Debugf("No egress config found, likely because ProxyGroup has not been created")
		return res, nil
	}

	cfg, ok := cfgs[tailnetSvc]
	if !ok {
		lg.Warnf("configuration for tailnet service %q not found", tailnetSvc)
		return res, nil
	}

	// Check which Pods in ProxyGroup are ready to route traffic to this
	// egress service.
	podList := &corev1.PodList{}
	if err := er.List(ctx, podList, client.MatchingLabels(pgLabels(proxyGroupName, nil))); err != nil {
		return res, fmt.Errorf("error listing Pods for ProxyGroup %s: %w", proxyGroupName, err)
	}
	newEndpoints := make([]*discoveryac.EndpointApplyConfiguration, 0)
	for _, pod := range podList.Items {
		ready, err := er.podIsReadyToRouteTraffic(ctx, pod, &cfg, tailnetSvc, eps.AddressType, lg)
		if err != nil {
			return res, fmt.Errorf("error verifying if Pod is ready to route traffic: %w", err)
		}
		if !ready {
			continue // maybe next time
		}
		podIP, err := podIPForFamily(&pod, eps.AddressType)
		if err != nil {
			return res, fmt.Errorf("error determining Pod IP for %s EndpointSlice: %w", eps.AddressType, err)
		}
		if podIP == "" {
			continue // Pod doesn't have an IP for this address family
		}
		newEndpoints = append(newEndpoints, discoveryac.Endpoint().
			WithHostname(string(pod.UID)).
			WithAddresses(podIP).
			WithConditions(discoveryac.EndpointConditions().
				WithReady(true).
				WithServing(true).
				WithTerminating(false)))
	}
	// Endpoints must be in a deterministic order. EndpointSlice.Endpoints is a
	// +listType=atomic field, so Server-Side Apply (below) compares the whole
	// list as a single value. Sort by the endpoint's address so an
	// unchanged set of ready Pods always produces an identical apply.
	slices.SortFunc(newEndpoints, func(a, b *discoveryac.EndpointApplyConfiguration) int {
		return strings.Compare(firstAddress(a), firstAddress(b))
	})

	// Apply only the Endpoints field under this reconciler's own field manager.
	// The egress Services reconciler owns labels/addressType/ports on the same
	// slice via its own field manager- see (tailscale/tailscale#20916).
	desired := discoveryac.EndpointSlice(eps.Name, eps.Namespace).
		WithEndpoints(newEndpoints...)
	u, err := applyConfigToUnstructured(desired)
	if err != nil {
		return res, err
	}
	// When no Pods are ready, apply an explicit empty endpoints list rather than
	// omitting the field. The apply configuration's endpoints field is
	// omitempty, so WithEndpoints of an empty set drops it entirely, which under
	// Server-Side Apply relinquishes ownership. This may have little impact in
	// practice, but is safer given the potential for resource contention on
	// endpointslices.
	if len(newEndpoints) == 0 {
		if err := unstructured.SetNestedField(u.Object, []any{}, "endpoints"); err != nil {
			return res, fmt.Errorf("error setting empty endpoints: %w", err)
		}
	}
	if err := er.Patch(ctx, u, client.Apply, client.FieldOwner(egressEpsFieldOwner), client.ForceOwnership); err != nil {
		return res, fmt.Errorf("error applying EndpointSlice endpoints: %w", err)
	}

	return res, nil
}

// applyConfigToUnstructured converts a typed apply configuration into an
// *unstructured.Unstructured suitable for a server-side-apply Patch
// (client.Apply) on controller-runtime v0.19.4, which has no typed
// client.Client.Apply method.
// TODO(beckypauley): remove when upgraded to v0.23.
func applyConfigToUnstructured(ac any) (*unstructured.Unstructured, error) {
	contents, err := runtime.DefaultUnstructuredConverter.ToUnstructured(ac)
	if err != nil {
		return nil, fmt.Errorf("error converting apply configuration to unstructured: %w", err)
	}
	return &unstructured.Unstructured{Object: contents}, nil
}

// egressEpsFieldOwner is the field manager used by the egress EndpointSlices
// reconciler when it Server-Side Applies the Endpoints of a slice.
const egressEpsFieldOwner = "tailscale-egress-eps-reconciler"

// firstAddress returns the endpoint's first address, or the empty string if it
// has none, for use as a stable sort key.
func firstAddress(e *discoveryac.EndpointApplyConfiguration) string {
	if e == nil || len(e.Addresses) == 0 {
		return ""
	}
	return e.Addresses[0]
}

func podIPForFamily(pod *corev1.Pod, addrType discoveryv1.AddressType) (string, error) {
	for _, ip := range pod.Status.PodIPs {
		parsed, err := netip.ParseAddr(ip.IP)
		if err != nil {
			return "", fmt.Errorf("error parsing IP address %s: %w", ip, err)
		}
		switch {
		case addrType == discoveryv1.AddressTypeIPv4 && parsed.Is4():
			return parsed.String(), nil
		case addrType == discoveryv1.AddressTypeIPv6 && parsed.Is6():
			return parsed.String(), nil
		}
	}
	return "", nil
}

// podIsReadyToRouteTraffic returns true if it appears that the proxy Pod has configured firewall rules to be able to
// route traffic to the given tailnet service. It retrieves the proxy's state Secret and compares the tailnet service
// status written there to the desired service configuration.
func (er *egressEpsReconciler) podIsReadyToRouteTraffic(ctx context.Context, pod corev1.Pod, cfg *egressservices.Config, tailnetSvcName string, addrType discoveryv1.AddressType, lg *zap.SugaredLogger) (bool, error) {
	lg = lg.With("proxy_pod", pod.Name)
	lg.Debug("checking whether proxy is ready to route to egress service")
	if !pod.DeletionTimestamp.IsZero() {
		lg.Debug("proxy Pod is being deleted, ignore")
		return false, nil
	}
	podIP, err := podIPForFamily(&pod, addrType)
	switch {
	case err != nil:
		return false, fmt.Errorf("error determining Pod IP address: %v", err)
	case podIP == "":
		lg.Debugf("Pod does not have an address for family %s", addrType)
		return false, nil
	}

	stateS := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
	}

	err = er.Get(ctx, client.ObjectKeyFromObject(stateS), stateS)
	switch {
	case apierrors.IsNotFound(err):
		lg.Debug("proxy does not yet have a state Secret, waiting...")
		return false, nil
	case err != nil:
		return false, fmt.Errorf("error retrieving state Secret: %w", err)
	}

	svcStatusBS := stateS.Data[egressservices.KeyEgressServices]
	if len(svcStatusBS) == 0 {
		lg.Debug("proxy's state Secret does not contain egress services status, waiting...")
		return false, nil
	}

	svcStatus := &egressservices.Status{}
	if err = json.Unmarshal(svcStatusBS, svcStatus); err != nil {
		return false, fmt.Errorf("error unmarshalling egress service status: %w", err)
	}
	var statusIP string
	switch addrType {
	case discoveryv1.AddressTypeIPv4:
		statusIP = svcStatus.PodIPv4
	case discoveryv1.AddressTypeIPv6:
		statusIP = svcStatus.PodIPv6
	}
	if !strings.EqualFold(podIP, statusIP) {
		lg.Infof("proxy's egress service status is for Pod IP %q, current proxy's Pod IP %q, waiting for the proxy to reconfigure...", statusIP, podIP)
		return false, nil
	}

	st, ok := svcStatus.Services[tailnetSvcName]
	if !ok {
		lg.Infof("proxy's state Secret does not have egress service status, waiting...")
		return false, nil
	}

	if !reflect.DeepEqual(cfg.TailnetTarget, st.TailnetTarget) {
		lg.Infof("proxy has configured egress service for tailnet target %q, current target is %q, waiting for proxy to reconfigure...", st.TailnetTarget, cfg.TailnetTarget)
		return false, nil
	}

	if !reflect.DeepEqual(cfg.Ports, st.Ports) {
		lg.Debugf("proxy has configured egress service for ports %#+v, wants ports %#+v, waiting for proxy to reconfigure", st.Ports, cfg.Ports)
		return false, nil
	}

	lg.Debug("proxy is ready to route traffic to egress service")
	return true, nil
}
