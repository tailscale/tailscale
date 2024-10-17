// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsoperator "tailscale.com/k8s-operator"
	"tailscale.com/kube/egressservices"
	"tailscale.com/types/ptr"
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
	l := er.logger.With("Service", req.NamespacedName)
	l.Debugf("starting reconcile")
	defer l.Debugf("reconcile finished")

	eps := new(discoveryv1.EndpointSlice)
	err = er.Get(ctx, req.NamespacedName, eps)
	if apierrors.IsNotFound(err) {
		l.Debugf("EndpointSlice not found")
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get EndpointSlice: %w", err)
	}
	if !eps.DeletionTimestamp.IsZero() {
		l.Debugf("EnpointSlice is being deleted")
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
		l.Infof("ExternalName Service %s/%s not found, perhaps it was deleted", svc.Namespace, svc.Name)
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("error retrieving ExternalName Service: %w", err)
	}
	if !tsoperator.EgressServiceIsValidAndConfigured(svc) {
		l.Infof("Cluster resources for ExternalName Service %s/%s are not yet configured", svc.Namespace, svc.Name)
		return res, nil
	}

	// TODO(irbekrm): currently this reconcile loop runs all the checks every time it's triggered, which is
	// wasteful. Once we have a Ready condition for ExternalName Services for ProxyGroup, use the condition to
	// determine if a reconcile is needed.

	oldEps := eps.DeepCopy()
	proxyGroupName := eps.Labels[labelProxyGroup]
	tailnetSvc := tailnetSvcName(svc)
	l = l.With("tailnet-service-name", tailnetSvc)

	// Retrieve the desired tailnet service configuration from the ConfigMap.
	_, cfgs, err := egressSvcsConfigs(ctx, er.Client, proxyGroupName, er.tsNamespace)
	if err != nil {
		return res, fmt.Errorf("error retrieving tailnet services configuration: %w", err)
	}
	cfg, ok := (*cfgs)[tailnetSvc]
	if !ok {
		l.Infof("[unexpected] configuration for tailnet service %s not found", tailnetSvc)
		return res, nil
	}

	// Check which Pods in ProxyGroup are ready to route traffic to this
	// egress service.
	podList := &corev1.PodList{}
	if err := er.List(ctx, podList, client.MatchingLabels(pgLabels(proxyGroupName, nil))); err != nil {
		return res, fmt.Errorf("error listing Pods for ProxyGroup %s: %w", proxyGroupName, err)
	}
	newEndpoints := make([]discoveryv1.Endpoint, 0)
	for _, pod := range podList.Items {
		ready, err := er.podIsReadyToRouteTraffic(ctx, pod, &cfg, tailnetSvc, l)
		if err != nil {
			return res, fmt.Errorf("error verifying if Pod is ready to route traffic: %w", err)
		}
		if !ready {
			continue // maybe next time
		}
		podIP, err := podIPv4(&pod) // we currently only support IPv4
		if err != nil {
			return res, fmt.Errorf("error determining IPv4 address for Pod: %w", err)
		}
		newEndpoints = append(newEndpoints, discoveryv1.Endpoint{
			Hostname:  (*string)(&pod.UID),
			Addresses: []string{podIP},
			Conditions: discoveryv1.EndpointConditions{
				Ready:       ptr.To(true),
				Serving:     ptr.To(true),
				Terminating: ptr.To(false),
			},
		})
	}
	// Note that Endpoints are being overwritten with the currently valid endpoints so we don't need to explicitly
	// run a cleanup for deleted Pods etc.
	eps.Endpoints = newEndpoints
	if !reflect.DeepEqual(eps, oldEps) {
		l.Infof("Updating EndpointSlice to ensure traffic is routed to ready proxy Pods")
		if err := er.Update(ctx, eps); err != nil {
			return res, fmt.Errorf("error updating EndpointSlice: %w", err)
		}
	}
	return res, nil
}

func podIPv4(pod *corev1.Pod) (string, error) {
	for _, ip := range pod.Status.PodIPs {
		parsed, err := netip.ParseAddr(ip.IP)
		if err != nil {
			return "", fmt.Errorf("error parsing IP address %s: %w", ip, err)
		}
		if parsed.Is4() {
			return parsed.String(), nil
		}
	}
	return "", nil
}

// podIsReadyToRouteTraffic returns true if it appears that the proxy Pod has configured firewall rules to be able to
// route traffic to the given tailnet service. It retrieves the proxy's state Secret and compares the tailnet service
// status written there to the desired service configuration.
func (er *egressEpsReconciler) podIsReadyToRouteTraffic(ctx context.Context, pod corev1.Pod, cfg *egressservices.Config, tailnetSvcName string, l *zap.SugaredLogger) (bool, error) {
	l = l.With("proxy_pod", pod.Name)
	l.Debugf("checking whether proxy is ready to route to egress service")
	if !pod.DeletionTimestamp.IsZero() {
		l.Debugf("proxy Pod is being deleted, ignore")
		return false, nil
	}
	podIP, err := podIPv4(&pod)
	if err != nil {
		return false, fmt.Errorf("error determining Pod IP address: %v", err)
	}
	if podIP == "" {
		l.Infof("[unexpected] Pod does not have an IPv4 address, and IPv6 is not currently supported")
		return false, nil
	}
	stateS := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
	}
	err = er.Get(ctx, client.ObjectKeyFromObject(stateS), stateS)
	if apierrors.IsNotFound(err) {
		l.Debugf("proxy does not have a state Secret, waiting...")
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("error getting state Secret: %w", err)
	}
	svcStatusBS := stateS.Data[egressservices.KeyEgressServices]
	if len(svcStatusBS) == 0 {
		l.Debugf("proxy's state Secret does not contain egress services status, waiting...")
		return false, nil
	}
	svcStatus := &egressservices.Status{}
	if err := json.Unmarshal(svcStatusBS, svcStatus); err != nil {
		return false, fmt.Errorf("error unmarshalling egress service status: %w", err)
	}
	if !strings.EqualFold(podIP, svcStatus.PodIPv4) {
		l.Infof("proxy's egress service status is for Pod IP %s, current proxy's Pod IP %s, waiting for the proxy to reconfigure...", svcStatus.PodIPv4, podIP)
		return false, nil
	}
	st, ok := (*svcStatus).Services[tailnetSvcName]
	if !ok {
		l.Infof("proxy's state Secret does not have egress service status, waiting...")
		return false, nil
	}
	if !reflect.DeepEqual(cfg.TailnetTarget, st.TailnetTarget) {
		l.Infof("proxy has configured egress service for tailnet target %v, current target is %v, waiting for proxy to reconfigure...", st.TailnetTarget, cfg.TailnetTarget)
		return false, nil
	}
	if !reflect.DeepEqual(cfg.Ports, st.Ports) {
		l.Debugf("proxy has configured egress service for ports %#+v, wants ports %#+v, waiting for proxy to reconfigure", st.Ports, cfg.Ports)
		return false, nil
	}
	l.Debugf("proxy is ready to route traffic to egress service")
	return true, nil
}
