// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	kube "tailscale.com/k8s-operator"
	"tailscale.com/types/ptr"
)

// reconciles fwegress Pods
type FWEgressReconciler struct {
	client.Client
	logger *zap.SugaredLogger
}

func (er *FWEgressReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := er.logger.With("service-ns", req.Namespace, "service-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	p := new(corev1.Pod)
	err = er.Get(ctx, req.NamespacedName, p)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("Pod not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get pod: %w", err)
	}
	if !p.DeletionTimestamp.IsZero() {
		logger.Debugf("Pod is being deleted")
		return
	}
	egressSvcName := p.Labels["tailscale.com/fwegress"]
	if egressSvcName == "" {
		logger.Debugf("[unexpected] Pod is not for egress service")
	}
	eps, err := er.fwegressEPS(ctx, egressSvcName)
	if err != nil {
		return res, fmt.Errorf("error ensuring EndpointSlice: %w", err)
	}
	oldEndpoints := eps.DeepCopy()
	found := false
	for _, e := range eps.Endpoints {
		if strings.EqualFold(*e.Hostname, string(p.UID)) {
			found = true
			break
		}
	}
	if !found {
		eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
			Hostname: ptr.To(string(p.UID)),
		})
	}
	if !reflect.DeepEqual(oldEndpoints, eps) {
		if err := er.Update(ctx, eps); err != nil {
			return res, fmt.Errorf("error updating EndpointSlice: %w", err)
		}
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-proxies",
			Namespace: "tailscale",
		},
	}
	if err := er.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		return res, fmt.Errorf("error getting egress-proxies cm: %w", err)
	}
	svcCfg := &kube.EgressServices{}
	if err := json.Unmarshal([]byte(cm.Data["services"]), svcCfg); err != nil {
		return res, fmt.Errorf("error unmarshalling config: %w", err)
	}
	found = false
	egSvc := svcCfg.Services[egressSvcName]
	for _, ip := range egSvc.ClusterSources {
		if strings.EqualFold(ip, p.Status.PodIP) {
			found = true
			break
		}
	}
	if !found {
		egSvc.ClusterSources = append(egSvc.ClusterSources, p.Status.PodIP)
		svcCfg.Services[egressSvcName] = egSvc
		if err := er.Update(ctx, cm); err != nil {
			return res, fmt.Errorf("error updating ConfigMap: %w", err)
		}
	}
	return res, nil
}

func (er *FWEgressReconciler) fwegressEPS(ctx context.Context, name string) (*discoveryv1.EndpointSlice, error) {
	eps := &discoveryv1.EndpointSlice{
		AddressType: discoveryv1.AddressTypeIPv4, // for this prototype
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "tailscale",
			Labels:    map[string]string{"tailscale.com/fwegress": name},
		},
	}
	// only create if not exists as the other reconciler will be updating this
	err := er.Get(ctx, client.ObjectKeyFromObject(eps), eps)
	if apierrors.IsNotFound(err) {
		if err := er.Create(ctx, eps); err != nil {
			return nil, fmt.Errorf("error creating Endpointslice: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("error getting EndpointSlice: %w", err)
	}
	return eps, nil
}
