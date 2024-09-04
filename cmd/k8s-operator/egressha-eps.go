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

type egressHAEndpointSliceReconciler struct {
	client.Client
	logger *zap.SugaredLogger
}

// Get EndpointSlice
// Retrieve all proxy group Pods
func (ehr *egressHAEndpointSliceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := ehr.logger.With("Service", req.NamespacedName)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	eps := new(discoveryv1.EndpointSlice)
	err = ehr.Get(ctx, req.NamespacedName, eps)
	if apierrors.IsNotFound(err) {
		logger.Debugf("EndpointSlice not found")
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get EndpointSlice: %w", err)
	}
	if !eps.DeletionTimestamp.IsZero() {
		logger.Debugf("EnpointSlice is being deleted")
		return res, nil
	}
	oldEps := eps.DeepCopy()
	proxyGroupName := eps.Labels["tailscale.com/proxy-group"]
	egressServiceName := eps.Labels["tailscale.com/egress-service"]

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-egress-services", proxyGroupName),
			Namespace: "tailscale",
		},
	}
	err = ehr.Get(ctx, client.ObjectKeyFromObject(cm), cm)
	if apierrors.IsNotFound(err) {
		logger.Debugf("ConfigMap %s not found", cm.Name)
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("error retrieving ConfigMap %s: %w", cm.Name, err)
	}
	wantsCfgBS, ok := cm.BinaryData["cfg"]
	if !ok {
		// nothing here
		logger.Debugf("egress-services config is empty")
		return res, nil
	}
	wantsCfg := &kube.EgressServices{}
	if err := json.Unmarshal(wantsCfgBS, wantsCfg); err != nil {
		return res, fmt.Errorf("error unmarshalling egress services config: %w", err)
	}
	wantsEgressCfg, ok := (*wantsCfg)[egressServiceName]
	if !ok {
		logger.Debugf("egress services config does not contain config for %s", egressServiceName)
		return res, nil
	}
	// get all proxy pods
	podList := &corev1.PodList{}
	if err := ehr.List(ctx, podList, client.MatchingLabels(map[string]string{"tailscale.com/proxy-group": proxyGroupName})); err != nil {
		return res, fmt.Errorf("error listing Pods for %s ProxyGroup: %w", proxyGroupName, err)
	}
	if len(podList.Items) == 0 {
		logger.Debugf("no Pods")
		return res, nil
	}
	// also remove any leftover ones
	// for each pod
	newEndpoints := make([]discoveryv1.Endpoint, 0)
	for _, pod := range podList.Items {
		if !pod.DeletionTimestamp.IsZero() {
			logger.Debugf("Pod %s is being deleted, ignore", pod.Name)
			continue
		}
		// TODO: maybe some more Pod readiness checks
		podIP := pod.Status.PodIP
		// get the associated state Secret
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pod.Name,
				Namespace: pod.Namespace,
			},
		}
		err := ehr.Get(ctx, client.ObjectKeyFromObject(secret), secret)
		if apierrors.IsNotFound(err) {
			logger.Debugf("state Secret %s not yet exists", secret.Name)
			continue
		}
		if err != nil {
			return res, fmt.Errorf("error getting state Secret %s: %w", secret.Name, err)
		}
		svcStatusBS := secret.Data["egress-services"]
		if len(svcStatusBS) == 0 {
			// nothing ready here
			logger.Debugf("state Secret %s does not yet have egress services status", secret.Name)
			continue
		}
		svcStatus := &kube.EgressServicesStatus{}
		if err := json.Unmarshal(svcStatusBS, svcStatus); err != nil {
			return res, fmt.Errorf("error unmarshalling service status: %v", err)
		}
		thisSvcStatus, ok := (*svcStatus)[egressServiceName]
		if !ok {
			logger.Debugf("state Secret %s does not yet have status for egress service %s", secret.Name, egressServiceName)
			continue
		}
		if !strings.EqualFold(podIP, thisSvcStatus.PodIP) {
			logger.Debugf("got Pod IP %s, want Pod IP %s, not yet ready", thisSvcStatus.PodIP, podIP)
			continue
		}
		if !strings.EqualFold(wantsEgressCfg.TailnetTarget.IP, thisSvcStatus.TailnetTarget.IP) {
			logger.Debugf("got tailnet target IP %s, want %s, not yet ready", thisSvcStatus.TailnetTarget.IP, wantsEgressCfg.TailnetTarget.IP)
			continue
		}
		if !reflect.DeepEqual(wantsEgressCfg.Ports, thisSvcStatus.Ports) {
			logger.Debugf("got ports %+#v, wants ports %+#v", thisSvcStatus.Ports, wantsEgressCfg.Ports)
			continue
		}
		// appears like the proxy's firewall should be ready to route traffic for this egress service
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
	eps.Endpoints = newEndpoints
	if !reflect.DeepEqual(eps, oldEps) {
		if err := ehr.Update(ctx, eps); err != nil {
			return res, fmt.Errorf("error updating EndpointSlice: %v", err)
		}
	}
	// TODO: or maybe do this elsewhere
	if len(eps.Endpoints) > 0 {
		extSvcName := eps.Labels["tailscale.com/external-service-name"]
		extSvcNamespace := eps.Labels["tailscale.com/external-service-namespace"]
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      extSvcName,
				Namespace: extSvcNamespace,
			},
		}
		if err := ehr.Get(ctx, client.ObjectKeyFromObject(svc), svc); err != nil {
			// unexpected
			return res, fmt.Errorf("error getting ExternalName Service %s/%s: %w", extSvcName, extSvcNamespace, err)
		}
		clusterSvcFQDN := fmt.Sprintf("%s.tailscale.svc.cluster.local", egressServiceName)
		if !strings.EqualFold(svc.Spec.ExternalName, clusterSvcFQDN) {
			svc.Spec.ExternalName = clusterSvcFQDN
			if err := ehr.Update(ctx, svc); err != nil {
				return res, fmt.Errorf("error updating ExternalName service %s/%s: %w", extSvcName, extSvcNamespace, err)
			}
		}
	}
	return res, nil
}
