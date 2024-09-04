// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	kube "tailscale.com/k8s-operator"
	"tailscale.com/util/mak"
)

// Reconciles Services with tailscale.com/tailnet-ip annotation and
// tailscale.com/proxy-group label.
type egressHAServiceReconciler struct {
	client.Client
	logger *zap.SugaredLogger
}

func (ehr *egressHAServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := ehr.logger.With("Service", req.NamespacedName)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	svc := new(corev1.Service)
	err = ehr.Get(ctx, req.NamespacedName, svc)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Service not found")
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Service: %w", err)
	}
	if !svc.DeletionTimestamp.IsZero() {
		logger.Debugf("Service is being deleted")
		// TODO: cleanup
		return res, nil
	}

	// TODO: probably will have to switch to an annotation as else it's too confusing
	proxyGroupName := svc.Labels["tailscale.com/proxy-group"]
	if proxyGroupName == "" {
		logger.Debugf("not reconciling Service without tailscale.com/proxy-group label")
		return res, nil
	}
	// TODO: also validate that the ProxyGroup is for egress service type

	tailnetIP := svc.Annotations["tailscale.com/tailnet-ip"]
	if tailnetIP == "" {
		logger.Debugf("not reconciling Service without tailscale.com/tailnet-ip annotation")
		return res, nil
	}
	// get the egress services config for these proxies
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-egress-services", proxyGroupName),
			Namespace: "tailscale", // hardcoded for this prototype
		},
	}
	err = ehr.Get(ctx, client.ObjectKeyFromObject(cm), cm)
	if apierrors.IsNotFound(err) {
		logger.Debugf("egress services ConfigMap for %s not yet created, waiting", proxyGroupName)
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("error retrieving egress service config map for %s", proxyGroupName)
	}
	oldCM := cm.DeepCopy()
	config := &kube.EgressServices{}
	if len(cm.BinaryData["cfg"]) != 0 {
		if err := json.Unmarshal(cm.BinaryData["cfg"], config); err != nil {
			return res, fmt.Errorf("error unmarshaling egress services config %v: %v", cm.BinaryData["cfg"], err)
		}
	}

	svcConfig := kube.EgressService{
		TailnetTarget: kube.TailnetTarget{
			IP: tailnetIP,
		},
		Ports: []kube.PortMap{},
	}

	oldSvcSpec := svc.DeepCopy()
	// TODO: only do this stuff if needed
	svcList := &corev1.ServiceList{}
	if err := ehr.List(ctx, svcList, client.MatchingLabels(map[string]string{"tailscale.com/proxy-group": proxyGroupName})); err != nil {
		return res, fmt.Errorf("error listing Services: %v", err)
	}
	usedPorts := sets.NewInt32()
	for _, s := range svcList.Items {
		for _, p := range s.Spec.Ports {
			usedPorts.Insert(p.Port)
		}
	}
	// loop over ports, for each port that does not yet have a target port set, allocate one
	epsPorts := []discoveryv1.EndpointPort{}
	for i, portmap := range svc.Spec.Ports {
		if portmap.TargetPort.String() == "" || portmap.TargetPort.IntVal == portmap.Port {
			logger.Debugf("need to allocate target port for port %d", portmap.Port)
			// TODO: this is why tailscale.com/proxy-group has to be a label- but we can instead add markers in cache and make it an annotation
			// get a random port
			foundFreePort := false
			var suggestPort int32 = 0
			for !foundFreePort {
				suggestPort = rand.Int32N(4000) + 1 // don't want 0, otherwise doesn't matter, we're root in the container and this is not going to be a sidecar
				if !usedPorts.Has(suggestPort) {
					foundFreePort = true
				}
			}
			svc.Spec.Ports[i].TargetPort = intstr.FromInt32(suggestPort)
		}
		svcConfig.Ports = append(svcConfig.Ports, kube.PortMap{Src: uint16(portmap.Port), Protocol: string(portmap.Protocol), Dst: uint16(svc.Spec.Ports[i].TargetPort.IntVal)})
		epsPorts = append(epsPorts, discoveryv1.EndpointPort{Protocol: &portmap.Protocol, Port: &svc.Spec.Ports[i].TargetPort.IntVal, Name: &svc.Spec.Ports[i].Name})
	}
	if !reflect.DeepEqual(oldSvcSpec, svc.Spec) {
		// update ports only
		if _, err := createOrUpdate(ctx, ehr.Client, svc.Namespace, svc, func(s *corev1.Service) { s.Spec.Ports = svc.Spec.Ports }); err != nil {
			return res, fmt.Errorf("error updating Service: %v", err)
		}
	} else {
		logger.Debugf("update to service not needed")
	}
	// update configmap
	egressSvcName := fmt.Sprintf("%s-%s", svc.Name, svc.Namespace) // TODO: or hostname
	mak.Set(config, egressSvcName, svcConfig)
	bs, err := json.Marshal(config)
	if err != nil {
		return res, fmt.Errorf("error updating service config: %v", err)
	}
	mak.Set(&cm.BinaryData, "cfg", bs)
	if !reflect.DeepEqual(cm, oldCM) {
		if err := ehr.Update(ctx, cm); err != nil {
			return res, fmt.Errorf("error updating ConfigMap: %v", err)
		}
	}
	logger.Debugf("updating EndpointSlice, line 151")
	// ensure EndpointSlice
	// TODO: ports?
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      egressSvcName,
			Namespace: "tailscale",
			Labels: map[string]string{
				"tailscale.com/egress-service":             egressSvcName,
				"tailscale.com/proxy-group":                proxyGroupName,
				"tailscale.com/external-service-name":      svc.Name,
				"tailscale.com/external-service-namespace": svc.Namespace,
				"kubernetes.io/service-name":               egressSvcName,
			},
		},
		AddressType: "IPv4",
		Ports:       epsPorts,
	}
	err = ehr.Get(ctx, client.ObjectKeyFromObject(eps), &discoveryv1.EndpointSlice{})
	if apierrors.IsNotFound(err) {
		logger.Debugf("creating EndpointSlice")
		if err := ehr.Create(ctx, eps); err != nil {
			logger.Debugf("error creating EndpointSlice: %v", err)
			return res, fmt.Errorf("error creating EndpointSlice: %v", err)
		}
	} else if err != nil {
		return res, fmt.Errorf("error retrieving EnpointSlice %s: %w", eps.Name, err)
	}
	// TODO: deal with port update
	logger.Debugf("updating ClusterIP Service, line 174")

	// TODO: will need to generate a different name for the ClusterIP
	// service as else this will prevent from creating egresses in ts
	// namespace. ensure ClusterIP Service
	clusterIPSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      egressSvcName,
			Namespace: "tailscale",
			Labels: map[string]string{"tailscale.com/egress-service": egressSvcName,
				"tailscale.com/proxy-group":                proxyGroupName,
				"tailscale.com/external-service-name":      svc.Name,
				"tailscale.com/external-service-namespace": svc.Namespace,
			},
		},
		Spec: corev1.ServiceSpec{Ports: svc.Spec.Ports, Type: corev1.ServiceTypeClusterIP},
	}
	// TODO: deal with ports update
	err = ehr.Client.Get(ctx, client.ObjectKeyFromObject(clusterIPSvc), &corev1.Service{})
	if apierrors.IsNotFound(err) {
		logger.Debugf("creating ClusterIP Service")
		if err := ehr.Create(ctx, clusterIPSvc); err != nil {
			logger.Debugf("error creating ClusterIP Service: %v", err)
			return res, fmt.Errorf("error creating ClusterIP Service: %v", err)
		}
	} else if err != nil {
		return res, fmt.Errorf("error retrieving ClusterIP Service: %v", err)
	}
	return res, nil
}
