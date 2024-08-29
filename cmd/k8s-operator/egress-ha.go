// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"
	kube "tailscale.com/k8s-operator"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
)

// This reconciler reconciles Tailscale egress Services configured to be exposed
// on a pre-existing ProxyGroup. For each it:
// - sets up a forwarding StatefulSet
// - updates egress service config for the ProxyGroup with a mapping of
// forwarding StatefulSet Pod IPs to tailnet target IP.
type EgressHAReconciler struct {
	client.Client
	ssr    *tailscaleSTSReconciler
	logger *zap.SugaredLogger

	mu sync.Mutex // protects following
	// Temporary for this prototype - the amount of replicas for a StatefulSet
	tempCurrentProxyGroupReplicas int
}

func (er *EgressHAReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := er.logger.With("service-ns", req.Namespace, "service-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	svc := new(corev1.Service)
	err = er.Get(ctx, req.NamespacedName, svc)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("service not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get svc: %w", err)
	}

	// For this prototype only IP target is supported
	tsIP := tailnetTargetAnnotation(svc)
	if tsIP == "" {
		return res, nil
	}

	// For this prototype only.
	// Otherwise services will need tailscale.com/proxy-group label
	// ensure a proxy group fronted with a headless Service (?)
	if err := er.tempCreateProxyGroup(ctx); err != nil {
		return res, fmt.Errorf("error ensuring proxy group: %v", err)
	}
	egressSvcName := fmt.Sprintf("%s-%s", svc.Name, svc.Namespace)
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
	_, ok := svcCfg.Services[egressSvcName]
	if !ok {
		mak.Set(&svcCfg.Services, egressSvcName, kube.EgressService{TailnetTargetIP: tsIP})
	}
	bs, err := json.Marshal(svcCfg)
	if err != nil {
		return res, fmt.Errorf("error marhalling service config: %w", err)
	}
	cm.Data["services"] = string(bs)
	if err := er.Update(ctx, cm); err != nil {
		return res, fmt.Errorf("error updating configmap: %w", err)
	}
	if _, err := er.fwegressHeadlessSvc(ctx, egressSvcName); err != nil {
		return res, fmt.Errorf("error reconciling headless svc:%w", err)
	}
	if _, err := er.fwegressSTS(ctx, egressSvcName); err != nil {
		return res, fmt.Errorf("error reconciling StatefulSet: %w", err)
	}
	return
}

//go:embed deploy/manifests/fwegress.yaml
var fwegressDeploy []byte

func (er *EgressHAReconciler) fwegressSTS(ctx context.Context, name string) (*appsv1.StatefulSet, error) {
	ss := new(appsv1.StatefulSet)
	if err := yaml.Unmarshal(fwegressDeploy, &ss); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fwegress STS: %w", err)
	}
	ss.ObjectMeta.Name = name
	ss.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": name},
	}
	pod := &ss.Spec.Template
	pod.Labels = map[string]string{"app": name, "name": name, "tailscale.com/fwegress": name}
	return createOrUpdate(ctx, er.Client, "tailscale", ss, func(s *appsv1.StatefulSet) { s.Spec = ss.Spec })
}

func (er *EgressHAReconciler) fwegressHeadlessSvc(ctx context.Context, name string) (*corev1.Service, error) {
	hsvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "tailscale",
			Labels:    map[string]string{"app": name},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Selector: map[string]string{
				"app": name,
			},
			IPFamilyPolicy: ptr.To(corev1.IPFamilyPolicyPreferDualStack),
		},
	}
	return createOrUpdate(ctx, er.Client, "tailscale", hsvc, func(svc *corev1.Service) { svc.Spec = hsvc.Spec })
}

// create or get
func (er *EgressHAReconciler) fwegressEPS(ctx context.Context, name string) (*discoveryv1.EndpointSlice, error) {
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

func (er *EgressHAReconciler) tempCreateProxyGroup(ctx context.Context) error {
	er.mu.Lock()
	defer er.mu.Unlock()
	replicas := defaultIntEnv("REPLICAS", 3)
	if replicas == er.tempCurrentProxyGroupReplicas {
		er.logger.Debugf("Proxy group with %d replicas already exists", replicas)
	}
	er.logger.Debugf("Wants a proxy group with %d replicas, currently has %d replicas, updating", replicas, er.tempCurrentProxyGroupReplicas)
	conf := &tailscaleSTSConfig{
		name:     "egress-proxies",
		replicas: int32(replicas),
	}
	if err := er.createConfigMap(ctx, "egress-proxies"); err != nil {
		return fmt.Errorf("error creating ConfigMap: %w", err)
	}
	if _, err := er.ssr.Provision(ctx, er.logger, conf); err != nil {
		return fmt.Errorf("error provision proxy group: %w", err)
	}
	er.tempCurrentProxyGroupReplicas = replicas
	return nil
}

// create if not exists only, no update as another reconciler updates spec
// TODO: SSA
func (er *EgressHAReconciler) createConfigMap(ctx context.Context, name string) error {
	cfg := kube.EgressServices{
		Version: "v1alpha1",
	}
	cfgBS, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("error marshalling config: %w", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "tailscale",
			Labels:    map[string]string{"tailscale.com/proxy-group": name},
		},
		Data: map[string]string{"services": string(cfgBS)},
	}
	err = er.Get(ctx, client.ObjectKeyFromObject(cm), cm)
	if apierrors.IsNotFound(err) {
		return er.Create(ctx, cm)
	}
	if err != nil {
		return fmt.Errorf("error creating ConfigMap: %w", err)
	}
	return nil
}

// defaultEnv returns the value of the given envvar name, or defVal if
// unset.
func defaultIntEnv(name string, defVal int) int {
	v := os.Getenv(name)
	i, err := strconv.Atoi(v)
	if err != nil {
		return defVal
	}
	return i
}
