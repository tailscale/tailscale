// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"tailscale.com/client/tailscale/apitype"
)

const dnsConfigKey = "dns.json"

// hostsCMConfig contains the config needed to update ts.net config for a
// particular egress proxy
type hostsCMConfig struct {
	// IP of the Tailscale service that we are setting up egress for
	targetIP string
	// serviceLabels identify the proxy service
	serviceLabels map[string]string
}

// hostsCMProvisioner knows how to update ts.net nameserver config as egress
// proxy Services get added/deleted
type hostsCMProvisioner struct {
	// Client reads from cache first, then kube-apiserver, writes to
	// kube-apiserver
	client.Client
	// namespace in which tailscale resources get provisioned
	tsNamespace string
	// localClient knows how to talk to tailscaled local API
	localAPIClient localClient
}

type localClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// Provision ensures that ts.net nameserver config has been updated with a
// mapping of Tailscale service to its egress proxy kube Service IP. If
// successful, returns the Tailscale service FQDN
func (h *hostsCMProvisioner) Provision(ctx context.Context, logger *zap.SugaredLogger, hcc *hostsCMConfig) (string, error) {
	ip := fmt.Sprintf("%s:0", hcc.targetIP)
	whois, err := h.localAPIClient.WhoIs(ctx, ip)
	if err != nil {
		logger.Errorf("error determining tailscale service: %v", err)
		return "", err
	}
	fqdn := whois.Node.Name
	fqdn = strings.TrimSuffix(fqdn, ".")

	logger.Debugf("ensuring a ts.net record for %s: %s", ip, fqdn)

	proxySvc, err := getSingleObject[corev1.Service](ctx, h.Client, h.tsNamespace, hcc.serviceLabels)
	if apierrors.IsNotFound(err) {
		// we will reconcile again on proxy Service creation/update
		// event and the hosts config will get updated then
		logger.Debugf("proxy Service not yet created waiting...")
		return "", nil
	}
	if err != nil {
		logger.Errorf("error retrieving proxy Service: %v", err)
		return "", err
	}

	if proxySvc == nil || proxySvc.Spec.ClusterIP == "" || proxySvc.Spec.ClusterIP == "None" {
		// we will reconcile again on proxy Service creation/update
		// event and the hosts config will get updated then
		logger.Infof("proxy Service for %s not yet ready, waiting...", fqdn)
		return "", nil
	}

	cm := &corev1.ConfigMap{}
	err = h.Get(ctx, types.NamespacedName{Name: dnsConfigMapName, Namespace: h.tsNamespace}, cm)
	if err != nil {
		logger.Errorf("error retrieving hosts config: %v", err)
		return "", err
	}

	hosts := make(map[string]string)
	if cm.Data[dnsConfigKey] != "" {
		if err := json.Unmarshal([]byte(cm.Data[dnsConfigKey]), &hosts); err != nil {
			logger.Errorf("error unmarshaling hosts config %v", err)
			return "", err
		}
	}
	hosts[fqdn] = proxySvc.Spec.ClusterIP
	hostsBytes, err := json.Marshal(hosts)
	if err != nil {
		logger.Errorf("error marshaling hosts config %v", err)
		return "", err
	}

	cm.Data[dnsConfigKey] = string(hostsBytes)

	// TODO (irbekrm): probably better to SSA here
	// TODO (irbekrm): check diff only apply update if needed
	if err := h.Update(ctx, cm); err != nil {
		logger.Errorf("failed to update ts.net DNS config: %v", err)
		return "", err
	}

	return fqdn, nil
}
