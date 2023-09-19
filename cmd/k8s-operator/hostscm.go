// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet and to make Tailscale nodes available to cluster
// workloads
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/kube"
	"tailscale.com/util/mak"
)

const dnsConfigKey = "dns.json"

// hostsCMConfig contains the config needed to update ts.net config for a
// particular egress proxy
type hostsCMConfig struct {
	// IP of the Tailscale node that we are setting up egress for
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
// mapping of Tailscale node FQDN to its egress proxy kube Service IP. If
// successful, returns the Tailscale nodes FQDN
func (h *hostsCMProvisioner) Provision(ctx context.Context, logger *zap.SugaredLogger, hcc *hostsCMConfig) (string, error) {
	fqdn, err := h.updateDNSConfig(ctx, logger, hcc, func(dnsCfg *kube.DNSConfig, fqdn string) error {
		proxySvc, err := getSingleObject[corev1.Service](ctx, h.Client, h.tsNamespace, hcc.serviceLabels)
		if apierrors.IsNotFound(err) {
			// we will reconcile again on proxy Service creation/update
			// event and the hosts config will get updated then
			logger.Debugf("proxy Service not yet created waiting...")
			return nil
		}
		if err != nil {
			logger.Errorf("error retrieving proxy Service: %v", err)
			return err
		}

		if proxySvc == nil || proxySvc.Spec.ClusterIP == "" || proxySvc.Spec.ClusterIP == "None" {
			// we will reconcile again on proxy Service creation/update
			// event and the hosts config will get updated then
			logger.Infof("proxy Service for %#+v not yet ready, waiting...", proxySvc)
			return nil
		}
		mak.Set(&dnsCfg.Hosts, fqdn, proxySvc.Spec.ClusterIP)
		return nil
	})
	return fqdn, err
}

func (h *hostsCMProvisioner) Cleanup(ctx context.Context, logger *zap.SugaredLogger, hcc *hostsCMConfig) error {
	_, err := h.updateDNSConfig(ctx, logger, hcc, func(cfg *kube.DNSConfig, fqdn string) error {
		if cfg == nil || cfg.Hosts == nil {
			return nil
		}
		delete(cfg.Hosts, fqdn)
		return nil
	})
	return err
}

func (h *hostsCMProvisioner) updateDNSConfig(ctx context.Context, logger *zap.SugaredLogger, hcc *hostsCMConfig, update func(*kube.DNSConfig, string) error) (string, error) {
	ip := fmt.Sprintf("%s:0", hcc.targetIP)
	whois, err := h.localAPIClient.WhoIs(ctx, ip)
	if err != nil {
		logger.Errorf("error determining Tailscale node: %v", err)
		return "", err
	}
	fqdn := whois.Node.Name
	fqdn = strings.TrimSuffix(fqdn, ".")
	cm := &corev1.ConfigMap{}
	err = h.Get(ctx, types.NamespacedName{Name: dnsConfigMapName, Namespace: h.tsNamespace}, cm)
	if err != nil {
		logger.Errorf("error retrieving hosts config: %v", err)
		return "", err
	}
	oldCm := cm.DeepCopy()

	dnsCfg := &kube.DNSConfig{}
	if cm.Data != nil && cm.Data[dnsConfigKey] != "" {
		if err := json.Unmarshal([]byte(cm.Data[dnsConfigKey]), &dnsCfg); err != nil {
			logger.Errorf("error unmarshaling DNS config %v", err)
			return "", err
		}
	}

	err = update(dnsCfg, fqdn)
	if err != nil {
		logger.Errorf("error updating DNS config: %v", err)
	}

	hostsBytes, err := json.Marshal(dnsCfg)
	if err != nil {
		logger.Errorf("error marshaling DNS config %v", err)
		return "", err
	}

	mak.Set(&cm.Data, dnsConfigKey, string(hostsBytes))

	if apiequality.Semantic.DeepEqual(oldCm, cm) {
		return fqdn, nil
	}

	if err := h.Update(ctx, cm); err != nil {
		logger.Errorf("failed to update ts.net DNS config: %v", err)
		return "", err
	}
	return fqdn, nil
}
