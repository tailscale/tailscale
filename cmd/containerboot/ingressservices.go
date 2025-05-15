// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/kube/ingressservices"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/util/linuxfw"
	"tailscale.com/util/mak"
)

// ingressProxy corresponds to a Kubernetes Operator's network layer ingress
// proxy. It configures firewall rules (iptables or nftables) to proxy tailnet
// traffic to Kubernetes Services.  Currently this is only used for network
// layer proxies in HA mode.
type ingressProxy struct {
	cfgPath string // path to ingress configfile.

	// nfr is the netfilter runner used to configure firewall rules.
	// This is going to be either iptables or nftables based runner.
	// Never nil.
	nfr linuxfw.NetfilterRunner

	kc          kubeclient.Client // never nil
	stateSecret string            // Secret that holds Tailscale state

	// Pod's IP addresses are used as an identifier of this particular Pod.
	podIPv4 string // empty if Pod does not have IPv4 address
	podIPv6 string // empty if Pod does not have IPv6 address
}

// run starts the ingress proxy and ensures that firewall rules are set on start
// and refreshed as ingress config changes.
func (p *ingressProxy) run(ctx context.Context, opts ingressProxyOpts) error {
	log.Printf("starting ingress proxy...")
	p.configure(opts)
	var tickChan <-chan time.Time
	var eventChan <-chan fsnotify.Event
	if w, err := fsnotify.NewWatcher(); err != nil {
		log.Printf("failed to create fsnotify watcher, timer-only mode: %v", err)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		tickChan = ticker.C
	} else {
		defer w.Close()
		dir := filepath.Dir(p.cfgPath)
		if err := w.Add(dir); err != nil {
			return fmt.Errorf("failed to add fsnotify watch for %v: %w", dir, err)
		}
		eventChan = w.Events
	}

	if err := p.sync(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tickChan:
			log.Printf("periodic sync, ensuring firewall config is up to date...")
		case <-eventChan:
			log.Printf("config file change detected, ensuring firewall config is up to date...")
		}
		if err := p.sync(ctx); err != nil {
			return fmt.Errorf("error syncing ingress service config: %w", err)
		}
	}
}

// sync reconciles proxy's firewall rules (iptables or nftables) on ingress config changes:
// - ensures that new firewall rules are added
// - ensures that old firewall rules are deleted
// - updates ingress proxy's status in the state Secret
func (p *ingressProxy) sync(ctx context.Context) error {
	// 1. Get the desired firewall configuration
	cfgs, err := p.getConfigs()
	if err != nil {
		return fmt.Errorf("ingress proxy: error retrieving configs: %w", err)
	}

	// 2. Get the recorded firewall status
	status, err := p.getStatus(ctx)
	if err != nil {
		return fmt.Errorf("ingress proxy: error retrieving current status: %w", err)
	}

	// 3. Ensure that firewall configuration is up to date
	if err := p.syncIngressConfigs(cfgs, status); err != nil {
		return fmt.Errorf("ingress proxy: error syncing configs: %w", err)
	}
	var existingConfigs *ingressservices.Configs
	if status != nil {
		existingConfigs = &status.Configs
	}

	// 4. Update the recorded firewall status
	if !(ingressServicesStatusIsEqual(cfgs, existingConfigs) && p.isCurrentStatus(status)) {
		if err := p.recordStatus(ctx, cfgs); err != nil {
			return fmt.Errorf("ingress proxy: error setting status: %w", err)
		}
	}
	return nil
}

// getConfigs returns the desired ingress service configuration from the mounted
// configfile.
func (p *ingressProxy) getConfigs() (*ingressservices.Configs, error) {
	j, err := os.ReadFile(p.cfgPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(j) == 0 || string(j) == "" {
		return nil, nil
	}
	cfg := &ingressservices.Configs{}
	if err := json.Unmarshal(j, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// getStatus gets the recorded status of the configured firewall. The status is
// stored in the proxy's state Secret.  Note that the recorded status might not
// be the current status of the firewall if it belongs to a previous Pod- we
// take that into account further down the line when determining if the desired
// rules are actually present.
func (p *ingressProxy) getStatus(ctx context.Context) (*ingressservices.Status, error) {
	secret, err := p.kc.GetSecret(ctx, p.stateSecret)
	if err != nil {
		return nil, fmt.Errorf("error retrieving state Secret: %w", err)
	}
	status := &ingressservices.Status{}
	raw, ok := secret.Data[ingressservices.IngressConfigKey]
	if !ok {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(raw), status); err != nil {
		return nil, fmt.Errorf("error unmarshalling previous config: %w", err)
	}
	return status, nil
}

// syncIngressConfigs takes the desired firewall configuration and the recorded
// status and ensures that any missing rules are added and no longer needed
// rules are deleted.
func (p *ingressProxy) syncIngressConfigs(cfgs *ingressservices.Configs, status *ingressservices.Status) error {
	rulesToAdd := p.getRulesToAdd(cfgs, status)
	rulesToDelete := p.getRulesToDelete(cfgs, status)

	if err := ensureIngressRulesDeleted(rulesToDelete, p.nfr); err != nil {
		return fmt.Errorf("error deleting ingress rules: %w", err)
	}
	if err := ensureIngressRulesAdded(rulesToAdd, p.nfr); err != nil {
		return fmt.Errorf("error adding ingress rules: %w", err)
	}
	return nil
}

// recordStatus writes the configured firewall status to the proxy's state
// Secret. This allows the Kubernetes Operator to determine whether this proxy
// Pod has setup firewall rules to route traffic for an ingress service.
func (p *ingressProxy) recordStatus(ctx context.Context, newCfg *ingressservices.Configs) error {
	status := &ingressservices.Status{}
	if newCfg != nil {
		status.Configs = *newCfg
	}
	// Pod IPs are used to determine if recorded status applies to THIS proxy Pod.
	status.PodIPv4 = p.podIPv4
	status.PodIPv6 = p.podIPv6
	secret, err := p.kc.GetSecret(ctx, p.stateSecret)
	if err != nil {
		return fmt.Errorf("error retrieving state Secret: %w", err)
	}
	bs, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("error marshalling status: %w", err)
	}
	secret.Data[ingressservices.IngressConfigKey] = bs
	patch := kubeclient.JSONPatch{
		Op:    "replace",
		Path:  fmt.Sprintf("/data/%s", ingressservices.IngressConfigKey),
		Value: bs,
	}
	if err := p.kc.JSONPatchResource(ctx, p.stateSecret, kubeclient.TypeSecrets, []kubeclient.JSONPatch{patch}); err != nil {
		return fmt.Errorf("error patching state Secret: %w", err)
	}
	return nil
}

// getRulesToAdd takes the desired firewall configuration and the recorded
// firewall status and returns a map of missing Tailscale Services and rules.
func (p *ingressProxy) getRulesToAdd(cfgs *ingressservices.Configs, status *ingressservices.Status) map[string]ingressservices.Config {
	if cfgs == nil {
		return nil
	}
	var rulesToAdd map[string]ingressservices.Config
	for tsSvc, wantsCfg := range *cfgs {
		if status == nil || !p.isCurrentStatus(status) {
			mak.Set(&rulesToAdd, tsSvc, wantsCfg)
			continue
		}
		gotCfg := status.Configs.GetConfig(tsSvc)
		if gotCfg == nil || !reflect.DeepEqual(wantsCfg, *gotCfg) {
			mak.Set(&rulesToAdd, tsSvc, wantsCfg)
		}
	}
	return rulesToAdd
}

// getRulesToDelete takes the desired firewall configuration and the recorded
// status and returns a map of Tailscale Services and rules that need to be deleted.
func (p *ingressProxy) getRulesToDelete(cfgs *ingressservices.Configs, status *ingressservices.Status) map[string]ingressservices.Config {
	if status == nil || !p.isCurrentStatus(status) {
		return nil
	}
	var rulesToDelete map[string]ingressservices.Config
	for tsSvc, gotCfg := range status.Configs {
		if cfgs == nil {
			mak.Set(&rulesToDelete, tsSvc, gotCfg)
			continue
		}
		wantsCfg := cfgs.GetConfig(tsSvc)
		if wantsCfg != nil && reflect.DeepEqual(*wantsCfg, gotCfg) {
			continue
		}
		mak.Set(&rulesToDelete, tsSvc, gotCfg)
	}
	return rulesToDelete
}

// ensureIngressRulesAdded takes a map of Tailscale Services and rules and ensures that the firewall rules are added.
func ensureIngressRulesAdded(cfgs map[string]ingressservices.Config, nfr linuxfw.NetfilterRunner) error {
	for serviceName, cfg := range cfgs {
		if cfg.IPv4Mapping != nil {
			if err := addDNATRuleForSvc(nfr, serviceName, cfg.IPv4Mapping.TailscaleServiceIP, cfg.IPv4Mapping.ClusterIP); err != nil {
				return fmt.Errorf("error adding ingress rule for %s: %w", serviceName, err)
			}
		}
		if cfg.IPv6Mapping != nil {
			if err := addDNATRuleForSvc(nfr, serviceName, cfg.IPv6Mapping.TailscaleServiceIP, cfg.IPv6Mapping.ClusterIP); err != nil {
				return fmt.Errorf("error adding ingress rule for %s: %w", serviceName, err)
			}
		}
	}
	return nil
}

func addDNATRuleForSvc(nfr linuxfw.NetfilterRunner, serviceName string, tsIP, clusterIP netip.Addr) error {
	log.Printf("adding DNAT rule for Tailscale Service %s with IP %s to Kubernetes Service IP %s", serviceName, tsIP, clusterIP)
	return nfr.EnsureDNATRuleForSvc(serviceName, tsIP, clusterIP)
}

// ensureIngressRulesDeleted takes a map of Tailscale Services and rules and ensures that the firewall rules are deleted.
func ensureIngressRulesDeleted(cfgs map[string]ingressservices.Config, nfr linuxfw.NetfilterRunner) error {
	for serviceName, cfg := range cfgs {
		if cfg.IPv4Mapping != nil {
			if err := deleteDNATRuleForSvc(nfr, serviceName, cfg.IPv4Mapping.TailscaleServiceIP, cfg.IPv4Mapping.ClusterIP); err != nil {
				return fmt.Errorf("error deleting ingress rule for %s: %w", serviceName, err)
			}
		}
		if cfg.IPv6Mapping != nil {
			if err := deleteDNATRuleForSvc(nfr, serviceName, cfg.IPv6Mapping.TailscaleServiceIP, cfg.IPv6Mapping.ClusterIP); err != nil {
				return fmt.Errorf("error deleting ingress rule for %s: %w", serviceName, err)
			}
		}
	}
	return nil
}

func deleteDNATRuleForSvc(nfr linuxfw.NetfilterRunner, serviceName string, tsIP, clusterIP netip.Addr) error {
	log.Printf("deleting DNAT rule for Tailscale Service %s with IP %s to Kubernetes Service IP %s", serviceName, tsIP, clusterIP)
	return nfr.DeleteDNATRuleForSvc(serviceName, tsIP, clusterIP)
}

// isCurrentStatus returns true if the status of an ingress proxy as read from
// the proxy's state Secret is the status of the current proxy Pod.  We use
// Pod's IP addresses to determine that the status is for this Pod.
func (p *ingressProxy) isCurrentStatus(status *ingressservices.Status) bool {
	if status == nil {
		return true
	}
	return status.PodIPv4 == p.podIPv4 && status.PodIPv6 == p.podIPv6
}

type ingressProxyOpts struct {
	cfgPath     string
	nfr         linuxfw.NetfilterRunner // never nil
	kc          kubeclient.Client       // never nil
	stateSecret string
	podIPv4     string
	podIPv6     string
}

// configure sets the ingress proxy's configuration. It is called once on start
// so we don't care about concurrent access to fields.
func (p *ingressProxy) configure(opts ingressProxyOpts) {
	p.cfgPath = opts.cfgPath
	p.nfr = opts.nfr
	p.kc = opts.kc
	p.stateSecret = opts.stateSecret
	p.podIPv4 = opts.podIPv4
	p.podIPv6 = opts.podIPv6
}

func ingressServicesStatusIsEqual(st, st1 *ingressservices.Configs) bool {
	if st == nil && st1 == nil {
		return true
	}
	if st == nil || st1 == nil {
		return false
	}
	return reflect.DeepEqual(*st, *st1)
}
