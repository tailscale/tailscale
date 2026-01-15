// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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
//
// Important: For ExternalName services, cfgs is mutated in-place to include the
// resolved IPs from DNS lookups. These resolved IPs are then persisted to the
// status so that rules can be deleted correctly even if DNS changes later.
func (p *ingressProxy) syncIngressConfigs(cfgs *ingressservices.Configs, status *ingressservices.Status) error {
	rulesToAdd := p.getRulesToAdd(cfgs, status)
	rulesToDelete := p.getRulesToDelete(cfgs, status)

	if err := ensureIngressRulesDeleted(rulesToDelete, p.nfr); err != nil {
		return fmt.Errorf("error deleting ingress rules: %w", err)
	}
	if err := ensureIngressRulesAdded(rulesToAdd, p.nfr); err != nil {
		return fmt.Errorf("error adding ingress rules: %w", err)
	}

	// Merge resolved IPs from rulesToAdd back into cfgs so they get recorded
	// in the status. This is needed for ExternalName services so we know what
	// rules to delete even if DNS changes.
	if cfgs != nil {
		for svcName, cfg := range rulesToAdd {
			if cfg.IsExternalName() && len(cfg.ResolvedIPs) > 0 {
				(*cfgs)[svcName] = cfg
			}
		}
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
// For ExternalName services, rules are also re-added when DNS refresh is needed.
func (p *ingressProxy) getRulesToAdd(cfgs *ingressservices.Configs, status *ingressservices.Status) map[string]ingressservices.Config {
	if cfgs == nil {
		return nil
	}
	now := time.Now()
	var rulesToAdd map[string]ingressservices.Config
	for tsSvc, wantsCfg := range *cfgs {
		if status == nil || !p.isCurrentStatus(status) {
			mak.Set(&rulesToAdd, tsSvc, wantsCfg)
			continue
		}
		gotCfg := status.Configs.GetConfig(tsSvc)
		if gotCfg == nil || !wantsCfg.EqualIgnoringResolved(gotCfg) {
			mak.Set(&rulesToAdd, tsSvc, wantsCfg)
			continue
		}
		// For ExternalName services, check if DNS refresh is needed
		if gotCfg.DNSRefreshNeeded(now) {
			log.Printf("DNS refresh needed for ExternalName service %s (last refresh: %v)",
				tsSvc, time.Unix(gotCfg.LastDNSRefresh, 0))
			mak.Set(&rulesToAdd, tsSvc, wantsCfg)
		}
	}
	return rulesToAdd
}

// getRulesToDelete takes the desired firewall configuration and the recorded
// status and returns a map of Tailscale Services and rules that need to be deleted.
// For ExternalName services, rules are also deleted when DNS refresh is needed
// (so they can be re-created with potentially new IPs).
func (p *ingressProxy) getRulesToDelete(cfgs *ingressservices.Configs, status *ingressservices.Status) map[string]ingressservices.Config {
	if status == nil || !p.isCurrentStatus(status) {
		return nil
	}
	now := time.Now()
	var rulesToDelete map[string]ingressservices.Config
	for tsSvc, gotCfg := range status.Configs {
		if cfgs == nil {
			mak.Set(&rulesToDelete, tsSvc, gotCfg)
			continue
		}
		wantsCfg := cfgs.GetConfig(tsSvc)
		if wantsCfg == nil {
			mak.Set(&rulesToDelete, tsSvc, gotCfg)
			continue
		}
		if !wantsCfg.EqualIgnoringResolved(&gotCfg) {
			mak.Set(&rulesToDelete, tsSvc, gotCfg)
			continue
		}
		// For ExternalName services, delete old rules when DNS refresh is needed
		if gotCfg.DNSRefreshNeeded(now) {
			mak.Set(&rulesToDelete, tsSvc, gotCfg)
		}
	}
	return rulesToDelete
}

// ensureIngressRulesAdded takes a map of Tailscale Services and rules and ensures that the firewall rules are added.
// For ExternalName services, it also updates the config in the map with the resolved IPs.
func ensureIngressRulesAdded(cfgs map[string]ingressservices.Config, nfr linuxfw.NetfilterRunner) error {
	for serviceName, cfg := range cfgs {
		if cfg.IsExternalName() {
			if err := addDNATRulesForExternalName(nfr, serviceName, &cfg); err != nil {
				return fmt.Errorf("error adding ingress rules for ExternalName service %s: %w", serviceName, err)
			}
			// Store the updated config with resolved IPs back into the map
			cfgs[serviceName] = cfg
			continue
		}
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

// addDNATRulesForExternalName resolves the ExternalName DNS and creates DNAT rules
// for each resolved IP address. It also stores the resolved IPs and refresh timestamp
// in the config so they can be used for deletion and periodic re-resolution.
func addDNATRulesForExternalName(nfr linuxfw.NetfilterRunner, serviceName string, cfg *ingressservices.Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	ips, err := net.LookupIP(cfg.ExternalName)
	if err != nil {
		return fmt.Errorf("error resolving ExternalName %q: %w", cfg.ExternalName, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("ExternalName %q resolved to no IP addresses", cfg.ExternalName)
	}

	log.Printf("resolved ExternalName %q to %d IP(s)", cfg.ExternalName, len(ips))
	cfg.LastDNSRefresh = time.Now().Unix()

	// Clear any previously resolved IPs and store new ones
	cfg.ResolvedIPs = nil

	var errs []error
	for _, ip := range ips {
		destIP, ok := netip.AddrFromSlice(ip)
		if !ok {
			log.Printf("warning: could not parse resolved IP %v for %s", ip, cfg.ExternalName)
			continue
		}
		destIP = destIP.Unmap()

		var tsIP netip.Addr
		if destIP.Is4() && cfg.TailscaleServiceIPv4.IsValid() {
			tsIP = cfg.TailscaleServiceIPv4
		} else if destIP.Is6() && cfg.TailscaleServiceIPv6.IsValid() {
			tsIP = cfg.TailscaleServiceIPv6
		} else {
			log.Printf("warning: no matching Tailscale service IP for resolved IP %v (hasIPv4VIP=%v, hasIPv6VIP=%v)",
				destIP, cfg.TailscaleServiceIPv4.IsValid(), cfg.TailscaleServiceIPv6.IsValid())
			continue
		}

		if err := addDNATRuleForSvc(nfr, serviceName, tsIP, destIP); err != nil {
			errs = append(errs, fmt.Errorf("resolved IP %v: %w", destIP, err))
			continue
		}
		cfg.ResolvedIPs = append(cfg.ResolvedIPs, destIP)
	}

	if len(cfg.ResolvedIPs) == 0 {
		if len(errs) > 0 {
			return fmt.Errorf("ExternalName %q: all DNAT rules failed: %w", cfg.ExternalName, errors.Join(errs...))
		}
		return fmt.Errorf("ExternalName %q resolved but no usable IPs (check IPv4/IPv6 VIP configuration)", cfg.ExternalName)
	}
	if len(errs) > 0 {
		log.Printf("warning: some DNAT rules failed for ExternalName %q: %v", cfg.ExternalName, errors.Join(errs...))
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
		if cfg.IsExternalName() {
			if err := deleteDNATRulesForExternalName(nfr, serviceName, &cfg); err != nil {
				return fmt.Errorf("error deleting ingress rules for ExternalName service %s: %w", serviceName, err)
			}
			continue
		}
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

// deleteDNATRulesForExternalName deletes DNAT rules using the stored resolved IPs
// from when the rules were created. This ensures we delete the correct rules even
// if DNS has changed since creation.
func deleteDNATRulesForExternalName(nfr linuxfw.NetfilterRunner, serviceName string, cfg *ingressservices.Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if len(cfg.ResolvedIPs) == 0 {
		// This can happen if the service was never successfully configured
		// (e.g., DNS lookup failed on initial setup). Not an error, but worth noting.
		log.Printf("info: no resolved IPs stored for ExternalName service %s (ExternalName=%q), no rules to delete",
			serviceName, cfg.ExternalName)
		return nil
	}

	var errs []error
	var deleted int
	for _, destIP := range cfg.ResolvedIPs {
		var tsIP netip.Addr
		if destIP.Is4() && cfg.TailscaleServiceIPv4.IsValid() {
			tsIP = cfg.TailscaleServiceIPv4
		} else if destIP.Is6() && cfg.TailscaleServiceIPv6.IsValid() {
			tsIP = cfg.TailscaleServiceIPv6
		} else {
			continue
		}

		if err := deleteDNATRuleForSvc(nfr, serviceName, tsIP, destIP); err != nil {
			errs = append(errs, fmt.Errorf("resolved IP %v: %w", destIP, err))
			continue
		}
		deleted++
	}

	if len(errs) > 0 {
		if deleted == 0 {
			return fmt.Errorf("ExternalName %q: all DNAT rule deletions failed: %w", cfg.ExternalName, errors.Join(errs...))
		}
		log.Printf("warning: some DNAT rule deletions failed for ExternalName %q (deleted %d/%d): %v",
			cfg.ExternalName, deleted, len(cfg.ResolvedIPs), errors.Join(errs...))
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
	if len(*st) != len(*st1) {
		return false
	}
	for name, cfg := range *st {
		cfg1, ok := (*st1)[name]
		if !ok {
			return false
		}
		if !cfg.EqualIgnoringResolved(&cfg1) {
			return false
		}
	}
	return true
}
