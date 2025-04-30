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

type ingressProxy struct {
	cfgPath string // path to a directory with ingress services config files

	nfr linuxfw.NetfilterRunner // never nil

	kc          kubeclient.Client // never nil
	stateSecret string            // name of the kube state Secret

	podIP string // never empty string
}

func (ep *ingressProxy) run(ctx context.Context, opts ingressProxyOpts) error {
	log.Printf("starting ingress proxy...")
	ep.configure(opts)
	var tickChan <-chan time.Time
	var eventChan <-chan fsnotify.Event
	// TODO (irbekrm): take a look if this can be pulled into a single func
	// shared with serve config loader.
	if w, err := fsnotify.NewWatcher(); err != nil {
		log.Printf("failed to create fsnotify watcher, timer-only mode: %v", err)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		tickChan = ticker.C
	} else {
		defer w.Close()
		dir := filepath.Dir(ep.cfgPath)
		if err := w.Add(dir); err != nil {
			return fmt.Errorf("failed to add fsnotify watch for %v: %w", dir, err)
		}
		eventChan = w.Events
	}

	if err := ep.sync(ctx); err != nil {
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
		if err := ep.sync(ctx); err != nil {
			return fmt.Errorf("error syncing ingress service config: %w", err)
		}
	}
}

type ingressProxyOpts struct {
	cfgPath     string
	nfr         linuxfw.NetfilterRunner
	kc          kubeclient.Client
	stateSecret string
	podIP       string // TODO: change to IP hash maybe
}

// applyOpts configures egress proxy using the provided options.
func (ep *ingressProxy) configure(opts ingressProxyOpts) {
	ep.cfgPath = opts.cfgPath
	ep.nfr = opts.nfr
	ep.kc = opts.kc
	ep.stateSecret = opts.stateSecret
	ep.podIP = opts.podIP
}

func (ep *ingressProxy) sync(ctx context.Context) error {
	cfgs, err := ep.getConfigs()
	if err != nil {
		return fmt.Errorf("error retrieving ingress service configs: %w", err)
	}
	status, err := ep.getStatus(ctx)
	if err != nil {
		return fmt.Errorf("error retrieving current ingress proxy status: %w", err)
	}
	// get status
	if err := ep.syncIngressConfigs(cfgs, status); err != nil {
		return fmt.Errorf("error syncing ingress service configs: %w", err)
	}
	var existingConfigs *ingressservices.Configs
	if status != nil {
		existingConfigs = &status.Configs
	}
	if !ingresServicesStatusIsEqual(cfgs, existingConfigs) {
		if err := ep.setStatus(ctx, cfgs); err != nil {
			return fmt.Errorf("error setting ingress proxy status: %w", err)
		}
	}
	return nil
}

func (ep *ingressProxy) getRulesToDelete(cfgs *ingressservices.Configs, status *ingressservices.Status) (rulesToDelete map[string]ingressservices.Config) {
	if status == nil {
		return nil
	}
	for svcName, cfg := range status.Configs {
		needed := cfgs.GetConfig(svcName)
		if reflect.DeepEqual(needed, cfg) {
			continue
		}
		mak.Set(&rulesToDelete, svcName, cfg)
	}
	return rulesToDelete
}

func (ep *ingressProxy) getRulesToAdd(cfgs *ingressservices.Configs, status *ingressservices.Status) (rulesToAdd map[string]ingressservices.Config) {
	if cfgs == nil {
		return nil
	}
	for svcName, cfg := range *cfgs {
		if status == nil {
			mak.Set(&rulesToAdd, svcName, cfg)
			continue
		}
		existing := status.Configs.GetConfig(svcName)
		if reflect.DeepEqual(existing, cfg) {
			continue
		}
		mak.Set(&rulesToAdd, svcName, cfg)
	}
	return rulesToAdd
}

func (ep *ingressProxy) syncIngressConfigs(cfgs *ingressservices.Configs, status *ingressservices.Status) error {
	// Add new services, update rules for any that have changed.
	rulesToAdd := ep.getRulesToAdd(cfgs, status)
	rulesToDelete := ep.getRulesToDelete(cfgs, status)

	if err := ensureIngressRulesDeleted(rulesToDelete, ep.nfr); err != nil {
		return fmt.Errorf("error deleting ingress rules: %w", err)
	}
	if err := ensureIngressRulesAdded(rulesToAdd, ep.nfr); err != nil {
		return fmt.Errorf("error adding rules: %w", err)
	}
	// Maybe SNAT?
	return nil
}

// getConfigs gets the mounted egress service configuration.
func (ep *ingressProxy) getConfigs() (*ingressservices.Configs, error) {
	j, err := os.ReadFile(ep.cfgPath)
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

// getStatus gets the current status of the configured firewall. The current
// status is stored in state Secret. Returns nil status if no status that
// applies to the current proxy Pod was found. Uses the Pod IP to determine if a
// status found in the state Secret applies to this proxy Pod.
func (ep *ingressProxy) getStatus(ctx context.Context) (*ingressservices.Status, error) {
	secret, err := ep.kc.GetSecret(ctx, ep.stateSecret)
	if err != nil {
		return nil, fmt.Errorf("error retrieving state secret: %w", err)
	}
	status := &ingressservices.Status{}
	raw, ok := secret.Data[ingressservices.IngressConfigKey]
	if !ok {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(raw), status); err != nil {
		return nil, fmt.Errorf("error unmarshalling previous config: %w", err)
	}
	if reflect.DeepEqual(status.PodIP, ep.podIP) {
		return status, nil
	}
	return nil, nil
}

func (ep *ingressProxy) setStatus(ctx context.Context, newCfg *ingressservices.Configs) error {
	// Pod IP is used to determine if a stored status applies to THIS proxy Pod.
	status := &ingressservices.Status{Configs: *newCfg}
	status.PodIP = ep.podIP
	secret, err := ep.kc.GetSecret(ctx, ep.stateSecret)
	if err != nil {
		return fmt.Errorf("error retrieving state Secret: %w", err)
	}
	bs, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("error marshalling service config: %w", err)
	}
	secret.Data[ingressservices.IngressConfigKey] = bs
	patch := kubeclient.JSONPatch{
		Op:    "replace",
		Path:  fmt.Sprintf("/data/%s", ingressservices.IngressConfigKey),
		Value: bs,
	}
	if err := ep.kc.JSONPatchResource(ctx, ep.stateSecret, kubeclient.TypeSecrets, []kubeclient.JSONPatch{patch}); err != nil {
		return fmt.Errorf("error patching state Secret: %w", err)
	}
	return nil
}

func ensureIngressRulesAdded(cfgs map[string]ingressservices.Config, nfr linuxfw.NetfilterRunner) error {
	for serviceName, cfg := range cfgs {
		f := func(svcName string, vipIP, clusterIP netip.Addr) error {
			log.Printf("ensureIngressRulesAdded VIPService %s with IP %s to cluster IP %s", serviceName, vipIP, clusterIP)
			return nfr.EnsureDNATRuleForSvc(svcName, vipIP, clusterIP)
		}
		if cfg.IPv4Mapping != nil {
			if err := f(serviceName, cfg.IPv4Mapping.VIPServiceIP, cfg.IPv4Mapping.ClusterIP); err != nil {
				return fmt.Errorf("error adding ingress rule for %s: %w", serviceName, err)
			}
		}
		if cfg.IPv6Mapping != nil {
			if err := f(serviceName, cfg.IPv6Mapping.VIPServiceIP, cfg.IPv6Mapping.ClusterIP); err != nil {
				return fmt.Errorf("error adding ingress rule for %s: %w", serviceName, err)
			}
		}
	}
	return nil
}

func ensureIngressRulesDeleted(cfgs map[string]ingressservices.Config, nfr linuxfw.NetfilterRunner) error {
	for serviceName, cfg := range cfgs {
		f := func(svcName string, vipIP, clusterIP netip.Addr) error {
			log.Printf("ensureIngressRulesDeleted VIPService %s with IP %s to cluster IP %s", serviceName, vipIP, clusterIP)
			return nfr.DeleteDNATRuleForSvc(svcName, vipIP, clusterIP)
		}
		if cfg.IPv4Mapping != nil {
			if err := f(serviceName, cfg.IPv4Mapping.VIPServiceIP, cfg.IPv4Mapping.ClusterIP); err != nil {
				return fmt.Errorf("error deleting ingress rule for %s: %w", serviceName, err)
			}
		}
		if cfg.IPv6Mapping != nil {
			if err := f(serviceName, cfg.IPv6Mapping.VIPServiceIP, cfg.IPv6Mapping.ClusterIP); err != nil {
				return fmt.Errorf("error deleting ingress rule for %s: %w", serviceName, err)
			}
		}
	}
	return nil
}

func ingresServicesStatusIsEqual(st, st1 *ingressservices.Configs) bool {
	if st == nil && st1 == nil {
		return true
	}
	if st == nil || st1 == nil {
		return false
	}
	return reflect.DeepEqual(*st, *st1)
}
