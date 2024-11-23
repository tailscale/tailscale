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
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/ipn"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/tailcfg"
	"tailscale.com/util/linuxfw"
	"tailscale.com/util/mak"
)

const tailscaleTunInterface = "tailscale0"

// This file contains functionality to run containerboot as a proxy that can
// route cluster traffic to one or more tailnet targets, based on portmapping
// rules read from a configfile. Currently (9/2024) this is only used for the
// Kubernetes operator egress proxies.

// egressProxy knows how to configure firewall rules to route cluster traffic to
// one or more tailnet services.
type egressProxy struct {
	cfgPath string // path to egress service config file

	nfr linuxfw.NetfilterRunner // never nil

	kc          kubeclient.Client // never nil
	stateSecret string            // name of the kube state Secret

	netmapChan chan ipn.Notify // chan to receive netmap updates on

	podIPv4 string // never empty string, currently only IPv4 is supported

	// tailnetFQDNs is the egress service FQDN to tailnet IP mappings that
	// were last used to configure firewall rules for this proxy.
	// TODO(irbekrm): target addresses are also stored in the state Secret.
	// Evaluate whether we should retrieve them from there and not store in
	// memory at all.
	targetFQDNs map[string][]netip.Prefix

	// used to configure firewall rules.
	tailnetAddrs []netip.Prefix
}

// run configures egress proxy firewall rules and ensures that the firewall rules are reconfigured when:
// - the mounted egress config has changed
// - the proxy's tailnet IP addresses have changed
// - tailnet IPs have changed for any backend targets specified by tailnet FQDN
func (ep *egressProxy) run(ctx context.Context, n ipn.Notify) error {
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
		if err := w.Add(filepath.Dir(ep.cfgPath)); err != nil {
			return fmt.Errorf("failed to add fsnotify watch: %w", err)
		}
		eventChan = w.Events
	}

	if err := ep.sync(ctx, n); err != nil {
		return err
	}
	for {
		var err error
		select {
		case <-ctx.Done():
			return nil
		case <-tickChan:
			err = ep.sync(ctx, n)
		case <-eventChan:
			log.Printf("config file change detected, ensuring firewall config is up to date...")
			err = ep.sync(ctx, n)
		case n = <-ep.netmapChan:
			shouldResync := ep.shouldResync(n)
			if shouldResync {
				log.Printf("netmap change detected, ensuring firewall config is up to date...")
				err = ep.sync(ctx, n)
			}
		}
		if err != nil {
			return fmt.Errorf("error syncing egress service config: %w", err)
		}
	}
}

// sync triggers an egress proxy config resync. The resync calculates the diff between config and status to determine if
// any firewall rules need to be updated. Currently using status in state Secret as a reference for what is the current
// firewall configuration is good enough because - the status is keyed by the Pod IP - we crash the Pod on errors such
// as failed firewall update
func (ep *egressProxy) sync(ctx context.Context, n ipn.Notify) error {
	cfgs, err := ep.getConfigs()
	if err != nil {
		return fmt.Errorf("error retrieving egress service configs: %w", err)
	}
	status, err := ep.getStatus(ctx)
	if err != nil {
		return fmt.Errorf("error retrieving current egress proxy status: %w", err)
	}
	newStatus, err := ep.syncEgressConfigs(cfgs, status, n)
	if err != nil {
		return fmt.Errorf("error syncing egress service configs: %w", err)
	}
	if !servicesStatusIsEqual(newStatus, status) {
		if err := ep.setStatus(ctx, newStatus, n); err != nil {
			return fmt.Errorf("error setting egress proxy status: %w", err)
		}
	}
	return nil
}

// addrsHaveChanged returns true if the provided netmap update contains tailnet address change for this proxy node.
// Netmap must not be nil.
func (ep *egressProxy) addrsHaveChanged(n ipn.Notify) bool {
	return !reflect.DeepEqual(ep.tailnetAddrs, n.NetMap.SelfNode.Addresses())
}

// syncEgressConfigs adds and deletes firewall rules to match the desired
// configuration. It uses the provided status to determine what is currently
// applied and updates the status after a successful sync.
func (ep *egressProxy) syncEgressConfigs(cfgs *egressservices.Configs, status *egressservices.Status, n ipn.Notify) (*egressservices.Status, error) {
	if !(wantsServicesConfigured(cfgs) || hasServicesConfigured(status)) {
		return nil, nil
	}

	// Delete unnecessary services.
	if err := ep.deleteUnnecessaryServices(cfgs, status); err != nil {
		return nil, fmt.Errorf("error deleting services: %w", err)

	}
	newStatus := &egressservices.Status{}
	if !wantsServicesConfigured(cfgs) {
		return newStatus, nil
	}

	// Add new services, update rules for any that have changed.
	rulesPerSvcToAdd := make(map[string][]rule, 0)
	rulesPerSvcToDelete := make(map[string][]rule, 0)
	for svcName, cfg := range *cfgs {
		tailnetTargetIPs, err := ep.tailnetTargetIPsForSvc(cfg, n)
		if err != nil {
			return nil, fmt.Errorf("error determining tailnet target IPs: %w", err)
		}
		rulesToAdd, rulesToDelete, err := updatesForCfg(svcName, cfg, status, tailnetTargetIPs)
		if err != nil {
			return nil, fmt.Errorf("error validating service changes: %v", err)
		}
		log.Printf("syncegressservices: looking at svc %s rulesToAdd %d rulesToDelete %d", svcName, len(rulesToAdd), len(rulesToDelete))
		if len(rulesToAdd) != 0 {
			mak.Set(&rulesPerSvcToAdd, svcName, rulesToAdd)
		}
		if len(rulesToDelete) != 0 {
			mak.Set(&rulesPerSvcToDelete, svcName, rulesToDelete)
		}
		if len(rulesToAdd) != 0 || ep.addrsHaveChanged(n) {
			// For each tailnet target, set up SNAT from the local tailnet device address of the matching
			// family.
			for _, t := range tailnetTargetIPs {
				var local netip.Addr
				for _, pfx := range n.NetMap.SelfNode.Addresses().All() {
					if !pfx.IsSingleIP() {
						continue
					}
					if pfx.Addr().Is4() != t.Is4() {
						continue
					}
					local = pfx.Addr()
					break
				}
				if !local.IsValid() {
					return nil, fmt.Errorf("no valid local IP: %v", local)
				}
				if err := ep.nfr.EnsureSNATForDst(local, t); err != nil {
					return nil, fmt.Errorf("error setting up SNAT rule: %w", err)
				}
			}
		}
		// Update the status. Status will be written back to the state Secret by the caller.
		mak.Set(&newStatus.Services, svcName, &egressservices.ServiceStatus{TailnetTargetIPs: tailnetTargetIPs, TailnetTarget: cfg.TailnetTarget, Ports: cfg.Ports})
	}

	// Actually apply the firewall rules.
	if err := ensureRulesAdded(rulesPerSvcToAdd, ep.nfr); err != nil {
		return nil, fmt.Errorf("error adding rules: %w", err)
	}
	if err := ensureRulesDeleted(rulesPerSvcToDelete, ep.nfr); err != nil {
		return nil, fmt.Errorf("error deleting rules: %w", err)
	}

	return newStatus, nil
}

// updatesForCfg calculates any rules that need to be added or deleted for an individucal egress service config.
func updatesForCfg(svcName string, cfg egressservices.Config, status *egressservices.Status, tailnetTargetIPs []netip.Addr) ([]rule, []rule, error) {
	rulesToAdd := make([]rule, 0)
	rulesToDelete := make([]rule, 0)
	currentConfig, ok := lookupCurrentConfig(svcName, status)

	// If no rules for service are present yet, add them all.
	if !ok {
		for _, t := range tailnetTargetIPs {
			for ports := range cfg.Ports {
				log.Printf("syncegressservices: svc %s adding port %v", svcName, ports)
				rulesToAdd = append(rulesToAdd, rule{tailnetPort: ports.TargetPort, containerPort: ports.MatchPort, protocol: ports.Protocol, tailnetIP: t})
			}
		}
		return rulesToAdd, rulesToDelete, nil
	}

	// If there are no backend targets available, delete any currently configured rules.
	if len(tailnetTargetIPs) == 0 {
		log.Printf("tailnet target for egress service %s does not have any backend addresses, deleting all rules", svcName)
		for _, ip := range currentConfig.TailnetTargetIPs {
			for ports := range currentConfig.Ports {
				rulesToDelete = append(rulesToAdd, rule{tailnetPort: ports.TargetPort, containerPort: ports.MatchPort, protocol: ports.Protocol, tailnetIP: ip})
			}
		}
		return rulesToAdd, rulesToDelete, nil
	}

	// If there are rules present for backend targets that no longer match, delete them.
	for _, ip := range currentConfig.TailnetTargetIPs {
		var found bool
		for _, wantsIP := range tailnetTargetIPs {
			if reflect.DeepEqual(ip, wantsIP) {
				found = true
				break
			}
		}
		if !found {
			for ports := range currentConfig.Ports {
				rulesToDelete = append(rulesToDelete, rule{tailnetPort: ports.TargetPort, containerPort: ports.MatchPort, protocol: ports.Protocol, tailnetIP: ip})
			}
		}
	}

	// Sync rules for the currently wanted backend targets.
	for _, ip := range tailnetTargetIPs {

		// If the backend target is not yet present in status, add all rules.
		var found bool
		for _, gotIP := range currentConfig.TailnetTargetIPs {
			if reflect.DeepEqual(ip, gotIP) {
				found = true
				break
			}
		}
		if !found {
			for ports := range cfg.Ports {
				rulesToAdd = append(rulesToAdd, rule{tailnetPort: ports.TargetPort, containerPort: ports.MatchPort, protocol: ports.Protocol, tailnetIP: ip})
			}
			continue
		}

		// If the backend target is present in status, check that the
		// currently applied rules are up to date.

		// Delete any current portmappings that are no longer present in config.
		for port := range currentConfig.Ports {
			if _, ok := cfg.Ports[port]; ok {
				continue
			}
			rulesToDelete = append(rulesToDelete, rule{tailnetPort: port.TargetPort, containerPort: port.MatchPort, protocol: port.Protocol, tailnetIP: ip})
		}

		// Add any new portmappings.
		for port := range cfg.Ports {
			if _, ok := currentConfig.Ports[port]; ok {
				continue
			}
			rulesToAdd = append(rulesToAdd, rule{tailnetPort: port.TargetPort, containerPort: port.MatchPort, protocol: port.Protocol, tailnetIP: ip})
		}
	}
	return rulesToAdd, rulesToDelete, nil
}

// deleteUnneccessaryServices ensure that any services found on status, but not
// present in config are deleted.
func (ep *egressProxy) deleteUnnecessaryServices(cfgs *egressservices.Configs, status *egressservices.Status) error {
	if !hasServicesConfigured(status) {
		return nil
	}
	if !wantsServicesConfigured(cfgs) {
		for svcName, svc := range status.Services {
			log.Printf("service %s is no longer required, deleting", svcName)
			if err := ensureServiceDeleted(svcName, svc, ep.nfr); err != nil {
				return fmt.Errorf("error deleting service %s: %w", svcName, err)
			}
		}
		return nil
	}

	for svcName, svc := range status.Services {
		if _, ok := (*cfgs)[svcName]; !ok {
			log.Printf("service %s is no longer required, deleting", svcName)
			if err := ensureServiceDeleted(svcName, svc, ep.nfr); err != nil {
				return fmt.Errorf("error deleting service %s: %w", svcName, err)
			}
			// TODO (irbekrm): also delete the SNAT rule here
		}
	}
	return nil
}

// getConfigs gets the mounted egress service configuration.
func (ep *egressProxy) getConfigs() (*egressservices.Configs, error) {
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
	cfg := &egressservices.Configs{}
	if err := json.Unmarshal(j, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// getStatus gets the current status of the configured firewall. The current
// status is stored in state Secret. Returns nil status if no status that
// applies to the current proxy Pod was found. Uses the Pod IP to determine if a
// status found in the state Secret applies to this proxy Pod.
func (ep *egressProxy) getStatus(ctx context.Context) (*egressservices.Status, error) {
	secret, err := ep.kc.GetSecret(ctx, ep.stateSecret)
	if err != nil {
		return nil, fmt.Errorf("error retrieving state secret: %w", err)
	}
	status := &egressservices.Status{}
	raw, ok := secret.Data[egressservices.KeyEgressServices]
	if !ok {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(raw), status); err != nil {
		return nil, fmt.Errorf("error unmarshalling previous config: %w", err)
	}
	if reflect.DeepEqual(status.PodIPv4, ep.podIPv4) {
		return status, nil
	}
	return nil, nil
}

// setStatus writes egress proxy's currently configured firewall to the state
// Secret and updates proxy's tailnet addresses.
func (ep *egressProxy) setStatus(ctx context.Context, status *egressservices.Status, n ipn.Notify) error {
	// Pod IP is used to determine if a stored status applies to THIS proxy Pod.
	if status == nil {
		status = &egressservices.Status{}
	}
	status.PodIPv4 = ep.podIPv4
	secret, err := ep.kc.GetSecret(ctx, ep.stateSecret)
	if err != nil {
		return fmt.Errorf("error retrieving state Secret: %w", err)
	}
	bs, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("error marshalling service config: %w", err)
	}
	secret.Data[egressservices.KeyEgressServices] = bs
	patch := kubeclient.JSONPatch{
		Op:    "replace",
		Path:  fmt.Sprintf("/data/%s", egressservices.KeyEgressServices),
		Value: bs,
	}
	if err := ep.kc.JSONPatchResource(ctx, ep.stateSecret, kubeclient.TypeSecrets, []kubeclient.JSONPatch{patch}); err != nil {
		return fmt.Errorf("error patching state Secret: %w", err)
	}
	ep.tailnetAddrs = n.NetMap.SelfNode.Addresses().AsSlice()
	return nil
}

// tailnetTargetIPsForSvc returns the tailnet IPs to which traffic for this
// egress service should be proxied. The egress service can be configured by IP
// or by FQDN. If it's configured by IP, just return that. If it's configured by
// FQDN, resolve the FQDN and return the resolved IPs. It checks if the
// netfilter runner supports IPv6 NAT and skips any IPv6 addresses if it
// doesn't.
func (ep *egressProxy) tailnetTargetIPsForSvc(svc egressservices.Config, n ipn.Notify) (addrs []netip.Addr, err error) {
	if svc.TailnetTarget.IP != "" {
		addr, err := netip.ParseAddr(svc.TailnetTarget.IP)
		if err != nil {
			return nil, fmt.Errorf("error parsing tailnet target IP: %w", err)
		}
		if addr.Is6() && !ep.nfr.HasIPV6NAT() {
			log.Printf("tailnet target is an IPv6 address, but this host does not support IPv6 in the chosen firewall mode. This will probably not work.")
			return addrs, nil
		}
		return []netip.Addr{addr}, nil
	}

	if svc.TailnetTarget.FQDN == "" {
		return nil, errors.New("unexpected egress service config- neither tailnet target IP nor FQDN is set")
	}
	if n.NetMap == nil {
		log.Printf("netmap is not available, unable to determine backend addresses for %s", svc.TailnetTarget.FQDN)
		return addrs, nil
	}
	var (
		node      tailcfg.NodeView
		nodeFound bool
	)
	for _, nn := range n.NetMap.Peers {
		if equalFQDNs(nn.Name(), svc.TailnetTarget.FQDN) {
			node = nn
			nodeFound = true
			break
		}
	}
	if nodeFound {
		for _, addr := range node.Addresses().AsSlice() {
			if addr.Addr().Is6() && !ep.nfr.HasIPV6NAT() {
				log.Printf("tailnet target %v is an IPv6 address, but this host does not support IPv6 in the chosen firewall mode, skipping.", addr.Addr().String())
				continue
			}
			addrs = append(addrs, addr.Addr())
		}
		// Egress target endpoints configured via FQDN are stored, so
		// that we can determine if a netmap update should trigger a
		// resync.
		mak.Set(&ep.targetFQDNs, svc.TailnetTarget.FQDN, node.Addresses().AsSlice())
	}
	return addrs, nil
}

// shouldResync parses netmap update and returns true if the update contains
// changes for which the egress proxy's firewall should be reconfigured.
func (ep *egressProxy) shouldResync(n ipn.Notify) bool {
	if n.NetMap == nil {
		return false
	}

	// If proxy's tailnet addresses have changed, resync.
	if !reflect.DeepEqual(n.NetMap.SelfNode.Addresses().AsSlice(), ep.tailnetAddrs) {
		log.Printf("node addresses have changed, trigger egress config resync")
		ep.tailnetAddrs = n.NetMap.SelfNode.Addresses().AsSlice()
		return true
	}

	// If the IPs for any of the egress services configured via FQDN have
	// changed, resync.
	for fqdn, ips := range ep.targetFQDNs {
		for _, nn := range n.NetMap.Peers {
			if equalFQDNs(nn.Name(), fqdn) {
				if !reflect.DeepEqual(ips, nn.Addresses().AsSlice()) {
					log.Printf("backend addresses for egress target %q have changed old IPs %v, new IPs %v trigger egress config resync", nn.Name(), ips, nn.Addresses().AsSlice())
				}
				return true
			}
		}
	}
	return false
}

// ensureServiceDeleted ensures that any rules for an egress service are removed
// from the firewall configuration.
func ensureServiceDeleted(svcName string, svc *egressservices.ServiceStatus, nfr linuxfw.NetfilterRunner) error {

	// Note that the portmap is needed for iptables based firewall only.
	// Nftables group rules for a service in a chain, so there is no need to
	// specify individual portmapping based rules.
	pms := make([]linuxfw.PortMap, 0)
	for pm := range svc.Ports {
		pms = append(pms, linuxfw.PortMap{MatchPort: pm.MatchPort, TargetPort: pm.TargetPort, Protocol: pm.Protocol})
	}

	if err := nfr.DeleteSvc(svcName, tailscaleTunInterface, svc.TailnetTargetIPs, pms); err != nil {
		return fmt.Errorf("error deleting service %s: %w", svcName, err)
	}
	return nil
}

// ensureRulesAdded ensures that all portmapping rules are added to the firewall
// configuration. For any rules that already exist, calling this function is a
// no-op. In case of nftables, a service consists of one or two (one per IP
// family) chains that conain the portmapping rules for the service and the
// chains as needed when this function is called.
func ensureRulesAdded(rulesPerSvc map[string][]rule, nfr linuxfw.NetfilterRunner) error {
	for svc, rules := range rulesPerSvc {
		for _, rule := range rules {
			log.Printf("ensureRulesAdded svc %s tailnetTarget %s container port %d tailnet port %d protocol %s", svc, rule.tailnetIP, rule.containerPort, rule.tailnetPort, rule.protocol)
			if err := nfr.EnsurePortMapRuleForSvc(svc, tailscaleTunInterface, rule.tailnetIP, linuxfw.PortMap{MatchPort: rule.containerPort, TargetPort: rule.tailnetPort, Protocol: rule.protocol}); err != nil {
				return fmt.Errorf("error ensuring rule: %w", err)
			}
		}
	}
	return nil
}

// ensureRulesDeleted ensures that the given rules are deleted from the firewall
// configuration. For any rules that do not exist, calling this funcion is a
// no-op.
func ensureRulesDeleted(rulesPerSvc map[string][]rule, nfr linuxfw.NetfilterRunner) error {
	for svc, rules := range rulesPerSvc {
		for _, rule := range rules {
			log.Printf("ensureRulesDeleted svc %s tailnetTarget %s container port %d tailnet port %d protocol %s", svc, rule.tailnetIP, rule.containerPort, rule.tailnetPort, rule.protocol)
			if err := nfr.DeletePortMapRuleForSvc(svc, tailscaleTunInterface, rule.tailnetIP, linuxfw.PortMap{MatchPort: rule.containerPort, TargetPort: rule.tailnetPort, Protocol: rule.protocol}); err != nil {
				return fmt.Errorf("error deleting rule: %w", err)
			}
		}
	}
	return nil
}

func lookupCurrentConfig(svcName string, status *egressservices.Status) (*egressservices.ServiceStatus, bool) {
	if status == nil || len(status.Services) == 0 {
		return nil, false
	}
	c, ok := status.Services[svcName]
	return c, ok
}

func equalFQDNs(s, s1 string) bool {
	s, _ = strings.CutSuffix(s, ".")
	s1, _ = strings.CutSuffix(s1, ".")
	return strings.EqualFold(s, s1)
}

// rule contains configuration for an egress proxy firewall rule.
type rule struct {
	containerPort uint16     // port to match incoming traffic
	tailnetPort   uint16     // tailnet service port
	tailnetIP     netip.Addr // tailnet service IP
	protocol      string
}

func wantsServicesConfigured(cfgs *egressservices.Configs) bool {
	return cfgs != nil && len(*cfgs) != 0
}

func hasServicesConfigured(status *egressservices.Status) bool {
	return status != nil && len(status.Services) != 0
}

func servicesStatusIsEqual(st, st1 *egressservices.Status) bool {
	if st == nil && st1 == nil {
		return true
	}
	if st == nil || st1 == nil {
		return false
	}
	st.PodIPv4 = ""
	st1.PodIPv4 = ""
	return reflect.DeepEqual(*st, *st1)
}
