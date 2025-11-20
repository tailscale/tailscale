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
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/util/httpm"
	"tailscale.com/util/linuxfw"
	"tailscale.com/util/mak"
)

const tailscaleTunInterface = "tailscale0"

// Modified using a build flag to speed up tests.
var testSleepDuration string

// This file contains functionality to run containerboot as a proxy that can
// route cluster traffic to one or more tailnet targets, based on portmapping
// rules read from a configfile. Currently (9/2024) this is only used for the
// Kubernetes operator egress proxies.

// egressProxy knows how to configure firewall rules to route cluster traffic to
// one or more tailnet services.
type egressProxy struct {
	cfgPath string // path to a directory with egress services config files

	nfr linuxfw.NetfilterRunner // never nil

	kc          kubeclient.Client // never nil
	stateSecret string            // name of the kube state Secret

	tsClient *local.Client // never nil

	netmapChan chan ipn.Notify // chan to receive netmap updates on

	podIPv4 string // never empty string, currently only IPv4 is supported

	// tailnetFQDNs is the egress service FQDN to tailnet IP mappings that
	// were last used to configure firewall rules for this proxy.
	// TODO(irbekrm): target addresses are also stored in the state Secret.
	// Evaluate whether we should retrieve them from there and not store in
	// memory at all.
	targetFQDNs map[string][]netip.Prefix

	tailnetAddrs []netip.Prefix // tailnet IPs of this tailnet device

	// shortSleep is the backoff sleep between healthcheck endpoint calls - can be overridden in tests.
	shortSleep time.Duration
	// longSleep is the time to sleep after the routing rules are updated to increase the chance that kube
	// proxies on all nodes have updated their routing configuration. It can be configured to 0 in
	// tests.
	longSleep time.Duration
	// client is a client that can send HTTP requests.
	client httpClient
}

// httpClient is a client that can send HTTP requests and can be mocked in tests.
type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

// run configures egress proxy firewall rules and ensures that the firewall rules are reconfigured when:
// - the mounted egress config has changed
// - the proxy's tailnet IP addresses have changed
// - tailnet IPs have changed for any backend targets specified by tailnet FQDN
func (ep *egressProxy) run(ctx context.Context, n ipn.Notify, opts egressProxyRunOpts) error {
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
		if err := w.Add(ep.cfgPath); err != nil {
			return fmt.Errorf("failed to add fsnotify watch: %w", err)
		}
		eventChan = w.Events
	}

	if err := ep.sync(ctx, n); err != nil {
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
		case n = <-ep.netmapChan:
			shouldResync := ep.shouldResync(n)
			if !shouldResync {
				continue
			}
			log.Printf("netmap change detected, ensuring firewall config is up to date...")
		}
		if err := ep.sync(ctx, n); err != nil {
			return fmt.Errorf("error syncing egress service config: %w", err)
		}
	}
}

type egressProxyRunOpts struct {
	cfgPath      string
	nfr          linuxfw.NetfilterRunner
	kc           kubeclient.Client
	tsClient     *local.Client
	stateSecret  string
	netmapChan   chan ipn.Notify
	podIPv4      string
	tailnetAddrs []netip.Prefix
}

// applyOpts configures egress proxy using the provided options.
func (ep *egressProxy) configure(opts egressProxyRunOpts) {
	ep.cfgPath = opts.cfgPath
	ep.nfr = opts.nfr
	ep.kc = opts.kc
	ep.tsClient = opts.tsClient
	ep.stateSecret = opts.stateSecret
	ep.netmapChan = opts.netmapChan
	ep.podIPv4 = opts.podIPv4
	ep.tailnetAddrs = opts.tailnetAddrs
	ep.client = &http.Client{} // default HTTP client
	sleepDuration := time.Second
	if d, err := time.ParseDuration(testSleepDuration); err == nil && d > 0 {
		log.Printf("using test sleep duration %v", d)
		sleepDuration = d
	}
	ep.shortSleep = sleepDuration
	ep.longSleep = sleepDuration * 10
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
				rulesToDelete = append(rulesToDelete, rule{tailnetPort: ports.TargetPort, containerPort: ports.MatchPort, protocol: ports.Protocol, tailnetIP: ip})
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
	svcsCfg := filepath.Join(ep.cfgPath, egressservices.KeyEgressServices)
	j, err := os.ReadFile(svcsCfg)
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
					return true
				}
				break
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
// configuration. For any rules that do not exist, calling this function is a
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

// registerHandlers adds a new handler to the provided ServeMux that can be called as a Kubernetes prestop hook to
// delay shutdown till it's safe to do so.
func (ep *egressProxy) registerHandlers(mux *http.ServeMux) {
	mux.Handle(fmt.Sprintf("GET %s", kubetypes.EgessServicesPreshutdownEP), ep)
}

// ServeHTTP serves /internal-egress-services-preshutdown endpoint, when it receives a request, it periodically polls
// the configured health check endpoint for each egress service till it the health check endpoint no longer hits this
// proxy Pod. It uses the Pod-IPv4 header to verify if health check response is received from this Pod.
func (ep *egressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfgs, err := ep.getConfigs()
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving egress services configs: %v", err), http.StatusInternalServerError)
		return
	}
	if cfgs == nil {
		if _, err := w.Write([]byte("safe to terminate")); err != nil {
			http.Error(w, fmt.Sprintf("error writing termination status: %v", err), http.StatusInternalServerError)
		}
		return
	}
	hp, err := ep.getHEPPings()
	if err != nil {
		http.Error(w, fmt.Sprintf("error determining the number of times health check endpoint should be pinged: %v", err), http.StatusInternalServerError)
		return
	}
	ep.waitTillSafeToShutdown(r.Context(), cfgs, hp)
}

// waitTillSafeToShutdown looks up all egress targets configured to be proxied via this instance and, for each target
// whose configuration includes a healthcheck endpoint, pings the endpoint till none of the responses
// are returned by this instance or till the HTTP request times out. In practice, the endpoint will be a Kubernetes Service for whom one of the backends
// would normally be this Pod. When this Pod is being deleted, the operator should have removed it from the Service
// backends and eventually kube proxy routing rules should be updated to no longer route traffic for the Service to this
// Pod.
func (ep *egressProxy) waitTillSafeToShutdown(ctx context.Context, cfgs *egressservices.Configs, hp int) {
	if cfgs == nil || len(*cfgs) == 0 { // avoid sleeping if no services are configured
		return
	}
	log.Printf("Ensuring that cluster traffic for egress targets is no longer routed via this Pod...")
	var wg sync.WaitGroup
	for s, cfg := range *cfgs {
		hep := cfg.HealthCheckEndpoint
		if hep == "" {
			log.Printf("Tailnet target %q does not have a cluster healthcheck specified, unable to verify if cluster traffic for the target is still routed via this Pod", s)
			continue
		}
		svc := s
		wg.Go(func() {
			log.Printf("Ensuring that cluster traffic is no longer routed to %q via this Pod...", svc)
			for {
				if ctx.Err() != nil { // kubelet's HTTP request timeout
					log.Printf("Cluster traffic for %s did not stop being routed to this Pod.", svc)
					return
				}
				found, err := lookupPodRoute(ctx, hep, ep.podIPv4, hp, ep.client)
				if err != nil {
					log.Printf("unable to reach endpoint %q, assuming the routing rules for this Pod have been deleted: %v", hep, err)
					break
				}
				if !found {
					log.Printf("service %q is no longer routed through this Pod", svc)
					break
				}
				log.Printf("service %q is still routed through this Pod, waiting...", svc)
				time.Sleep(ep.shortSleep)
			}
		})
	}
	wg.Wait()
	// The check above really only checked that the routing rules are updated on this node. Sleep for a bit to
	// ensure that the routing rules are updated on other nodes. TODO(irbekrm): this may or may not be good enough.
	// If it's not good enough, we'd probably want to do something more complex, where the proxies check each other.
	log.Printf("Sleeping for %s before shutdown to ensure that kube proxies on all nodes have updated routing configuration", ep.longSleep)
	time.Sleep(ep.longSleep)
}

// lookupPodRoute calls the healthcheck endpoint repeat times and returns true if the endpoint returns with the podIP
// header at least once.
func lookupPodRoute(ctx context.Context, hep, podIP string, repeat int, client httpClient) (bool, error) {
	for range repeat {
		f, err := lookup(ctx, hep, podIP, client)
		if err != nil {
			return false, err
		}
		if f {
			return true, nil
		}
	}
	return false, nil
}

// lookup calls the healthcheck endpoint and returns true if the response contains the podIP header.
func lookup(ctx context.Context, hep, podIP string, client httpClient) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, httpm.GET, hep, nil)
	if err != nil {
		return false, fmt.Errorf("error creating new HTTP request: %v", err)
	}

	// Close the TCP connection to ensure that the next request is routed to a different backend.
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Endpoint %q can not be reached: %v, likely because there are no (more) healthy backends", hep, err)
		return true, nil
	}
	defer resp.Body.Close()
	gotIP := resp.Header.Get(kubetypes.PodIPv4Header)
	return strings.EqualFold(podIP, gotIP), nil
}

// getHEPPings gets the number of pings that should be sent to a health check endpoint to ensure that each configured
// backend is hit. This assumes that a health check endpoint is a Kubernetes Service and traffic to backend Pods is
// round robin load balanced.
func (ep *egressProxy) getHEPPings() (int, error) {
	hepPingsPath := filepath.Join(ep.cfgPath, egressservices.KeyHEPPings)
	j, err := os.ReadFile(hepPingsPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return -1, err
	}
	if len(j) == 0 || string(j) == "" {
		return 0, nil
	}
	hp, err := strconv.Atoi(string(j))
	if err != nil {
		return -1, fmt.Errorf("error parsing hep pings as int: %v", err)
	}
	if hp < 0 {
		log.Printf("[unexpected] hep pings is negative: %d", hp)
		return 0, nil
	}
	return hp, nil
}
