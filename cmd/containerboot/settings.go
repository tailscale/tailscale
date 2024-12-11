// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path"
	"strconv"
	"strings"

	"tailscale.com/ipn/conffile"
	"tailscale.com/kube/kubeclient"
)

// settings is all the configuration for containerboot.
type settings struct {
	AuthKey  string
	Hostname string
	Routes   *string
	// ProxyTargetIP is the destination IP to which all incoming
	// Tailscale traffic should be proxied. If empty, no proxying
	// is done. This is typically a locally reachable IP.
	ProxyTargetIP string
	// ProxyTargetDNSName is a DNS name to whose backing IP addresses all
	// incoming Tailscale traffic should be proxied.
	ProxyTargetDNSName string
	// TailnetTargetIP is the destination IP to which all incoming
	// non-Tailscale traffic should be proxied. This is typically a
	// Tailscale IP.
	TailnetTargetIP string
	// TailnetTargetFQDN is an MagicDNS name to which all incoming
	// non-Tailscale traffic should be proxied. This must be a full Tailnet
	// node FQDN.
	TailnetTargetFQDN             string
	ServeConfigPath               string
	DaemonExtraArgs               string
	ExtraArgs                     string
	InKubernetes                  bool
	UserspaceMode                 bool
	StateDir                      string
	AcceptDNS                     *bool
	KubeSecret                    string
	SOCKSProxyAddr                string
	HTTPProxyAddr                 string
	Socket                        string
	AuthOnce                      bool
	Root                          string
	KubernetesCanPatch            bool
	TailscaledConfigFilePath      string
	EnableForwardingOptimizations bool
	// If set to true and, if this containerboot instance is a Kubernetes
	// ingress proxy, set up rules to forward incoming cluster traffic to be
	// forwarded to the ingress target in cluster.
	AllowProxyingClusterTrafficViaIngress bool
	// PodIP is the IP of the Pod if running in Kubernetes. This is used
	// when setting up rules to proxy cluster traffic to cluster ingress
	// target.
	// Deprecated: use PodIPv4, PodIPv6 instead to support dual stack clusters
	PodIP               string
	PodIPv4             string
	PodIPv6             string
	PodUID              string
	HealthCheckAddrPort string
	LocalAddrPort       string
	MetricsEnabled      bool
	HealthCheckEnabled  bool
	DebugAddrPort       string
	EgressSvcsCfgPath   string
}

func configFromEnv() (*settings, error) {
	cfg := &settings{
		AuthKey:                               defaultEnvs([]string{"TS_AUTHKEY", "TS_AUTH_KEY"}, ""),
		Hostname:                              defaultEnv("TS_HOSTNAME", ""),
		Routes:                                defaultEnvStringPointer("TS_ROUTES"),
		ServeConfigPath:                       defaultEnv("TS_SERVE_CONFIG", ""),
		ProxyTargetIP:                         defaultEnv("TS_DEST_IP", ""),
		ProxyTargetDNSName:                    defaultEnv("TS_EXPERIMENTAL_DEST_DNS_NAME", ""),
		TailnetTargetIP:                       defaultEnv("TS_TAILNET_TARGET_IP", ""),
		TailnetTargetFQDN:                     defaultEnv("TS_TAILNET_TARGET_FQDN", ""),
		DaemonExtraArgs:                       defaultEnv("TS_TAILSCALED_EXTRA_ARGS", ""),
		ExtraArgs:                             defaultEnv("TS_EXTRA_ARGS", ""),
		InKubernetes:                          os.Getenv("KUBERNETES_SERVICE_HOST") != "",
		UserspaceMode:                         defaultBool("TS_USERSPACE", true),
		StateDir:                              defaultEnv("TS_STATE_DIR", ""),
		AcceptDNS:                             defaultEnvBoolPointer("TS_ACCEPT_DNS"),
		KubeSecret:                            defaultEnv("TS_KUBE_SECRET", "tailscale"),
		SOCKSProxyAddr:                        defaultEnv("TS_SOCKS5_SERVER", ""),
		HTTPProxyAddr:                         defaultEnv("TS_OUTBOUND_HTTP_PROXY_LISTEN", ""),
		Socket:                                defaultEnv("TS_SOCKET", "/tmp/tailscaled.sock"),
		AuthOnce:                              defaultBool("TS_AUTH_ONCE", false),
		Root:                                  defaultEnv("TS_TEST_ONLY_ROOT", "/"),
		TailscaledConfigFilePath:              tailscaledConfigFilePath(),
		AllowProxyingClusterTrafficViaIngress: defaultBool("EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS", false),
		PodIP:                                 defaultEnv("POD_IP", ""),
		EnableForwardingOptimizations:         defaultBool("TS_EXPERIMENTAL_ENABLE_FORWARDING_OPTIMIZATIONS", false),
		HealthCheckAddrPort:                   defaultEnv("TS_HEALTHCHECK_ADDR_PORT", ""),
		LocalAddrPort:                         defaultEnv("TS_LOCAL_ADDR_PORT", "[::]:9002"),
		MetricsEnabled:                        defaultBool("TS_ENABLE_METRICS", false),
		HealthCheckEnabled:                    defaultBool("TS_ENABLE_HEALTH_CHECK", false),
		DebugAddrPort:                         defaultEnv("TS_DEBUG_ADDR_PORT", ""),
		EgressSvcsCfgPath:                     defaultEnv("TS_EGRESS_SERVICES_CONFIG_PATH", ""),
		PodUID:                                defaultEnv("POD_UID", ""),
	}
	podIPs, ok := os.LookupEnv("POD_IPS")
	if ok {
		ips := strings.Split(podIPs, ",")
		if len(ips) > 2 {
			return nil, fmt.Errorf("POD_IPs can contain at most 2 IPs, got %d (%v)", len(ips), ips)
		}
		for _, ip := range ips {
			parsed, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("error parsing IP address %s: %w", ip, err)
			}
			if parsed.Is4() {
				cfg.PodIPv4 = parsed.String()
				continue
			}
			cfg.PodIPv6 = parsed.String()
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}
	return cfg, nil
}

func (s *settings) validate() error {
	if s.TailscaledConfigFilePath != "" {
		dir, file := path.Split(s.TailscaledConfigFilePath)
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("error validating whether directory with tailscaled config file %s exists: %w", dir, err)
		}
		if _, err := os.Stat(s.TailscaledConfigFilePath); err != nil {
			return fmt.Errorf("error validating whether tailscaled config directory %q contains tailscaled config for current capability version %q: %w. If this is a Tailscale Kubernetes operator proxy, please ensure that the version of the operator is not older than the version of the proxy", dir, file, err)
		}
		if _, err := conffile.Load(s.TailscaledConfigFilePath); err != nil {
			return fmt.Errorf("error validating tailscaled configfile contents: %w", err)
		}
	}
	if s.ProxyTargetIP != "" && s.UserspaceMode {
		return errors.New("TS_DEST_IP is not supported with TS_USERSPACE")
	}
	if s.ProxyTargetDNSName != "" && s.UserspaceMode {
		return errors.New("TS_EXPERIMENTAL_DEST_DNS_NAME is not supported with TS_USERSPACE")
	}
	if s.ProxyTargetDNSName != "" && s.ProxyTargetIP != "" {
		return errors.New("TS_EXPERIMENTAL_DEST_DNS_NAME and TS_DEST_IP cannot both be set")
	}
	if s.TailnetTargetIP != "" && s.UserspaceMode {
		return errors.New("TS_TAILNET_TARGET_IP is not supported with TS_USERSPACE")
	}
	if s.TailnetTargetFQDN != "" && s.UserspaceMode {
		return errors.New("TS_TAILNET_TARGET_FQDN is not supported with TS_USERSPACE")
	}
	if s.TailnetTargetFQDN != "" && s.TailnetTargetIP != "" {
		return errors.New("Both TS_TAILNET_TARGET_IP and TS_TAILNET_FQDN cannot be set")
	}
	if s.TailscaledConfigFilePath != "" && (s.AcceptDNS != nil || s.AuthKey != "" || s.Routes != nil || s.ExtraArgs != "" || s.Hostname != "") {
		return errors.New("TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR cannot be set in combination with TS_HOSTNAME, TS_EXTRA_ARGS, TS_AUTHKEY, TS_ROUTES, TS_ACCEPT_DNS.")
	}
	if s.AllowProxyingClusterTrafficViaIngress && s.UserspaceMode {
		return errors.New("EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS is not supported in userspace mode")
	}
	if s.AllowProxyingClusterTrafficViaIngress && s.ServeConfigPath == "" {
		return errors.New("EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS is set but this is not a cluster ingress proxy")
	}
	if s.AllowProxyingClusterTrafficViaIngress && s.PodIP == "" {
		return errors.New("EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS is set but POD_IP is not set")
	}
	if s.EnableForwardingOptimizations && s.UserspaceMode {
		return errors.New("TS_EXPERIMENTAL_ENABLE_FORWARDING_OPTIMIZATIONS is not supported in userspace mode")
	}
	if s.HealthCheckAddrPort != "" {
		log.Printf("[warning] TS_HEALTHCHECK_ADDR_PORT is deprecated and will be removed in 1.82.0. Please use TS_ENABLE_HEALTH_CHECK and optionally TS_LOCAL_ADDR_PORT instead.")
		if _, err := netip.ParseAddrPort(s.HealthCheckAddrPort); err != nil {
			return fmt.Errorf("error parsing TS_HEALTHCHECK_ADDR_PORT value %q: %w", s.HealthCheckAddrPort, err)
		}
	}
	if s.localMetricsEnabled() || s.localHealthEnabled() {
		if _, err := netip.ParseAddrPort(s.LocalAddrPort); err != nil {
			return fmt.Errorf("error parsing TS_LOCAL_ADDR_PORT value %q: %w", s.LocalAddrPort, err)
		}
	}
	if s.DebugAddrPort != "" {
		if _, err := netip.ParseAddrPort(s.DebugAddrPort); err != nil {
			return fmt.Errorf("error parsing TS_DEBUG_ADDR_PORT value %q: %w", s.DebugAddrPort, err)
		}
	}
	if s.HealthCheckEnabled && s.HealthCheckAddrPort != "" {
		return errors.New("TS_HEALTHCHECK_ADDR_PORT is deprecated and will be removed in 1.82.0, use TS_ENABLE_HEALTH_CHECK and optionally TS_LOCAL_ADDR_PORT")
	}
	return nil
}

// setupKube is responsible for doing any necessary configuration and checks to
// ensure that tailscale state storage and authentication mechanism will work on
// Kubernetes.
func (cfg *settings) setupKube(ctx context.Context, kc *kubeClient) error {
	if cfg.KubeSecret == "" {
		return nil
	}
	canPatch, canCreate, err := kc.CheckSecretPermissions(ctx, cfg.KubeSecret)
	if err != nil {
		return fmt.Errorf("some Kubernetes permissions are missing, please check your RBAC configuration: %v", err)
	}
	cfg.KubernetesCanPatch = canPatch
	kc.canPatch = canPatch

	s, err := kc.GetSecret(ctx, cfg.KubeSecret)
	if err != nil {
		if !kubeclient.IsNotFoundErr(err) {
			return fmt.Errorf("getting Tailscale state Secret %s: %v", cfg.KubeSecret, err)
		}

		if !canCreate {
			return fmt.Errorf("tailscale state Secret %s does not exist and we don't have permissions to create it. "+
				"If you intend to store tailscale state elsewhere than a Kubernetes Secret, "+
				"you can explicitly set TS_KUBE_SECRET env var to an empty string. "+
				"Else ensure that RBAC is set up that allows the service account associated with this installation to create Secrets.", cfg.KubeSecret)
		}
	}

	// Return early if we already have an auth key.
	if cfg.AuthKey != "" || isOneStepConfig(cfg) {
		return nil
	}

	if s == nil {
		log.Print("TS_AUTHKEY not provided and state Secret does not exist, login will be interactive if needed.")
		return nil
	}

	keyBytes, _ := s.Data["authkey"]
	key := string(keyBytes)

	if key != "" {
		// Enforce that we must be able to patch out the authkey after
		// authenticating if you want to use this feature. This avoids
		// us having to deal with the case where we might leave behind
		// an unnecessary reusable authkey in a secret, like a rake in
		// the grass.
		if !cfg.KubernetesCanPatch {
			return errors.New("authkey found in TS_KUBE_SECRET, but the pod doesn't have patch permissions on the Secret to manage the authkey.")
		}
		cfg.AuthKey = key
	}

	log.Print("No authkey found in state Secret and TS_AUTHKEY not provided, login will be interactive if needed.")

	return nil
}

// isTwoStepConfigAuthOnce returns true if the Tailscale node should be configured
// in two steps and login should only happen once.
// Step 1: run 'tailscaled'
// Step 2):
// A) if this is the first time starting this node run 'tailscale up --authkey <authkey> <config opts>'
// B) if this is not the first time starting this node run 'tailscale set <config opts>'.
func isTwoStepConfigAuthOnce(cfg *settings) bool {
	return cfg.AuthOnce && cfg.TailscaledConfigFilePath == ""
}

// isTwoStepConfigAlwaysAuth returns true if the Tailscale node should be configured
// in two steps and we should log in every time it starts.
// Step 1: run 'tailscaled'
// Step 2): run 'tailscale up --authkey <authkey> <config opts>'
func isTwoStepConfigAlwaysAuth(cfg *settings) bool {
	return !cfg.AuthOnce && cfg.TailscaledConfigFilePath == ""
}

// isOneStepConfig returns true if the Tailscale node should always be ran and
// configured in a single step by running 'tailscaled <config opts>'
func isOneStepConfig(cfg *settings) bool {
	return cfg.TailscaledConfigFilePath != ""
}

// isL3Proxy returns true if the Tailscale node needs to be configured to act
// as an L3 proxy, proxying to an endpoint provided via one of the config env
// vars.
func isL3Proxy(cfg *settings) bool {
	return cfg.ProxyTargetIP != "" || cfg.ProxyTargetDNSName != "" || cfg.TailnetTargetIP != "" || cfg.TailnetTargetFQDN != "" || cfg.AllowProxyingClusterTrafficViaIngress || cfg.EgressSvcsCfgPath != ""
}

// hasKubeStateStore returns true if the state must be stored in a Kubernetes
// Secret.
func hasKubeStateStore(cfg *settings) bool {
	return cfg.InKubernetes && cfg.KubernetesCanPatch && cfg.KubeSecret != ""
}

func (cfg *settings) localMetricsEnabled() bool {
	return cfg.LocalAddrPort != "" && cfg.MetricsEnabled
}

func (cfg *settings) localHealthEnabled() bool {
	return cfg.LocalAddrPort != "" && cfg.HealthCheckEnabled
}

// defaultEnv returns the value of the given envvar name, or defVal if
// unset.
func defaultEnv(name, defVal string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return defVal
}

// defaultEnvStringPointer returns a pointer to the given envvar value if set, else
// returns nil. This is useful in cases where we need to distinguish between a
// variable being set to empty string vs unset.
func defaultEnvStringPointer(name string) *string {
	if v, ok := os.LookupEnv(name); ok {
		return &v
	}
	return nil
}

// defaultEnvBoolPointer returns a pointer to the given envvar value if set, else
// returns nil. This is useful in cases where we need to distinguish between a
// variable being explicitly set to false vs unset.
func defaultEnvBoolPointer(name string) *bool {
	v := os.Getenv(name)
	ret, err := strconv.ParseBool(v)
	if err != nil {
		return nil
	}
	return &ret
}

func defaultEnvs(names []string, defVal string) string {
	for _, name := range names {
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
	}
	return defVal
}

// defaultBool returns the boolean value of the given envvar name, or
// defVal if unset or not a bool.
func defaultBool(name string, defVal bool) bool {
	v := os.Getenv(name)
	ret, err := strconv.ParseBool(v)
	if err != nil {
		return defVal
	}
	return ret
}
