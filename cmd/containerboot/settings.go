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
	PodIP               string
	HealthCheckAddrPort string
	EgressSvcsCfgPath   string
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
		if _, err := netip.ParseAddrPort(s.HealthCheckAddrPort); err != nil {
			return fmt.Errorf("error parsing TS_HEALTH_CHECK_ADDR_PORT value %q: %w", s.HealthCheckAddrPort, err)
		}
	}
	return nil
}

// setupKube is responsible for doing any necessary configuration and checks to
// ensure that tailscale state storage and authentication mechanism will work on
// Kubernetes.
func (cfg *settings) setupKube(ctx context.Context) error {
	if cfg.KubeSecret == "" {
		return nil
	}
	canPatch, canCreate, err := kc.CheckSecretPermissions(ctx, cfg.KubeSecret)
	if err != nil {
		return fmt.Errorf("Some Kubernetes permissions are missing, please check your RBAC configuration: %v", err)
	}
	cfg.KubernetesCanPatch = canPatch

	s, err := kc.GetSecret(ctx, cfg.KubeSecret)
	if err != nil && kubeclient.IsNotFoundErr(err) && !canCreate {
		return fmt.Errorf("Tailscale state Secret %s does not exist and we don't have permissions to create it. "+
			"If you intend to store tailscale state elsewhere than a Kubernetes Secret, "+
			"you can explicitly set TS_KUBE_SECRET env var to an empty string. "+
			"Else ensure that RBAC is set up that allows the service account associated with this installation to create Secrets.", cfg.KubeSecret)
	} else if err != nil && !kubeclient.IsNotFoundErr(err) {
		return fmt.Errorf("Getting Tailscale state Secret %s: %v", cfg.KubeSecret, err)
	}

	if cfg.AuthKey == "" && !isOneStepConfig(cfg) {
		if s == nil {
			log.Print("TS_AUTHKEY not provided and kube secret does not exist, login will be interactive if needed.")
			return nil
		}
		keyBytes, _ := s.Data["authkey"]
		key := string(keyBytes)

		if key != "" {
			// This behavior of pulling authkeys from kube secrets was added
			// at the same time as the patch permission, so we can enforce
			// that we must be able to patch out the authkey after
			// authenticating if you want to use this feature. This avoids
			// us having to deal with the case where we might leave behind
			// an unnecessary reusable authkey in a secret, like a rake in
			// the grass.
			if !cfg.KubernetesCanPatch {
				return errors.New("authkey found in TS_KUBE_SECRET, but the pod doesn't have patch permissions on the secret to manage the authkey.")
			}
			cfg.AuthKey = key
		} else {
			log.Print("No authkey found in kube secret and TS_AUTHKEY not provided, login will be interactive if needed.")
		}
	}
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
