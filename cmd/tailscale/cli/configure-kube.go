// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
//go:build !ts_omit_kube

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/exp/slices"
	"k8s.io/client-go/util/homedir"
	"sigs.k8s.io/yaml"
)

func init() {
	configureCmd.Subcommands = append(configureCmd.Subcommands, configureKubeconfigCmd)
}

var configureKubeconfigCmd = &ffcli.Command{
	Name:       "kubeconfig",
	ShortHelp:  "Configure kubeconfig to use Tailscale",
	ShortUsage: "kubeconfig <hostname-or-fqdn>",
	LongHelp: strings.TrimSpace(`
Run this command to configure your kubeconfig to use Tailscale for authentication to a Kubernetes cluster.

The hostname argument should be set to the Tailscale hostname of the peer running as an auth proxy in the cluster.
`),
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("kubeconfig")
		return fs
	})(),
	Exec: runConfigureKubeconfig,
}

func runConfigureKubeconfig(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("unknown arguments")
	}
	hostOrFQDN := args[0]

	st, err := localClient.Status(ctx)
	if err != nil {
		return err
	}
	if st.BackendState != "Running" {
		return errors.New("Tailscale is not running")
	}
	targetFQDN, ok := nodeDNSNameFromArg(st, hostOrFQDN)
	if !ok {
		return fmt.Errorf("no peer found with hostname %q", hostOrFQDN)
	}
	targetFQDN = strings.TrimSuffix(targetFQDN, ".")
	confPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
	if err := setKubeconfigForPeer(targetFQDN, confPath); err != nil {
		return err
	}
	printf("kubeconfig configured for %q\n", hostOrFQDN)
	return nil
}

// appendOrSetNamed finds a map with a "name" key matching name in dst, and
// replaces it with val. If no such map is found, val is appended to dst.
func appendOrSetNamed(dst []any, name string, val map[string]any) []any {
	if got := slices.IndexFunc(dst, func(m any) bool {
		if m, ok := m.(map[string]any); ok {
			return m["name"] == name
		}
		return false
	}); got != -1 {
		dst[got] = val
	} else {
		dst = append(dst, val)
	}
	return dst
}

var errInvalidKubeconfig = errors.New("invalid kubeconfig")

func updateKubeconfig(cfgYaml []byte, fqdn string) ([]byte, error) {
	var cfg map[string]any
	if len(cfgYaml) > 0 {
		if err := yaml.Unmarshal(cfgYaml, &cfg); err != nil {
			return nil, errInvalidKubeconfig
		}
	}
	if cfg == nil {
		cfg = map[string]any{
			"apiVersion": "v1",
			"kind":       "Config",
		}
	} else if cfg["apiVersion"] != "v1" || cfg["kind"] != "Config" {
		return nil, errInvalidKubeconfig
	}

	var clusters []any
	if cm, ok := cfg["clusters"]; ok {
		clusters = cm.([]any)
	}
	cfg["clusters"] = appendOrSetNamed(clusters, fqdn, map[string]any{
		"name": fqdn,
		"cluster": map[string]string{
			"server": "https://" + fqdn,
		},
	})

	var users []any
	if um, ok := cfg["users"]; ok {
		users = um.([]any)
	}
	cfg["users"] = appendOrSetNamed(users, "tailscale-auth", map[string]any{
		// We just need one of these, and can reuse it for all clusters.
		"name": "tailscale-auth",
		"user": map[string]string{
			// We do not use the token, but if we do not set anything here
			// kubectl will prompt for a username and password.
			"token": "unused",
		},
	})

	var contexts []any
	if cm, ok := cfg["contexts"]; ok {
		contexts = cm.([]any)
	}
	cfg["contexts"] = appendOrSetNamed(contexts, fqdn, map[string]any{
		"name": fqdn,
		"context": map[string]string{
			"cluster": fqdn,
			"user":    "tailscale-auth",
		},
	})
	cfg["current-context"] = fqdn
	return yaml.Marshal(cfg)
}

func setKubeconfigForPeer(fqdn, filePath string) error {
	b, err := os.ReadFile(filePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	b, err = updateKubeconfig(b, fqdn)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, b, 0600)
}
