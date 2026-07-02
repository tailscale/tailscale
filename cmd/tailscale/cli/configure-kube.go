// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build !ts_omit_kube

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"k8s.io/client-go/util/homedir"
	"sigs.k8s.io/yaml"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
	"tailscale.com/version"
)

var configureKubeconfigArgs struct {
	http bool // Use HTTP instead of HTTPS (default) for the auth proxy.
}

func configureKubeconfigCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "kubeconfig",
		ShortHelp:  "[ALPHA] Connect to a Kubernetes cluster using a Tailscale Auth Proxy",
		ShortUsage: "tailscale configure kubeconfig <hostname-or-fqdn>",
		LongHelp: strings.TrimSpace(`
Run this command to configure kubectl to connect to a Kubernetes cluster over Tailscale.

The hostname argument should be set to the Tailscale hostname of the peer running as an auth proxy in the cluster.

See: https://tailscale.com/s/k8s-auth-proxy
`),
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("kubeconfig")
			fs.BoolVar(&configureKubeconfigArgs.http, "http", false, "use HTTP instead of HTTPS to connect to the auth proxy. Ignored if you include a scheme in the hostname argument.")
			return fs
		})(),
		Exec: runConfigureKubeconfig,
	}
}

// kubeconfigPath returns the path to the kubeconfig file for the current user.
func kubeconfigPath() string {
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		var out string
		for _, out = range filepath.SplitList(kubeconfig) {
			if info, err := os.Stat(out); !os.IsNotExist(err) && !info.IsDir() {
				break
			}
		}
		return out
	}

	var dir string
	if version.IsSandboxedMacOS() {
		// The HOME environment variable in macOS sandboxed apps is set to
		// ~/Library/Containers/<app-id>/Data, but the kubeconfig file is
		// located in ~/.kube/config. We rely on the "com.apple.security.temporary-exception.files.home-relative-path.read-write"
		// entitlement to access the file.
		containerHome := os.Getenv("HOME")
		dir, _, _ = strings.Cut(containerHome, "/Library/Containers/")
	} else {
		dir = homedir.HomeDir()
	}
	return filepath.Join(dir, ".kube", "config")
}

// checkKubeconfigWritable returns nil if the kubeconfig at path can be written,
// or an error explaining why it can't. A not-yet-created file or .kube
// directory is fine as long as the nearest existing ancestor is writable.
//
// On sandboxed macOS builds, kubeconfigPath resolves path to the user's real
// ~/.kube/config, which we can only write via the home-relative-path
// entitlement. If that write would fail (e.g. because $KUBECONFIG points
// somewhere the sandbox can't reach), we want to surface a clear error pointing
// at the open-source tailscaled distribution rather than silently writing a
// config the user's kubectl will never read into the sandbox container.
func checkKubeconfigWritable(path string) error {
	for try := path; ; try = filepath.Dir(try) {
		if _, err := os.Stat(try); err == nil {
			if err := isWritable(try); err != nil {
				return kubeconfigAccessErr(path, err)
			}
			return nil
		} else if !os.IsNotExist(err) {
			return kubeconfigAccessErr(path, err)
		}
		if parent := filepath.Dir(try); parent == try {
			return nil // reached the filesystem root
		}
	}
}

// isWritable reports whether path can be opened or created for writing. For a
// directory it probes by creating and removing a temporary file.
func isWritable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		f, err := os.CreateTemp(path, ".tailscale-kubeconfig-*")
		if err != nil {
			return err
		}
		f.Close()
		return os.Remove(f.Name())
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// kubeconfigAccessErr wraps err with context about path, adding macOS sandbox
// guidance when the process is sandboxed.
func kubeconfigAccessErr(path string, err error) error {
	if version.IsSandboxedMacOS() {
		return fmt.Errorf("cannot write kubeconfig at %q: %w; GUI builds of the macOS client run in a sandbox and can only access files under your home directory, use the open-source tailscaled distribution for other locations", path, err)
	}
	return fmt.Errorf("cannot write kubeconfig at %q: %w", path, err)
}

func runConfigureKubeconfig(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] == "" {
		return flag.ErrHelp
	}
	hostOrFQDNOrIP, http, err := getInputs(args[0], configureKubeconfigArgs.http)
	if err != nil {
		return fmt.Errorf("error parsing inputs: %w", err)
	}

	st, err := localClient.Status(ctx)
	if err != nil {
		return err
	}
	if st.BackendState != "Running" {
		return errors.New("Tailscale is not running")
	}
	dnsCfg, err := getDNSConfig(ctx)
	if err != nil {
		return err
	}

	targetFQDN, err := nodeOrServiceDNSNameFromArg(st, dnsCfg, hostOrFQDNOrIP)
	if err != nil {
		return err
	}
	targetFQDN = strings.TrimSuffix(targetFQDN, ".")
	kubeconfig := kubeconfigPath()
	if err := checkKubeconfigWritable(kubeconfig); err != nil {
		return err
	}
	scheme := "https://"
	if http {
		scheme = "http://"
	}
	if err = setKubeconfigForPeer(scheme, targetFQDN, kubeconfig); err != nil {
		return err
	}
	printf("kubeconfig configured for %q at URL %q\n", targetFQDN, scheme+targetFQDN)
	return nil
}

func getInputs(arg string, httpArg bool) (string, bool, error) {
	u, err := url.Parse(arg)
	if err != nil {
		return "", false, err
	}

	switch u.Scheme {
	case "http", "https":
		return u.Host, u.Scheme == "http", nil
	default:
		return arg, httpArg, nil
	}
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

func updateKubeconfig(cfgYaml []byte, scheme, fqdn string) ([]byte, error) {
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
		clusters, _ = cm.([]any)
	}
	cfg["clusters"] = appendOrSetNamed(clusters, fqdn, map[string]any{
		"name": fqdn,
		"cluster": map[string]string{
			"server": scheme + fqdn,
		},
	})

	var users []any
	if um, ok := cfg["users"]; ok {
		users, _ = um.([]any)
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
		contexts, _ = cm.([]any)
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

func setKubeconfigForPeer(scheme, fqdn, filePath string) error {
	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return kubeconfigAccessErr(filePath, err)
		}
	}
	b, err := os.ReadFile(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading kubeconfig: %w", err)
	}
	b, err = updateKubeconfig(b, scheme, fqdn)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, b, 0600)
}

// nodeOrServiceDNSNameFromArg returns the PeerStatus.DNSName value from a peer
// in st that matches the input arg which can be a base name, full DNS name, or
// an IP. If none is found, it looks for a Tailscale Service
func nodeOrServiceDNSNameFromArg(st *ipnstate.Status, dns *tailcfg.DNSConfig, arg string) (string, error) {
	// First check for a node DNS name.
	if dnsName, ok := nodeDNSNameFromArg(st, arg); ok {
		return dnsName, nil
	}

	// If not found, check for a Tailscale Service DNS name.
	rec, ok := serviceDNSRecordFromDNSConfig(dns, arg)
	if !ok {
		return "", fmt.Errorf("no peer found for %q", arg)
	}

	// Validate we can see a peer advertising the Tailscale Service.
	ip, err := netip.ParseAddr(rec.Value)
	if err != nil {
		return "", fmt.Errorf("error parsing ExtraRecord IP address %q: %w", rec.Value, err)
	}
	ipPrefix := netip.PrefixFrom(ip, ip.BitLen())
	for _, ps := range st.Peer {
		if ps.AllowedIPs == nil {
			// Peer with no addresses visible in the tailnet, e.g. a ProxyGroup
			// whose backing nodes are offline or not yet approved (#20255).
			continue
		}
		for _, allowedIP := range ps.AllowedIPs.All() {
			if allowedIP == ipPrefix {
				return rec.Name, nil
			}
		}
	}

	return "", fmt.Errorf("%q is in MagicDNS, but is not currently reachable on any known peer", arg)
}

func getDNSConfig(ctx context.Context) (*tailcfg.DNSConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return localClient.DNSConfig(ctx)
}

func serviceDNSRecordFromDNSConfig(dns *tailcfg.DNSConfig, arg string) (rec tailcfg.DNSRecord, ok bool) {
	argIP, _ := netip.ParseAddr(arg)
	argFQDN, err := dnsname.ToFQDN(arg)
	argFQDNValid := err == nil
	if !argIP.IsValid() && !argFQDNValid {
		return rec, false
	}

	for _, rec := range dns.ExtraRecords {
		if argIP.IsValid() {
			recIP, _ := netip.ParseAddr(rec.Value)
			if recIP == argIP {
				return rec, true
			}
			continue
		}

		if !argFQDNValid {
			continue
		}

		recFirstLabel := dnsname.FirstLabel(rec.Name)
		if strings.EqualFold(arg, recFirstLabel) {
			return rec, true
		}

		recFQDN, err := dnsname.ToFQDN(rec.Name)
		if err != nil {
			continue
		}
		if strings.EqualFold(argFQDN.WithTrailingDot(), recFQDN.WithTrailingDot()) {
			return rec, true
		}
	}

	return tailcfg.DNSRecord{}, false
}
