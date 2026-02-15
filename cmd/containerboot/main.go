// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// The containerboot binary is a wrapper for starting tailscaled in a container.
// It handles reading the desired mode of operation out of environment
// variables, bringing up and authenticating Tailscale, and any other
// kubernetes-specific side jobs.
//
// As with most container things, configuration is passed through environment
// variables. All configuration is optional.
//
//   - TS_AUTHKEY: the authkey to use for login. Also accepts TS_AUTH_KEY.
//     If the value begins with "file:", it is treated as a path to a file containing the key.
//   - TS_CLIENT_ID: the OAuth client ID. Can be used alone (ID token auto-generated
//     in well-known environments), with TS_CLIENT_SECRET, or with TS_ID_TOKEN.
//   - TS_CLIENT_SECRET: the OAuth client secret for generating authkeys.
//     If the value begins with "file:", it is treated as a path to a file containing the secret.
//   - TS_ID_TOKEN: the ID token from the identity provider for workload identity federation.
//     Must be used together with TS_CLIENT_ID. If the value begins with "file:", it is
//     treated as a path to a file containing the token.
//   - TS_AUDIENCE: the audience to use when requesting an ID token from a well-known identity provider
//     to exchange with the control server for workload identity federation. Must be used together
//     with TS_CLIENT_ID.
//   - Note: TS_AUTHKEY is mutually exclusive with TS_CLIENT_ID, TS_CLIENT_SECRET, TS_ID_TOKEN,
//     and TS_AUDIENCE.
//     TS_CLIENT_SECRET, TS_ID_TOKEN, and TS_AUDIENCE cannot be used together.
//   - TS_HOSTNAME: the hostname to request for the node.
//   - TS_ROUTES: subnet routes to advertise. Explicitly setting it to an empty
//     value will cause containerboot to stop acting as a subnet router for any
//     previously advertised routes. To accept routes, use TS_EXTRA_ARGS to pass
//     in --accept-routes.
//   - TS_DEST_IP: proxy all incoming Tailscale traffic to the given
//     destination defined by an IP address.
//   - TS_EXPERIMENTAL_DEST_DNS_NAME: proxy all incoming Tailscale traffic to the given
//     destination defined by a DNS name. The DNS name will be periodically resolved and firewall rules updated accordingly.
//     This is currently intended to be used by the Kubernetes operator (ExternalName Services).
//     This is an experimental env var and will likely change in the future.
//   - TS_TAILNET_TARGET_IP: proxy all incoming non-Tailscale traffic to the given
//     destination defined by an IP.
//   - TS_TAILNET_TARGET_FQDN: proxy all incoming non-Tailscale traffic to the given
//     destination defined by a MagicDNS name.
//   - TS_TAILSCALED_EXTRA_ARGS: extra arguments to 'tailscaled'.
//   - TS_EXTRA_ARGS: extra arguments to 'tailscale up'.
//   - TS_USERSPACE: run with userspace networking (the default)
//     instead of kernel networking.
//   - TS_STATE_DIR: the directory in which to store tailscaled
//     state. The data should persist across container
//     restarts.
//   - TS_ACCEPT_DNS: whether to use the tailnet's DNS configuration.
//   - TS_KUBE_SECRET: the name of the Kubernetes secret in which to
//     store tailscaled state.
//   - TS_SOCKS5_SERVER: the address on which to listen for SOCKS5
//     proxying into the tailnet.
//   - TS_OUTBOUND_HTTP_PROXY_LISTEN: the address on which to listen
//     for HTTP proxying into the tailnet.
//   - TS_SOCKET: the path where the tailscaled LocalAPI socket should
//     be created.
//   - TS_AUTH_ONCE: if true, only attempt to log in if not already
//     logged in. If false (the default, for backwards
//     compatibility), forcibly log in every time the
//     container starts.
//   - TS_SERVE_CONFIG: if specified, is the file path where the ipn.ServeConfig is located.
//     It will be applied once tailscaled is up and running. If the file contains
//     ${TS_CERT_DOMAIN}, it will be replaced with the value of the available FQDN.
//     It cannot be used in conjunction with TS_DEST_IP. The file is watched for changes,
//     and will be re-applied when it changes.
//   - TS_HEALTHCHECK_ADDR_PORT: deprecated, use TS_ENABLE_HEALTH_CHECK instead and optionally
//     set TS_LOCAL_ADDR_PORT. Will be removed in 1.82.0.
//   - TS_LOCAL_ADDR_PORT: the address and port to serve local metrics and health
//     check endpoints if enabled via TS_ENABLE_METRICS and/or TS_ENABLE_HEALTH_CHECK.
//     Defaults to [::]:9002, serving on all available interfaces.
//   - TS_ENABLE_METRICS: if true, a metrics endpoint will be served at /metrics on
//     the address specified by TS_LOCAL_ADDR_PORT. See https://tailscale.com/kb/1482/client-metrics
//     for more information on the metrics exposed.
//   - TS_ENABLE_HEALTH_CHECK: if true, a health check endpoint will be served at /healthz on
//     the address specified by TS_LOCAL_ADDR_PORT. The health endpoint will return 200
//     OK if this node has at least one tailnet IP address, otherwise returns 503.
//     NB: the health criteria might change in the future.
//   - TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR: if specified, a path to a
//     directory that containers tailscaled config in file. The config file needs to be
//     named cap-<current-tailscaled-cap>.hujson. If this is set, TS_HOSTNAME,
//     TS_EXTRA_ARGS, TS_AUTHKEY, TS_CLIENT_ID, TS_CLIENT_SECRET, TS_ID_TOKEN,
//     TS_ROUTES, TS_ACCEPT_DNS, TS_AUDIENCE env vars must not be set. If this is set,
//     containerboot only runs `tailscaled --config <path-to-this-configfile>`
//     and not `tailscale up` or `tailscale set`.
//     The config file contents are currently read once on container start.
//     NB: This env var is currently experimental and the logic will likely change!
//     TS_EXPERIMENTAL_ENABLE_FORWARDING_OPTIMIZATIONS: set to true to
//     autoconfigure the default network interface for optimal performance for
//     Tailscale subnet router/exit node.
//     https://tailscale.com/kb/1320/performance-best-practices#linux-optimizations-for-subnet-routers-and-exit-nodes
//     NB: This env var is currently experimental and the logic will likely change!
//   - EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS: if set to true
//     and if this containerboot instance is an L7 ingress proxy (created by
//     the Kubernetes operator), set up rules to allow proxying cluster traffic,
//     received on the Pod IP of this node, to the ingress target in the cluster.
//     This, in conjunction with MagicDNS name resolution in cluster, can be
//     useful for cases where a cluster workload needs to access a target in
//     cluster using the same hostname (in this case, the MagicDNS name of the ingress proxy)
//     as a non-cluster workload on tailnet.
//     This is only meant to be configured by the Kubernetes operator.
//   - TS_EXPERIMENTAL_SERVICE_AUTO_ADVERTISEMENT: If set to true and if this
//     containerboot instance is not running in Kubernetes, autoadvertise any services
//     defined in the devices serve config, and unadvertise on shutdown. Defaults
//     to `true`, but can be disabled to allow user specific advertisement configuration.
//
// When running on Kubernetes, containerboot defaults to storing state in the
// "tailscale" kube secret. To store state on local disk instead, set
// TS_KUBE_SECRET="" and TS_STATE_DIR=/path/to/storage/dir. The state dir should
// be persistent storage.
//
// Additionally, if TS_AUTHKEY is not set and the TS_KUBE_SECRET contains an
// "authkey" field, that key is used as the tailscale authkey.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	kubeutils "tailscale.com/k8s-operator"
	healthz "tailscale.com/kube/health"
	"tailscale.com/kube/kubetypes"
	klc "tailscale.com/kube/localclient"
	"tailscale.com/kube/metrics"
	"tailscale.com/kube/services"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/util/deephash"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/linuxfw"
)

func newNetfilterRunner(logf logger.Logf) (linuxfw.NetfilterRunner, error) {
	if defaultBool("TS_TEST_FAKE_NETFILTER", false) {
		return linuxfw.NewFakeIPTablesRunner(), nil
	}
	return linuxfw.New(logf, "")
}

func getAutoAdvertiseBool() bool {
	return defaultBool("TS_EXPERIMENTAL_SERVICE_AUTO_ADVERTISEMENT", true)
}

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run() error {
	log.SetPrefix("boot: ")
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	cfg, err := configFromEnv()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	if !cfg.UserspaceMode {
		if err := ensureTunFile(cfg.Root); err != nil {
			return fmt.Errorf("unable to create tuntap device file: %w", err)
		}
		if cfg.ProxyTargetIP != "" || cfg.ProxyTargetDNSName != "" || cfg.Routes != nil || cfg.TailnetTargetIP != "" || cfg.TailnetTargetFQDN != "" {
			if err := ensureIPForwarding(cfg.Root, cfg.ProxyTargetIP, cfg.TailnetTargetIP, cfg.TailnetTargetFQDN, cfg.Routes); err != nil {
				log.Printf("Failed to enable IP forwarding: %v", err)
				log.Printf("To run tailscale as a proxy or router container, IP forwarding must be enabled.")
				if cfg.InKubernetes {
					return fmt.Errorf("you can either set the sysctls as a privileged initContainer, or run the tailscale container with privileged=true.")
				} else {
					return fmt.Errorf("you can fix this by running the container with privileged=true, or the equivalent in your container runtime that permits access to sysctls.")
				}
			}
		}
	}

	// Root context for the whole containerboot process, used to make sure
	// shutdown signals are promptly and cleanly handled.
	ctx, cancel := contextWithExitSignalWatch()
	defer cancel()

	// bootCtx is used for all setup stuff until we're in steady
	// state, so that if something is hanging we eventually time out
	// and crashloop the container.
	bootCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var kc *kubeClient
	if cfg.KubeSecret != "" {
		kc, err = newKubeClient(cfg.Root, cfg.KubeSecret)
		if err != nil {
			return fmt.Errorf("error initializing kube client: %w", err)
		}
		if err := cfg.setupKube(bootCtx, kc); err != nil {
			return fmt.Errorf("error setting up for running on Kubernetes: %w", err)
		}
		// Clear out any state from previous runs of containerboot. Check
		// hasKubeStateStore because although we know we're in kube, that
		// doesn't guarantee the state store is properly configured.
		if hasKubeStateStore(cfg) {
			if err := kc.resetContainerbootState(bootCtx, cfg.PodUID); err != nil {
				return fmt.Errorf("error clearing previous state from Secret: %w", err)
			}
		}
	}

	client, daemonProcess, err := startTailscaled(bootCtx, cfg)
	if err != nil {
		return fmt.Errorf("failed to bring up tailscale: %w", err)
	}
	killTailscaled := func() {
		// The default termination grace period for a Pod is 30s. We wait 25s at
		// most so that we still reserve some of that budget for tailscaled
		// to receive and react to a SIGTERM before the SIGKILL that k8s
		// will send at the end of the grace period.
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()

		// we are shutting down, we always want to unadvertise here
		if err := services.EnsureServicesNotAdvertised(ctx, client, log.Printf); err != nil {
			log.Printf("Error ensuring services are not advertised: %v", err)
		}

		if hasKubeStateStore(cfg) {
			// Check we're not shutting tailscaled down while it's still writing
			// state. If we authenticate and fail to write all the state, we'll
			// never recover automatically.
			log.Printf("Checking for consistent state")
			err := kc.waitForConsistentState(ctx)
			if err != nil {
				log.Printf("Error waiting for consistent state on shutdown: %v", err)
			}
		}
		log.Printf("Sending SIGTERM to tailscaled")
		if err := daemonProcess.Signal(unix.SIGTERM); err != nil {
			log.Fatalf("error shutting tailscaled down: %v", err)
		}
	}
	defer killTailscaled()

	var healthCheck *healthz.Healthz
	ep := &egressProxy{}
	if cfg.HealthCheckAddrPort != "" {
		mux := http.NewServeMux()

		log.Printf("Running healthcheck endpoint at %s/healthz", cfg.HealthCheckAddrPort)
		healthCheck = healthz.RegisterHealthHandlers(mux, cfg.PodIPv4, log.Printf)

		close := runHTTPServer(mux, cfg.HealthCheckAddrPort)
		defer close()
	}

	if cfg.localMetricsEnabled() || cfg.localHealthEnabled() || cfg.egressSvcsTerminateEPEnabled() {
		mux := http.NewServeMux()

		if cfg.localMetricsEnabled() {
			log.Printf("Running metrics endpoint at %s/metrics", cfg.LocalAddrPort)
			metrics.RegisterMetricsHandlers(mux, client, cfg.DebugAddrPort)
		}

		if cfg.localHealthEnabled() {
			log.Printf("Running healthcheck endpoint at %s/healthz", cfg.LocalAddrPort)
			healthCheck = healthz.RegisterHealthHandlers(mux, cfg.PodIPv4, log.Printf)
		}

		if cfg.egressSvcsTerminateEPEnabled() {
			log.Printf("Running egress preshutdown hook at %s%s", cfg.LocalAddrPort, kubetypes.EgessServicesPreshutdownEP)
			ep.registerHandlers(mux)
		}

		close := runHTTPServer(mux, cfg.LocalAddrPort)
		defer close()
	}

	if cfg.EnableForwardingOptimizations {
		if err := client.SetUDPGROForwarding(bootCtx); err != nil {
			log.Printf("[unexpected] error enabling UDP GRO forwarding: %v", err)
		}
	}

	w, err := client.WatchIPNBus(bootCtx, ipn.NotifyInitialNetMap|ipn.NotifyInitialPrefs|ipn.NotifyInitialState)
	if err != nil {
		return fmt.Errorf("failed to watch tailscaled for updates: %w", err)
	}

	// Now that we've started tailscaled, we can symlink the socket to the
	// default location if needed.
	const defaultTailscaledSocketPath = "/var/run/tailscale/tailscaled.sock"
	if cfg.Socket != "" && cfg.Socket != defaultTailscaledSocketPath {
		// If we were given a socket path, symlink it to the default location so
		// that the CLI can find it without any extra flags.
		// See #6849.

		dir := filepath.Dir(defaultTailscaledSocketPath)
		err := os.MkdirAll(dir, 0700)
		if err == nil {
			err = syscall.Symlink(cfg.Socket, defaultTailscaledSocketPath)
		}
		if err != nil {
			log.Printf("[warning] failed to symlink socket: %v\n\tTo interact with the Tailscale CLI please use `tailscale --socket=%q`", err, cfg.Socket)
		}
	}

	// Because we're still shelling out to `tailscale up` to get access to its
	// flag parser, we have to stop watching the IPN bus so that we can block on
	// the subcommand without stalling anything. Then once it's done, we resume
	// watching the bus.
	//
	// Depending on the requested mode of operation, this auth step happens at
	// different points in containerboot's lifecycle, hence the helper function.
	didLogin := false
	authTailscale := func() error {
		if didLogin {
			return nil
		}
		didLogin = true
		w.Close()
		if err := tailscaleUp(bootCtx, cfg); err != nil {
			return fmt.Errorf("failed to auth tailscale: %w", err)
		}
		w, err = client.WatchIPNBus(bootCtx, ipn.NotifyInitialNetMap|ipn.NotifyInitialState)
		if err != nil {
			return fmt.Errorf("rewatching tailscaled for updates after auth: %w", err)
		}
		return nil
	}

	if isTwoStepConfigAlwaysAuth(cfg) {
		if err := authTailscale(); err != nil {
			return fmt.Errorf("failed to auth tailscale: %w", err)
		}
	}

authLoop:
	for {
		n, err := w.Next()
		if err != nil {
			return fmt.Errorf("failed to read from tailscaled: %w", err)
		}

		if n.State != nil {
			switch *n.State {
			case ipn.NeedsLogin:
				if isOneStepConfig(cfg) {
					// This could happen if this is the first time tailscaled was run for this
					// device and the auth key was not passed via the configfile.
					return fmt.Errorf("invalid state: tailscaled daemon started with a config file, but tailscale is not logged in: ensure you pass a valid auth key in the config file.")
				}
				if err := authTailscale(); err != nil {
					return fmt.Errorf("failed to auth tailscale: %w", err)
				}
			case ipn.NeedsMachineAuth:
				log.Printf("machine authorization required, please visit the admin panel")
			case ipn.Running:
				// Technically, all we want is to keep monitoring the bus for
				// netmap updates. However, in order to make the container crash
				// if tailscale doesn't initially come up, the watch has a
				// startup deadline on it. So, we have to break out of this
				// watch loop, cancel the watch, and watch again with no
				// deadline to continue monitoring for changes.
				break authLoop
			default:
				log.Printf("tailscaled in state %q, waiting", *n.State)
			}
		}
	}

	w.Close()

	if isTwoStepConfigAuthOnce(cfg) {
		// Now that we are authenticated, we can set/reset any of the
		// settings that we need to.
		if err := tailscaleSet(ctx, cfg); err != nil {
			return fmt.Errorf("failed to auth tailscale: %w", err)
		}
	}

	// Remove any serve config and advertised HTTPS endpoint that may have been set by a previous run of
	// containerboot, but only if we're providing a new one.
	if cfg.ServeConfigPath != "" {
		log.Printf("serve proxy: unsetting previous config")
		if err := client.SetServeConfig(ctx, new(ipn.ServeConfig)); err != nil {
			return fmt.Errorf("failed to unset serve config: %w", err)
		}
	}

	if hasKubeStateStore(cfg) && isTwoStepConfigAuthOnce(cfg) {
		// We were told to only auth once, so any secret-bound
		// authkey is no longer needed. We don't strictly need to
		// wipe it, but it's good hygiene.
		log.Printf("Deleting authkey from kube secret")
		if err := kc.deleteAuthKey(ctx); err != nil {
			return fmt.Errorf("deleting authkey from kube secret: %w", err)
		}
	}

	w, err = client.WatchIPNBus(ctx, ipn.NotifyInitialNetMap|ipn.NotifyInitialState)
	if err != nil {
		return fmt.Errorf("rewatching tailscaled for updates after auth: %w", err)
	}

	// If tailscaled config was read from a mounted file, watch the file for updates and reload.
	cfgWatchErrChan := make(chan error)
	if cfg.TailscaledConfigFilePath != "" {
		go watchTailscaledConfigChanges(ctx, cfg.TailscaledConfigFilePath, client, cfgWatchErrChan)
	}

	var (
		startupTasksDone       = false
		currentIPs             deephash.Sum // tailscale IPs assigned to device
		currentDeviceID        deephash.Sum // device ID
		currentDeviceEndpoints deephash.Sum // device FQDN and IPs

		currentEgressIPs deephash.Sum

		addrs        []netip.Prefix
		backendAddrs []net.IP

		certDomain        = new(atomic.Pointer[string])
		certDomainChanged = make(chan bool, 1)

		triggerWatchServeConfigChanges sync.Once
	)

	var nfr linuxfw.NetfilterRunner
	if isL3Proxy(cfg) {
		nfr, err = newNetfilterRunner(log.Printf)
		if err != nil {
			return fmt.Errorf("error creating new netfilter runner: %w", err)
		}
	}

	// Setup for proxies that are configured to proxy to a target specified
	// by a DNS name (TS_EXPERIMENTAL_DEST_DNS_NAME).
	const defaultCheckPeriod = time.Minute * 10 // how often to check what IPs the DNS name resolves to
	var (
		tc                    = make(chan string, 1)
		failedResolveAttempts int
		t                     *time.Timer = time.AfterFunc(defaultCheckPeriod, func() {
			if cfg.ProxyTargetDNSName != "" {
				tc <- "recheck"
			}
		})
	)
	// egressSvcsErrorChan will get an error sent to it if this containerboot instance is configured to expose 1+
	// egress services in HA mode and errored.
	egressSvcsErrorChan := make(chan error)
	ingressSvcsErrorChan := make(chan error)
	defer t.Stop()
	// resetTimer resets timer for when to next attempt to resolve the DNS
	// name for the proxy configured with TS_EXPERIMENTAL_DEST_DNS_NAME. The
	// timer gets reset to 10 minutes from now unless the last resolution
	// attempt failed. If one or more consecutive previous resolution
	// attempts failed, the next resolution attempt will happen after the smallest
	// of (10 minutes, 2 ^ number-of-consecutive-failed-resolution-attempts
	// seconds) i.e 2s, 4s, 8s ... 10 minutes.
	resetTimer := func(lastResolveFailed bool) {
		if !lastResolveFailed {
			log.Printf("reconfigureTimer: next DNS resolution attempt in %s", defaultCheckPeriod)
			t.Reset(defaultCheckPeriod)
			failedResolveAttempts = 0
			return
		}
		minDelay := 2 // 2 seconds
		nextTick := time.Second * time.Duration(math.Pow(float64(minDelay), float64(failedResolveAttempts)))
		if nextTick > defaultCheckPeriod {
			nextTick = defaultCheckPeriod // cap at 10 minutes
		}
		log.Printf("reconfigureTimer: last DNS resolution attempt failed, next DNS resolution attempt in %v", nextTick)
		t.Reset(nextTick)
		failedResolveAttempts++
	}

	var egressSvcsNotify chan ipn.Notify
	notifyChan := make(chan ipn.Notify)
	errChan := make(chan error)
	go func() {
		for {
			n, err := w.Next()
			if err != nil {
				errChan <- err
				break
			} else {
				notifyChan <- n
			}
		}
	}()
	var wg sync.WaitGroup

runLoop:
	for {
		select {
		case <-ctx.Done():
			// Although killTailscaled() is deferred earlier, if we
			// have started the reaper defined below, we need to
			// kill tailscaled and let reaper clean up child
			// processes.
			killTailscaled()
			break runLoop
		case err := <-errChan:
			return fmt.Errorf("failed to read from tailscaled: %w", err)
		case err := <-cfgWatchErrChan:
			return fmt.Errorf("failed to watch tailscaled config: %w", err)
		case n := <-notifyChan:
			if n.State != nil && *n.State != ipn.Running {
				// Something's gone wrong and we've left the authenticated state.
				// Our container image never recovered gracefully from this, and the
				// control flow required to make it work now is hard. So, just crash
				// the container and rely on the container runtime to restart us,
				// whereupon we'll go through initial auth again.
				return fmt.Errorf("tailscaled left running state (now in state %q), exiting", *n.State)
			}
			if n.NetMap != nil {
				addrs = n.NetMap.SelfNode.Addresses().AsSlice()
				newCurrentIPs := deephash.Hash(&addrs)
				ipsHaveChanged := newCurrentIPs != currentIPs

				// Store device ID in a Kubernetes Secret before
				// setting up any routing rules. This ensures
				// that, for containerboot instances that are
				// Kubernetes operator proxies, the operator is
				// able to retrieve the device ID from the
				// Kubernetes Secret to clean up tailnet nodes
				// for proxies whose route setup continuously
				// fails.
				deviceID := n.NetMap.SelfNode.StableID()
				if hasKubeStateStore(cfg) && deephash.Update(&currentDeviceID, &deviceID) {
					if err := kc.storeDeviceID(ctx, n.NetMap.SelfNode.StableID()); err != nil {
						return fmt.Errorf("storing device ID in Kubernetes Secret: %w", err)
					}
				}
				if cfg.TailnetTargetFQDN != "" {
					egressAddrs, err := resolveTailnetFQDN(n.NetMap, cfg.TailnetTargetFQDN)
					if err != nil {
						log.Print(err.Error())
						break
					}

					newCurentEgressIPs := deephash.Hash(&egressAddrs)
					egressIPsHaveChanged := newCurentEgressIPs != currentEgressIPs
					// The firewall rules get (re-)installed:
					// - on startup
					// - when the tailnet IPs of the tailnet target have changed
					// - when the tailnet IPs of this node have changed
					if (egressIPsHaveChanged || ipsHaveChanged) && len(egressAddrs) != 0 {
						var rulesInstalled bool
						for _, egressAddr := range egressAddrs {
							ea := egressAddr.Addr()
							if ea.Is4() || (ea.Is6() && nfr.HasIPV6NAT()) {
								rulesInstalled = true
								log.Printf("Installing forwarding rules for destination %v", ea.String())
								if err := installEgressForwardingRule(ctx, ea.String(), addrs, nfr); err != nil {
									return fmt.Errorf("installing egress proxy rules for destination %s: %v", ea.String(), err)
								}
							}
						}
						if !rulesInstalled {
							return fmt.Errorf("no forwarding rules for egress addresses %v, host supports IPv6: %v", egressAddrs, nfr.HasIPV6NAT())
						}
					}
					currentEgressIPs = newCurentEgressIPs
				}
				if cfg.ProxyTargetIP != "" && len(addrs) != 0 && ipsHaveChanged {
					log.Printf("Installing proxy rules")
					if err := installIngressForwardingRule(ctx, cfg.ProxyTargetIP, addrs, nfr); err != nil {
						return fmt.Errorf("installing ingress proxy rules: %w", err)
					}
				}
				if cfg.ProxyTargetDNSName != "" && len(addrs) != 0 && ipsHaveChanged {
					newBackendAddrs, err := resolveDNS(ctx, cfg.ProxyTargetDNSName)
					if err != nil {
						log.Printf("[unexpected] error resolving DNS name %s: %v", cfg.ProxyTargetDNSName, err)
						resetTimer(true)
						continue
					}
					backendsHaveChanged := !(slices.EqualFunc(backendAddrs, newBackendAddrs, func(ip1 net.IP, ip2 net.IP) bool {
						return slices.ContainsFunc(newBackendAddrs, func(ip net.IP) bool { return ip.Equal(ip1) })
					}))
					if backendsHaveChanged {
						log.Printf("installing ingress proxy rules for backends %v", newBackendAddrs)
						if err := installIngressForwardingRuleForDNSTarget(ctx, newBackendAddrs, addrs, nfr); err != nil {
							return fmt.Errorf("error installing ingress proxy rules: %w", err)
						}
					}
					resetTimer(false)
					backendAddrs = newBackendAddrs
				}
				if cfg.ServeConfigPath != "" {
					cd := certDomainFromNetmap(n.NetMap)
					if cd == "" {
						cd = kubetypes.ValueNoHTTPS
					}
					prev := certDomain.Swap(ptr.To(cd))
					if prev == nil || *prev != cd {
						select {
						case certDomainChanged <- true:
						default:
						}
					}
				}
				if cfg.TailnetTargetIP != "" && ipsHaveChanged && len(addrs) != 0 {
					log.Printf("Installing forwarding rules for destination %v", cfg.TailnetTargetIP)
					if err := installEgressForwardingRule(ctx, cfg.TailnetTargetIP, addrs, nfr); err != nil {
						return fmt.Errorf("installing egress proxy rules: %w", err)
					}
				}
				// If this is a L7 cluster ingress proxy (set up
				// by Kubernetes operator) and proxying of
				// cluster traffic to the ingress target is
				// enabled, set up proxy rule each time the
				// tailnet IPs of this node change (including
				// the first time they become available).
				if cfg.AllowProxyingClusterTrafficViaIngress && cfg.ServeConfigPath != "" && ipsHaveChanged && len(addrs) != 0 {
					log.Printf("installing rules to forward traffic for %s to node's tailnet IP", cfg.PodIP)
					if err := installTSForwardingRuleForDestination(ctx, cfg.PodIP, addrs, nfr); err != nil {
						return fmt.Errorf("installing rules to forward traffic to node's tailnet IP: %w", err)
					}
				}
				currentIPs = newCurrentIPs

				// Only store device FQDN and IP addresses to
				// Kubernetes Secret when any required proxy
				// route setup has succeeded. IPs and FQDN are
				// read from the Secret by the Tailscale
				// Kubernetes operator and, for some proxy
				// types, such as Tailscale Ingress, advertized
				// on the Ingress status. Writing them to the
				// Secret only after the proxy routing has been
				// set up ensures that the operator does not
				// advertize endpoints of broken proxies.
				// TODO (irbekrm): instead of using the IP and FQDN, have some other mechanism for the proxy signal that it is 'Ready'.
				deviceEndpoints := []any{n.NetMap.SelfNode.Name(), n.NetMap.SelfNode.Addresses()}
				if hasKubeStateStore(cfg) && deephash.Update(&currentDeviceEndpoints, &deviceEndpoints) {
					if err := kc.storeDeviceEndpoints(ctx, n.NetMap.SelfNode.Name(), n.NetMap.SelfNode.Addresses().AsSlice()); err != nil {
						return fmt.Errorf("storing device IPs and FQDN in Kubernetes Secret: %w", err)
					}
				}

				if healthCheck != nil {
					healthCheck.Update(len(addrs) != 0)
				}

				var prevServeConfig *ipn.ServeConfig
				if getAutoAdvertiseBool() {
					prevServeConfig, err = client.GetServeConfig(ctx)
					if err != nil {
						return fmt.Errorf("autoadvertisement: failed to get serve config: %w", err)
					}

					err = refreshAdvertiseServices(ctx, prevServeConfig, klc.New(client))
					if err != nil {
						return fmt.Errorf("autoadvertisement: failed to refresh advertise services: %w", err)
					}
				}

				if cfg.ServeConfigPath != "" {
					triggerWatchServeConfigChanges.Do(func() {
						go watchServeConfigChanges(ctx, certDomainChanged, certDomain, client, kc, cfg, prevServeConfig)
					})
				}

				if egressSvcsNotify != nil {
					egressSvcsNotify <- n
				}
			}
			if !startupTasksDone {
				// For containerboot instances that act as TCP proxies (proxying traffic to an endpoint
				// passed via one of the env vars that containerboot reads) and store state in a
				// Kubernetes Secret, we consider startup tasks done at the point when device info has
				// been successfully stored to state Secret. For all other containerboot instances, if
				// we just get to this point the startup tasks can be considered done.
				if !isL3Proxy(cfg) || !hasKubeStateStore(cfg) || (currentDeviceEndpoints != deephash.Sum{} && currentDeviceID != deephash.Sum{}) {
					// This log message is used in tests to detect when all
					// post-auth configuration is done.
					log.Println("Startup complete, waiting for shutdown signal")
					startupTasksDone = true

					// Configure egress proxy. Egress proxy will set up firewall rules to proxy
					// traffic to tailnet targets configured in the provided configuration file. It
					// will then continuously monitor the config file and netmap updates and
					// reconfigure the firewall rules as needed. If any of its operations fail, it
					// will crash this node.
					if cfg.EgressProxiesCfgPath != "" {
						log.Printf("configuring egress proxy using configuration file at %s", cfg.EgressProxiesCfgPath)
						egressSvcsNotify = make(chan ipn.Notify)
						opts := egressProxyRunOpts{
							cfgPath:      cfg.EgressProxiesCfgPath,
							nfr:          nfr,
							kc:           kc,
							tsClient:     client,
							stateSecret:  cfg.KubeSecret,
							netmapChan:   egressSvcsNotify,
							podIPv4:      cfg.PodIPv4,
							tailnetAddrs: addrs,
						}
						go func() {
							if err := ep.run(ctx, n, opts); err != nil {
								egressSvcsErrorChan <- err
							}
						}()
					}
					ip := ingressProxy{}
					if cfg.IngressProxiesCfgPath != "" {
						log.Printf("configuring ingress proxy using configuration file at %s", cfg.IngressProxiesCfgPath)
						opts := ingressProxyOpts{
							cfgPath:     cfg.IngressProxiesCfgPath,
							nfr:         nfr,
							kc:          kc,
							stateSecret: cfg.KubeSecret,
							podIPv4:     cfg.PodIPv4,
							podIPv6:     cfg.PodIPv6,
						}
						go func() {
							if err := ip.run(ctx, opts); err != nil {
								ingressSvcsErrorChan <- err
							}
						}()
					}

					// Wait on tailscaled process. It won't be cleaned up by default when the
					// container exits as it is not PID1. TODO (irbekrm): perhaps we can replace the
					// reaper by a running cmd.Wait in a goroutine immediately after starting
					// tailscaled?
					reaper := func() {
						defer wg.Done()
						for {
							var status unix.WaitStatus
							_, err := unix.Wait4(daemonProcess.Pid, &status, 0, nil)
							if errors.Is(err, unix.EINTR) {
								continue
							}
							if err != nil {
								log.Fatalf("Waiting for tailscaled to exit: %v", err)
							}
							log.Print("tailscaled exited")
							os.Exit(0)
						}
					}
					wg.Add(1)
					go reaper()
				}
			}
		case <-tc:
			newBackendAddrs, err := resolveDNS(ctx, cfg.ProxyTargetDNSName)
			if err != nil {
				log.Printf("[unexpected] error resolving DNS name %s: %v", cfg.ProxyTargetDNSName, err)
				resetTimer(true)
				continue
			}
			backendsHaveChanged := !(slices.EqualFunc(backendAddrs, newBackendAddrs, func(ip1 net.IP, ip2 net.IP) bool {
				return slices.ContainsFunc(newBackendAddrs, func(ip net.IP) bool { return ip.Equal(ip1) })
			}))
			if backendsHaveChanged && len(addrs) != 0 {
				log.Printf("Backend address change detected, installing proxy rules for backends %v", newBackendAddrs)
				if err := installIngressForwardingRuleForDNSTarget(ctx, newBackendAddrs, addrs, nfr); err != nil {
					return fmt.Errorf("installing ingress proxy rules for DNS target %s: %v", cfg.ProxyTargetDNSName, err)
				}
			}
			backendAddrs = newBackendAddrs
			resetTimer(false)
		case e := <-egressSvcsErrorChan:
			return fmt.Errorf("egress proxy failed: %v", e)
		case e := <-ingressSvcsErrorChan:
			return fmt.Errorf("ingress proxy failed: %v", e)
		}
	}
	wg.Wait()

	return nil
}

// ensureTunFile checks that /dev/net/tun exists, creating it if
// missing.
func ensureTunFile(root string) error {
	// Verify that /dev/net/tun exists, in some container envs it
	// needs to be mknod-ed.
	if _, err := os.Stat(filepath.Join(root, "dev/net")); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(filepath.Join(root, "dev/net"), 0755); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(root, "dev/net/tun")); errors.Is(err, fs.ErrNotExist) {
		dev := unix.Mkdev(10, 200) // tuntap major and minor
		if err := unix.Mknod(filepath.Join(root, "dev/net/tun"), 0600|unix.S_IFCHR, int(dev)); err != nil {
			return err
		}
	}
	return nil
}

func resolveDNS(ctx context.Context, name string) ([]net.IP, error) {
	// TODO (irbekrm): look at using recursive.Resolver instead to resolve
	// the DNS names as well as retrieve TTLs. It looks though that this
	// seems to return very short TTLs (shorter than on the actual records).
	ip4s, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		if e, ok := err.(*net.DNSError); !(ok && e.IsNotFound) {
			return nil, fmt.Errorf("error looking up IPv4 addresses: %w", err)
		}
	}
	ip6s, err := net.DefaultResolver.LookupIP(ctx, "ip6", name)
	if err != nil {
		if e, ok := err.(*net.DNSError); !(ok && e.IsNotFound) {
			return nil, fmt.Errorf("error looking up IPv6 addresses: %w", err)
		}
	}
	if len(ip4s) == 0 && len(ip6s) == 0 {
		return nil, fmt.Errorf("no IPv4 or IPv6 addresses found for host: %s", name)
	}
	return append(ip4s, ip6s...), nil
}

// contextWithExitSignalWatch watches for SIGTERM/SIGINT signals. It returns a
// context that gets cancelled when a signal is received and a cancel function
// that can be called to free the resources when the watch should be stopped.
func contextWithExitSignalWatch() (context.Context, func()) {
	closeChan := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-signalChan:
			cancel()
		case <-closeChan:
			return
		}
	}()
	closeOnce := sync.Once{}
	f := func() {
		closeOnce.Do(func() {
			close(closeChan)
		})
	}
	return ctx, f
}

// tailscaledConfigFilePath returns the path to the tailscaled config file that
// should be used for the current capability version. It is determined by the
// TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR environment variable and looks for a
// file named cap-<capability_version>.hujson in the directory. It searches for
// the highest capability version that is less than or equal to the current
// capability version.
func tailscaledConfigFilePath() string {
	dir := os.Getenv("TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR")
	if dir == "" {
		return ""
	}
	fe, err := os.ReadDir(dir)
	if err != nil {
		log.Fatalf("error reading tailscaled config directory %q: %v", dir, err)
	}
	maxCompatVer := tailcfg.CapabilityVersion(-1)
	for _, e := range fe {
		// We don't check if type if file as in most cases this will
		// come from a mounted kube Secret, where the directory contents
		// will be various symlinks.
		if e.Type().IsDir() {
			continue
		}
		cv, err := kubeutils.CapVerFromFileName(e.Name())
		if err != nil {
			continue
		}
		if cv > maxCompatVer && cv <= tailcfg.CurrentCapabilityVersion {
			maxCompatVer = cv
		}
	}
	if maxCompatVer == -1 {
		log.Fatalf("no tailscaled config file found in %q for current capability version %d", dir, tailcfg.CurrentCapabilityVersion)
	}
	filePath := filepath.Join(dir, kubeutils.TailscaledConfigFileName(maxCompatVer))
	log.Printf("Using tailscaled config file %q to match current capability version %d", filePath, tailcfg.CurrentCapabilityVersion)
	return filePath
}

func runHTTPServer(mux *http.ServeMux, addr string) (close func() error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on addr %q: %v", addr, err)
	}
	srv := &http.Server{Handler: mux}

	go func() {
		if err := srv.Serve(ln); err != nil {
			if err != http.ErrServerClosed {
				log.Fatalf("failed running server: %v", err)
			} else {
				log.Printf("HTTP server at %s closed", addr)
			}
		}
	}()

	return func() error {
		err := srv.Shutdown(context.Background())
		return errors.Join(err, ln.Close())
	}
}

// resolveTailnetFQDN resolves a tailnet FQDN to a list of IP prefixes, which
// can be either a peer device or a Tailscale Service.
func resolveTailnetFQDN(nm *netmap.NetworkMap, fqdn string) ([]netip.Prefix, error) {
	dnsFQDN, err := dnsname.ToFQDN(fqdn)
	if err != nil {
		return nil, fmt.Errorf("error parsing %q as FQDN: %w", fqdn, err)
	}

	// Check all peer devices first.
	for _, p := range nm.Peers {
		if strings.EqualFold(p.Name(), dnsFQDN.WithTrailingDot()) {
			return p.Addresses().AsSlice(), nil
		}
	}

	// If not found yet, check for a matching Tailscale Service.
	if svcIPs := serviceIPsFromNetMap(nm, dnsFQDN); len(svcIPs) != 0 {
		return svcIPs, nil
	}

	return nil, fmt.Errorf("could not find Tailscale node or service %q; it either does not exist, or not reachable because of ACLs", fqdn)
}

// serviceIPsFromNetMap returns all IPs of a Tailscale Service if its FQDN is
// found in the netmap. Note that Tailscale Services are not a first-class
// object in the netmap, so we guess based on DNS ExtraRecords and AllowedIPs.
func serviceIPsFromNetMap(nm *netmap.NetworkMap, fqdn dnsname.FQDN) []netip.Prefix {
	var extraRecords []tailcfg.DNSRecord
	for _, rec := range nm.DNS.ExtraRecords {
		recFQDN, err := dnsname.ToFQDN(rec.Name)
		if err != nil {
			continue
		}
		if strings.EqualFold(fqdn.WithTrailingDot(), recFQDN.WithTrailingDot()) {
			extraRecords = append(extraRecords, rec)
		}
	}

	if len(extraRecords) == 0 {
		return nil
	}

	// Validate we can see a peer advertising the Tailscale Service.
	var prefixes []netip.Prefix
	for _, extraRecord := range extraRecords {
		ip, err := netip.ParseAddr(extraRecord.Value)
		if err != nil {
			continue
		}
		ipPrefix := netip.PrefixFrom(ip, ip.BitLen())
		for _, ps := range nm.Peers {
			for _, allowedIP := range ps.AllowedIPs().All() {
				if allowedIP == ipPrefix {
					prefixes = append(prefixes, ipPrefix)
				}
			}
		}
	}

	return prefixes
}
