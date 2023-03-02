// Copyright (c) Tailscale Inc & AUTHORS
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
//   - TS_AUTHKEY: the authkey to use for login.
//   - TS_HOSTNAME: the hostname to request for the node.
//   - TS_ROUTES: subnet routes to advertise.
//   - TS_DEST_IP: proxy all incoming Tailscale traffic to the given
//     destination.
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
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/util/deephash"
)

func main() {
	log.SetPrefix("boot: ")
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	cfg := &settings{
		AuthKey:         defaultEnvs([]string{"TS_AUTHKEY", "TS_AUTH_KEY"}, ""),
		Hostname:        defaultEnv("TS_HOSTNAME", ""),
		Routes:          defaultEnv("TS_ROUTES", ""),
		ProxyTo:         defaultEnv("TS_DEST_IP", ""),
		DaemonExtraArgs: defaultEnv("TS_TAILSCALED_EXTRA_ARGS", ""),
		ExtraArgs:       defaultEnv("TS_EXTRA_ARGS", ""),
		InKubernetes:    os.Getenv("KUBERNETES_SERVICE_HOST") != "",
		UserspaceMode:   defaultBool("TS_USERSPACE", true),
		StateDir:        defaultEnv("TS_STATE_DIR", ""),
		AcceptDNS:       defaultBool("TS_ACCEPT_DNS", false),
		KubeSecret:      defaultEnv("TS_KUBE_SECRET", "tailscale"),
		SOCKSProxyAddr:  defaultEnv("TS_SOCKS5_SERVER", ""),
		HTTPProxyAddr:   defaultEnv("TS_OUTBOUND_HTTP_PROXY_LISTEN", ""),
		Socket:          defaultEnv("TS_SOCKET", "/tmp/tailscaled.sock"),
		AuthOnce:        defaultBool("TS_AUTH_ONCE", false),
		Root:            defaultEnv("TS_TEST_ONLY_ROOT", "/"),
	}

	if cfg.ProxyTo != "" && cfg.UserspaceMode {
		log.Fatal("TS_DEST_IP is not supported with TS_USERSPACE")
	}

	if !cfg.UserspaceMode {
		if err := ensureTunFile(cfg.Root); err != nil {
			log.Fatalf("Unable to create tuntap device file: %v", err)
		}
		if cfg.ProxyTo != "" || cfg.Routes != "" {
			if err := ensureIPForwarding(cfg.Root, cfg.ProxyTo, cfg.Routes); err != nil {
				log.Printf("Failed to enable IP forwarding: %v", err)
				log.Printf("To run tailscale as a proxy or router container, IP forwarding must be enabled.")
				if cfg.InKubernetes {
					log.Fatalf("You can either set the sysctls as a privileged initContainer, or run the tailscale container with privileged=true.")
				} else {
					log.Fatalf("You can fix this by running the container with privileged=true, or the equivalent in your container runtime that permits access to sysctls.")
				}
			}
		}
	}

	if cfg.InKubernetes {
		initKube(cfg.Root)
	}

	// Context is used for all setup stuff until we're in steady
	// state, so that if something is hanging we eventually time out
	// and crashloop the container.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if cfg.InKubernetes && cfg.KubeSecret != "" {
		canPatch, err := kc.CheckSecretPermissions(ctx, cfg.KubeSecret)
		if err != nil {
			log.Fatalf("Some Kubernetes permissions are missing, please check your RBAC configuration: %v", err)
		}
		cfg.KubernetesCanPatch = canPatch

		if cfg.AuthKey == "" {
			key, err := findKeyInKubeSecret(ctx, cfg.KubeSecret)
			if err != nil {
				log.Fatalf("Getting authkey from kube secret: %v", err)
			}
			if key != "" {
				// This behavior of pulling authkeys from kube secrets was added
				// at the same time as the patch permission, so we can enforce
				// that we must be able to patch out the authkey after
				// authenticating if you want to use this feature. This avoids
				// us having to deal with the case where we might leave behind
				// an unnecessary reusable authkey in a secret, like a rake in
				// the grass.
				if !cfg.KubernetesCanPatch {
					log.Fatalf("authkey found in TS_KUBE_SECRET, but the pod doesn't have patch permissions on the secret to manage the authkey.")
				}
				log.Print("Using authkey found in kube secret")
				cfg.AuthKey = key
			} else {
				log.Print("No authkey found in kube secret and TS_AUTHKEY not provided, login will be interactive if needed.")
			}
		}
	}

	client, daemonPid, err := startTailscaled(ctx, cfg)
	if err != nil {
		log.Fatalf("failed to bring up tailscale: %v", err)
	}

	w, err := client.WatchIPNBus(ctx, ipn.NotifyInitialNetMap|ipn.NotifyInitialPrefs|ipn.NotifyInitialState)
	if err != nil {
		log.Fatalf("failed to watch tailscaled for updates: %v", err)
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
		if err := tailscaleUp(ctx, cfg); err != nil {
			return fmt.Errorf("failed to auth tailscale: %v", err)
		}
		w, err = client.WatchIPNBus(ctx, ipn.NotifyInitialNetMap|ipn.NotifyInitialState)
		if err != nil {
			return fmt.Errorf("rewatching tailscaled for updates after auth: %v", err)
		}
		return nil
	}

	if !cfg.AuthOnce {
		if err := authTailscale(); err != nil {
			log.Fatalf("failed to auth tailscale: %v", err)
		}
	}

authLoop:
	for {
		n, err := w.Next()
		if err != nil {
			log.Fatalf("failed to read from tailscaled: %v", err)
		}

		if n.State != nil {
			switch *n.State {
			case ipn.NeedsLogin:
				if err := authTailscale(); err != nil {
					log.Fatalf("failed to auth tailscale: %v", err)
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

	if cfg.InKubernetes && cfg.KubeSecret != "" && cfg.KubernetesCanPatch && cfg.AuthOnce {
		// We were told to only auth once, so any secret-bound
		// authkey is no longer needed. We don't strictly need to
		// wipe it, but it's good hygiene.
		log.Printf("Deleting authkey from kube secret")
		if err := deleteAuthKey(ctx, cfg.KubeSecret); err != nil {
			log.Fatalf("deleting authkey from kube secret: %v", err)
		}
	}

	w, err = client.WatchIPNBus(context.Background(), ipn.NotifyInitialNetMap|ipn.NotifyInitialState)
	if err != nil {
		log.Fatalf("rewatching tailscaled for updates after auth: %v", err)
	}

	var (
		wantProxy         = cfg.ProxyTo != ""
		wantDeviceInfo    = cfg.InKubernetes && cfg.KubeSecret != "" && cfg.KubernetesCanPatch
		startupTasksDone  = false
		currentIPs        deephash.Sum // tailscale IPs assigned to device
		currentDeviceInfo deephash.Sum // device ID and fqdn
	)
	for {
		n, err := w.Next()
		if err != nil {
			log.Fatalf("failed to read from tailscaled: %v", err)
		}

		if n.State != nil && *n.State != ipn.Running {
			// Something's gone wrong and we've left the authenticated state.
			// Our container image never recovered gracefully from this, and the
			// control flow required to make it work now is hard. So, just crash
			// the container and rely on the container runtime to restart us,
			// whereupon we'll go through initial auth again.
			log.Fatalf("tailscaled left running state (now in state %q), exiting", *n.State)
		}
		if n.NetMap != nil {
			if cfg.ProxyTo != "" && len(n.NetMap.Addresses) > 0 && deephash.Update(&currentIPs, &n.NetMap.Addresses) {
				if err := installIPTablesRule(ctx, cfg.ProxyTo, n.NetMap.Addresses); err != nil {
					log.Fatalf("installing proxy rules: %v", err)
				}
			}
			deviceInfo := []any{n.NetMap.SelfNode.StableID, n.NetMap.SelfNode.Name}
			if cfg.InKubernetes && cfg.KubernetesCanPatch && cfg.KubeSecret != "" && deephash.Update(&currentDeviceInfo, &deviceInfo) {
				if err := storeDeviceInfo(ctx, cfg.KubeSecret, n.NetMap.SelfNode.StableID, n.NetMap.SelfNode.Name); err != nil {
					log.Fatalf("storing device ID in kube secret: %v", err)
				}
			}
		}
		if !startupTasksDone {
			if (!wantProxy || currentIPs != deephash.Sum{}) && (!wantDeviceInfo || currentDeviceInfo != deephash.Sum{}) {
				// This log message is used in tests to detect when all
				// post-auth configuration is done.
				log.Println("Startup complete, waiting for shutdown signal")
				startupTasksDone = true

				// Reap all processes, since we are PID1 and need to collect zombies. We can
				// only start doing this once we've stopped shelling out to things
				// `tailscale up`, otherwise this goroutine can reap the CLI subprocesses
				// and wedge bringup.
				go func() {
					for {
						var status unix.WaitStatus
						pid, err := unix.Wait4(-1, &status, 0, nil)
						if errors.Is(err, unix.EINTR) {
							continue
						}
						if err != nil {
							log.Fatalf("Waiting for exited processes: %v", err)
						}
						if pid == daemonPid {
							log.Printf("Tailscaled exited")
							os.Exit(0)
						}
					}
				}()
			}
		}
	}
}

func startTailscaled(ctx context.Context, cfg *settings) (*tailscale.LocalClient, int, error) {
	args := tailscaledArgs(cfg)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, unix.SIGTERM, unix.SIGINT)
	// tailscaled runs without context, since it needs to persist
	// beyond the startup timeout in ctx.
	cmd := exec.Command("tailscaled", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	log.Printf("Starting tailscaled")
	if err := cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("starting tailscaled failed: %v", err)
	}
	go func() {
		<-sigCh
		log.Printf("Received SIGTERM from container runtime, shutting down tailscaled")
		cmd.Process.Signal(unix.SIGTERM)
	}()

	// Wait for the socket file to appear, otherwise API ops will racily fail.
	log.Printf("Waiting for tailscaled socket")
	for {
		if ctx.Err() != nil {
			log.Fatalf("Timed out waiting for tailscaled socket")
		}
		_, err := os.Stat(cfg.Socket)
		if errors.Is(err, fs.ErrNotExist) {
			time.Sleep(100 * time.Millisecond)
			continue
		} else if err != nil {
			log.Fatalf("Waiting for tailscaled socket: %v", err)
		}
		break
	}

	tsClient := &tailscale.LocalClient{
		Socket:        cfg.Socket,
		UseSocketOnly: true,
	}

	return tsClient, cmd.Process.Pid, nil
}

// tailscaledArgs uses cfg to construct the argv for tailscaled.
func tailscaledArgs(cfg *settings) []string {
	args := []string{"--socket=" + cfg.Socket}
	switch {
	case cfg.InKubernetes && cfg.KubeSecret != "":
		args = append(args, "--state=kube:"+cfg.KubeSecret)
		if cfg.StateDir == "" {
			cfg.StateDir = "/tmp"
		}
		fallthrough
	case cfg.StateDir != "":
		args = append(args, "--statedir="+cfg.StateDir)
	default:
		args = append(args, "--state=mem:", "--statedir=/tmp")
	}

	if cfg.UserspaceMode {
		args = append(args, "--tun=userspace-networking")
	} else if err := ensureTunFile(cfg.Root); err != nil {
		log.Fatalf("ensuring that /dev/net/tun exists: %v", err)
	}

	if cfg.SOCKSProxyAddr != "" {
		args = append(args, "--socks5-server="+cfg.SOCKSProxyAddr)
	}
	if cfg.HTTPProxyAddr != "" {
		args = append(args, "--outbound-http-proxy-listen="+cfg.HTTPProxyAddr)
	}
	if cfg.DaemonExtraArgs != "" {
		args = append(args, strings.Fields(cfg.DaemonExtraArgs)...)
	}
	return args
}

// tailscaleUp uses cfg to run 'tailscale up'.
func tailscaleUp(ctx context.Context, cfg *settings) error {
	args := []string{"--socket=" + cfg.Socket, "up"}
	if cfg.AcceptDNS {
		args = append(args, "--accept-dns=true")
	} else {
		args = append(args, "--accept-dns=false")
	}
	if cfg.AuthKey != "" {
		args = append(args, "--authkey="+cfg.AuthKey)
	}
	if cfg.Routes != "" {
		args = append(args, "--advertise-routes="+cfg.Routes)
	}
	if cfg.Hostname != "" {
		args = append(args, "--hostname="+cfg.Hostname)
	}
	if cfg.ExtraArgs != "" {
		args = append(args, strings.Fields(cfg.ExtraArgs)...)
	}
	log.Printf("Running 'tailscale up'")
	cmd := exec.CommandContext(ctx, "tailscale", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tailscale up failed: %v", err)
	}
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

// ensureIPForwarding enables IPv4/IPv6 forwarding for the container.
func ensureIPForwarding(root, proxyTo, routes string) error {
	var (
		v4Forwarding, v6Forwarding bool
	)
	if proxyTo != "" {
		proxyIP, err := netip.ParseAddr(proxyTo)
		if err != nil {
			return fmt.Errorf("invalid proxy destination IP: %v", err)
		}
		if proxyIP.Is4() {
			v4Forwarding = true
		} else {
			v6Forwarding = true
		}
	}
	if routes != "" {
		for _, route := range strings.Split(routes, ",") {
			cidr, err := netip.ParsePrefix(route)
			if err != nil {
				return fmt.Errorf("invalid subnet route: %v", err)
			}
			if cidr.Addr().Is4() {
				v4Forwarding = true
			} else {
				v6Forwarding = true
			}
		}
	}

	var paths []string
	if v4Forwarding {
		paths = append(paths, filepath.Join(root, "proc/sys/net/ipv4/ip_forward"))
	}
	if v6Forwarding {
		paths = append(paths, filepath.Join(root, "proc/sys/net/ipv6/conf/all/forwarding"))
	}

	// In some common configurations (e.g. default docker,
	// kubernetes), the container environment denies write access to
	// most sysctls, including IP forwarding controls. Check the
	// sysctl values before trying to change them, so that we
	// gracefully do nothing if the container's already been set up
	// properly by e.g. a k8s initContainer.
	for _, path := range paths {
		bs, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %q: %w", path, err)
		}
		if v := strings.TrimSpace(string(bs)); v != "1" {
			if err := os.WriteFile(path, []byte("1"), 0644); err != nil {
				return fmt.Errorf("enabling %q: %w", path, err)
			}
		}
	}
	return nil
}

func installIPTablesRule(ctx context.Context, dstStr string, tsIPs []netip.Prefix) error {
	dst, err := netip.ParseAddr(dstStr)
	if err != nil {
		return err
	}
	argv0 := "iptables"
	if dst.Is6() {
		argv0 = "ip6tables"
	}
	var local string
	for _, pfx := range tsIPs {
		if !pfx.IsSingleIP() {
			continue
		}
		if pfx.Addr().Is4() != dst.Is4() {
			continue
		}
		local = pfx.Addr().String()
		break
	}
	if local == "" {
		return fmt.Errorf("no tailscale IP matching family of %s found in %v", dstStr, tsIPs)
	}
	// Technically, if the control server ever changes the IPs assigned to this
	// node, we'll slowly accumulate iptables rules. This shouldn't happen, so
	// for now we'll live with it.
	cmd := exec.CommandContext(ctx, argv0, "-t", "nat", "-I", "PREROUTING", "1", "-d", local, "-j", "DNAT", "--to-destination", dstStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("executing iptables failed: %w", err)
	}
	return nil
}

// settings is all the configuration for containerboot.
type settings struct {
	AuthKey            string
	Hostname           string
	Routes             string
	ProxyTo            string
	DaemonExtraArgs    string
	ExtraArgs          string
	InKubernetes       bool
	UserspaceMode      bool
	StateDir           string
	AcceptDNS          bool
	KubeSecret         string
	SOCKSProxyAddr     string
	HTTPProxyAddr      string
	Socket             string
	AuthOnce           bool
	Root               string
	KubernetesCanPatch bool
}

// defaultEnv returns the value of the given envvar name, or defVal if
// unset.
func defaultEnv(name, defVal string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return defVal
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
