// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

// The containerboot binary is a wrapper for starting tailscaled in a
// container. It handles reading the desired mode of operation out of
// environment variables, bringing up and authenticating Tailscale,
// and any other kubernetes-specific side jobs.
//
// As with most container things, configuration is passed through
// environment variables. All configuration is optional.
//
//  - TS_AUTH_KEY: the authkey to use for login.
//  - TS_ROUTES: subnet routes to advertise.
//  - TS_DEST_IP: proxy all incoming Tailscale traffic to the given
//                destination.
//  - TS_TAILSCALED_EXTRA_ARGS: extra arguments to 'tailscaled'.
//  - TS_EXTRA_ARGS: extra arguments to 'tailscale up'.
//  - TS_USERSPACE: run with userspace networking (the default)
//                  instead of kernel networking.
//  - TS_STATE_DIR: the directory in which to store tailscaled
//                  state. The data should persist across container
//                  restarts.
//  - TS_ACCEPT_DNS: whether to use the tailnet's DNS configuration.
//  - TS_KUBE_SECRET: the name of the Kubernetes secret in which to
//                    store tailscaled state.
//  - TS_SOCKS5_SERVER: the address on which to listen for SOCKS5
//                      proxying into the tailnet.
//  - TS_OUTBOUND_HTTP_PROXY_LISTEN: the address on which to listen
//                                   for HTTP proxying into the tailnet.
//  - TS_SOCKET: the path where the tailscaled local API socket should
//               be created.
//  - TS_AUTH_ONCE: if true, only attempt to log in if not already
//                  logged in. If false (the default, for backwards
//                  compatibility), forcibly log in every time the
//                  container starts.
//
// When running on Kubernetes, TS_KUBE_SECRET takes precedence over
// TS_STATE_DIR. Additionally, if TS_AUTH_KEY is not provided and the
// TS_KUBE_SECRET contains an "authkey" field, that key is used.
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
)

func main() {
	log.SetPrefix("boot: ")
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	cfg := &settings{
		AuthKey:         defaultEnv("TS_AUTH_KEY", ""),
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
	}

	if cfg.ProxyTo != "" && cfg.UserspaceMode {
		log.Fatal("TS_DEST_IP is not supported with TS_USERSPACE")
	}

	if !cfg.UserspaceMode {
		if err := ensureTunFile(); err != nil {
			log.Fatalf("Unable to create tuntap device file: %v", err)
		}
	}
	if cfg.ProxyTo != "" || cfg.Routes != "" {
		if err := ensureIPForwarding(); err != nil {
			log.Printf("Failed to enable IP forwarding: %v", err)
			log.Printf("To run tailscale as a proxy or router container, IP forwarding must be enabled.")
			if cfg.InKubernetes {
				log.Fatalf("You can either set the sysctls as a privileged initContainer, or run the tailscale container with privileged=true.")
			} else {
				log.Fatalf("You can fix this by running the container with privileged=true, or the equivalent in your container runtime that permits access to sysctls.")
			}
		}
	}

	// Context is used for all setup stuff until we're in steady
	// state, so that if something is hanging we eventually time out
	// and crashloop the container.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if cfg.InKubernetes && cfg.KubeSecret != "" && cfg.AuthKey == "" {
		key, err := findKeyInKubeSecret(ctx, cfg.KubeSecret)
		if err != nil {
			log.Fatalf("Getting authkey from kube secret: %v", err)
		}
		if key != "" {
			log.Print("Using authkey found in kube secret")
			cfg.AuthKey = key
		} else {
			log.Print("No authkey found in kube secret and TS_AUTHKEY not provided, login will be interactive if needed.")
		}
	}

	st, daemonPid, err := startAndAuthTailscaled(ctx, cfg)
	if err != nil {
		log.Fatalf("failed to bring up tailscale: %v", err)
	}

	if cfg.ProxyTo != "" {
		if err := installIPTablesRule(ctx, cfg.ProxyTo, st.TailscaleIPs); err != nil {
			log.Fatalf("installing proxy rules: %v", err)
		}
	}
	if cfg.KubeSecret != "" {
		if err := storeDeviceID(ctx, cfg.KubeSecret, string(st.Self.ID)); err != nil {
			log.Fatalf("storing device ID in kube secret: %v", err)
		}
		if cfg.AuthOnce {
			// We were told to only auth once, so any secret-bound
			// authkey is no longer needed. We don't strictly need to
			// wipe it, but it's good hygiene.
			log.Printf("Deleting authkey from kube secret")
			if err := deleteAuthKey(ctx, cfg.KubeSecret); err != nil {
				log.Fatalf("deleting authkey from kube secret: %v", err)
			}
		}
	}

	log.Println("Startup complete, waiting for shutdown signal")
	// Reap all processes, since we are PID1 and need to collect
	// zombies.
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
}

// startAndAuthTailscaled starts the tailscale daemon and attempts to
// auth it, according to the settings in cfg. If successful, returns
// tailscaled's Status and pid.
func startAndAuthTailscaled(ctx context.Context, cfg *settings) (*ipnstate.Status, int, error) {
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

	// Wait for the socket file to appear, otherwise 'tailscale up'
	// can fail.
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

	if !cfg.AuthOnce {
		if err := tailscaleUp(ctx, cfg); err != nil {
			return nil, 0, fmt.Errorf("couldn't log in: %v", err)
		}
	}

	tsClient := tailscale.LocalClient{
		Socket:        cfg.Socket,
		UseSocketOnly: true,
	}

	// Poll for daemon state until it goes to either Running or
	// NeedsLogin. The latter only happens if cfg.AuthOnce is true,
	// because in that case we only try to auth when it's necessary to
	// reach the running state.
	for {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}

		loopCtx, cancel := context.WithTimeout(ctx, time.Second)
		st, err := tsClient.Status(loopCtx)
		cancel()
		if err != nil {
			return nil, 0, fmt.Errorf("Getting tailscaled state: %w", err)
		}

		switch st.BackendState {
		case "Running":
			if len(st.TailscaleIPs) > 0 {
				return st, cmd.Process.Pid, nil
			}
			log.Printf("No Tailscale IPs assigned yet")
		case "NeedsLogin":
			// Alas, we cannot currently trigger an authkey login from
			// LocalAPI, so we still have to shell out to the
			// tailscale CLI for this bit.
			if err := tailscaleUp(ctx, cfg); err != nil {
				return nil, 0, fmt.Errorf("couldn't log in: %v", err)
			}
		default:
			log.Printf("tailscaled in state %q, waiting", st.BackendState)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// tailscaledArgs uses cfg to construct the argv for tailscaled.
func tailscaledArgs(cfg *settings) []string {
	args := []string{"--socket=" + cfg.Socket}
	switch {
	case cfg.InKubernetes && cfg.KubeSecret != "":
		args = append(args, "--state=kube:"+cfg.KubeSecret, "--statedir=/tmp")
	case cfg.StateDir != "":
		args = append(args, "--state="+cfg.StateDir)
	default:
		args = append(args, "--state=mem:", "--statedir=/tmp")
	}

	if cfg.UserspaceMode {
		args = append(args, "--tun=userspace-networking")
	} else if err := ensureTunFile(); err != nil {
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
func ensureTunFile() error {
	// Verify that /dev/net/tun exists, in some container envs it
	// needs to be mknod-ed.
	if _, err := os.Stat("/dev/net"); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll("/dev/net", 0755); err != nil {
			return err
		}
	}
	if _, err := os.Stat("/dev/net/tun"); errors.Is(err, fs.ErrNotExist) {
		dev := unix.Mkdev(10, 200) // tuntap major and minor
		if err := unix.Mknod("/dev/net/tun", 0600|unix.S_IFCHR, int(dev)); err != nil {
			return err
		}
	}
	return nil
}

// ensureIPForwarding enables IPv4/IPv6 forwarding for the container.
func ensureIPForwarding() error {
	// In some common configurations (e.g. default docker,
	// kubernetes), the container environment denies write access to
	// most sysctls, including IP forwarding controls. Check the
	// sysctl values before trying to change them, so that we
	// gracefully do nothing if the container's already been set up
	// properly by e.g. a k8s initContainer.
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
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

func installIPTablesRule(ctx context.Context, dstStr string, tsIPs []netip.Addr) error {
	dst, err := netip.ParseAddr(dstStr)
	if err != nil {
		return err
	}
	argv0 := "iptables"
	if dst.Is6() {
		argv0 = "ip6tables"
	}
	var local string
	for _, ip := range tsIPs {
		if ip.Is4() != dst.Is4() {
			continue
		}
		local = ip.String()
		break
	}
	if local == "" {
		return fmt.Errorf("no tailscale IP matching family of %s found in %v", dstStr, tsIPs)
	}
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
	AuthKey         string
	Routes          string
	ProxyTo         string
	DaemonExtraArgs string
	ExtraArgs       string
	InKubernetes    bool
	UserspaceMode   bool
	StateDir        string
	AcceptDNS       bool
	KubeSecret      string
	SOCKSProxyAddr  string
	HTTPProxyAddr   string
	Socket          string
	AuthOnce        bool
}

// defaultEnv returns the value of the given envvar name, or defVal if
// unset.
func defaultEnv(name, defVal string) string {
	if v := os.Getenv(name); v != "" {
		return v
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
