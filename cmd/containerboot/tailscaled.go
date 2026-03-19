// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/client/local"
)

func startTailscaled(ctx context.Context, cfg *settings) (*local.Client, *os.Process, error) {
	args := tailscaledArgs(cfg)
	// tailscaled runs without context, since it needs to persist
	// beyond the startup timeout in ctx.
	cmd := exec.Command("tailscaled", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	if cfg.CertShareMode != "" {
		cmd.Env = append(os.Environ(), "TS_CERT_SHARE_MODE="+cfg.CertShareMode)
	}
	log.Printf("Starting tailscaled")
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting tailscaled failed: %w", err)
	}

	// Wait for the socket file to appear, otherwise API ops will racily fail.
	log.Printf("Waiting for tailscaled socket at %s", cfg.Socket)
	for {
		if ctx.Err() != nil {
			return nil, nil, errors.New("timed out waiting for tailscaled socket")
		}
		_, err := os.Stat(cfg.Socket)
		if errors.Is(err, fs.ErrNotExist) {
			time.Sleep(100 * time.Millisecond)
			continue
		} else if err != nil {
			return nil, nil, fmt.Errorf("error waiting for tailscaled socket: %w", err)
		}
		break
	}

	tsClient := &local.Client{
		Socket:        cfg.Socket,
		UseSocketOnly: true,
	}

	return tsClient, cmd.Process, nil
}

// tailscaledArgs uses cfg to construct the argv for tailscaled.
func tailscaledArgs(cfg *settings) []string {
	args := []string{"--socket=" + cfg.Socket}
	switch {
	case cfg.KubeSecret != "":
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
	if cfg.TailscaledConfigFilePath != "" {
		args = append(args, "--config="+cfg.TailscaledConfigFilePath)
	}
	// Once enough proxy versions have been released for all the supported
	// versions to understand this cfg setting, the operator can stop
	// setting TS_TAILSCALED_EXTRA_ARGS for the debug flag.
	if cfg.DebugAddrPort != "" && !strings.Contains(cfg.DaemonExtraArgs, cfg.DebugAddrPort) {
		args = append(args, "--debug="+cfg.DebugAddrPort)
	}
	if cfg.DaemonExtraArgs != "" {
		args = append(args, strings.Fields(cfg.DaemonExtraArgs)...)
	}
	return args
}

// tailscaleUp uses cfg to run 'tailscale up' everytime containerboot starts, or
// if TS_AUTH_ONCE is set, only the first time containerboot starts.
func tailscaleUp(ctx context.Context, cfg *settings) error {
	args := []string{"--socket=" + cfg.Socket, "up"}
	if cfg.AcceptDNS != nil && *cfg.AcceptDNS {
		args = append(args, "--accept-dns=true")
	} else {
		args = append(args, "--accept-dns=false")
	}
	if cfg.AuthKey != "" {
		args = append(args, "--authkey="+cfg.AuthKey)
	}
	if cfg.ClientID != "" {
		args = append(args, "--client-id="+cfg.ClientID)
	}
	if cfg.ClientSecret != "" {
		args = append(args, "--client-secret="+cfg.ClientSecret)
	}
	if cfg.IDToken != "" {
		args = append(args, "--id-token="+cfg.IDToken)
	}
	if cfg.Audience != "" {
		args = append(args, "--audience="+cfg.Audience)
	}
	// --advertise-routes can be passed an empty string to configure a
	// device (that might have previously advertised subnet routes) to not
	// advertise any routes. Respect an empty string passed by a user and
	// use it to explicitly unset the routes.
	if cfg.Routes != nil {
		args = append(args, "--advertise-routes="+*cfg.Routes)
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

// tailscaleSet uses cfg to run 'tailscale set' to set any known configuration
// options that are passed in via environment variables. This is run after the
// node is in Running state and only if TS_AUTH_ONCE is set.
func tailscaleSet(ctx context.Context, cfg *settings) error {
	args := []string{"--socket=" + cfg.Socket, "set"}
	if cfg.AcceptDNS != nil && *cfg.AcceptDNS {
		args = append(args, "--accept-dns=true")
	} else {
		args = append(args, "--accept-dns=false")
	}
	// --advertise-routes can be passed an empty string to configure a
	// device (that might have previously advertised subnet routes) to not
	// advertise any routes. Respect an empty string passed by a user and
	// use it to explicitly unset the routes.
	if cfg.Routes != nil {
		args = append(args, "--advertise-routes="+*cfg.Routes)
	}
	if cfg.Hostname != "" {
		args = append(args, "--hostname="+cfg.Hostname)
	}
	log.Printf("Running 'tailscale set'")
	cmd := exec.CommandContext(ctx, "tailscale", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tailscale set failed: %v", err)
	}
	return nil
}

func watchTailscaledConfigChanges(ctx context.Context, path string, lc *local.Client, errCh chan<- error) {
	var (
		tickChan          <-chan time.Time
		eventChan         <-chan fsnotify.Event
		errChan           <-chan error
		tailscaledCfgDir  = filepath.Dir(path)
		prevTailscaledCfg []byte
	)
	if w, err := fsnotify.NewWatcher(); err != nil {
		// Creating a new fsnotify watcher would fail for example if inotify was not able to create a new file descriptor.
		// See https://github.com/tailscale/tailscale/issues/15081
		log.Printf("tailscaled config watch: failed to create fsnotify watcher, timer-only mode: %v", err)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		tickChan = ticker.C
	} else {
		defer w.Close()
		if err := w.Add(tailscaledCfgDir); err != nil {
			errCh <- fmt.Errorf("failed to add fsnotify watch: %w", err)
			return
		}
		eventChan = w.Events
		errChan = w.Errors
	}
	b, err := os.ReadFile(path)
	if err != nil {
		errCh <- fmt.Errorf("error reading configfile: %w", err)
		return
	}
	prevTailscaledCfg = b
	// kubelet mounts Secrets to Pods using a series of symlinks, one of
	// which is <mount-dir>/..data that Kubernetes recommends consumers to
	// use if they need to monitor changes
	// https://github.com/kubernetes/kubernetes/blob/v1.28.1/pkg/volume/util/atomic_writer.go#L39-L61
	const kubeletMountedCfg = "..data"
	toWatch := filepath.Join(tailscaledCfgDir, kubeletMountedCfg)
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errChan:
			errCh <- fmt.Errorf("watcher error: %w", err)
			return
		case <-tickChan:
		case event := <-eventChan:
			if event.Name != toWatch {
				continue
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			errCh <- fmt.Errorf("error reading configfile: %w", err)
			return
		}
		// For some proxy types the mounted volume also contains tailscaled state and other files. We
		// don't want to reload config unnecessarily on unrelated changes to these files.
		if reflect.DeepEqual(b, prevTailscaledCfg) {
			continue
		}
		prevTailscaledCfg = b
		log.Printf("tailscaled config watch: ensuring that config is up to date")
		ok, err := lc.ReloadConfig(ctx)
		if err != nil {
			errCh <- fmt.Errorf("error reloading tailscaled config: %w", err)
			return
		}
		if ok {
			log.Printf("tailscaled config watch: config was reloaded")
		}
	}
}
