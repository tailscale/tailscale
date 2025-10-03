// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/router"
)

func init() {
	router.HookNewUserspaceRouter.Set(func(opts router.NewOpts) (router.Router, error) {
		return newUserspaceRouter(opts.Logf, opts.Tun, opts.NetMon, opts.Health, opts.Bus)
	})
}

type winRouter struct {
	logf                func(fmt string, args ...any)
	netMon              *netmon.Monitor // may be nil
	health              *health.Tracker
	nativeTun           *tun.NativeTun
	routeChangeCallback *winipcfg.RouteChangeCallback
	firewall            *firewallTweaker
}

func newUserspaceRouter(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor, health *health.Tracker, bus *eventbus.Bus) (router.Router, error) {
	nativeTun := tundev.(*tun.NativeTun)
	luid := winipcfg.LUID(nativeTun.LUID())
	guid, err := luid.GUID()
	if err != nil {
		return nil, err
	}

	return &winRouter{
		logf:      logf,
		netMon:    netMon,
		health:    health,
		nativeTun: nativeTun,
		firewall: &firewallTweaker{
			logf:    logger.WithPrefix(logf, "firewall: "),
			tunGUID: *guid,
		},
	}, nil
}

func (r *winRouter) Up() error {
	r.firewall.clear()

	var err error
	t0 := time.Now()
	r.routeChangeCallback, err = monitorDefaultRoutes(r.nativeTun)
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		return fmt.Errorf("monitorDefaultRoutes, after %v: %v", d, err)
	}
	r.logf("monitorDefaultRoutes done after %v", d)
	return nil
}

func (r *winRouter) Set(cfg *router.Config) error {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	var localAddrs []string
	for _, la := range cfg.LocalAddrs {
		localAddrs = append(localAddrs, la.String())
	}
	r.firewall.set(localAddrs, cfg.Routes, cfg.LocalRoutes)

	err := configureInterface(cfg, r.nativeTun, r.health)
	if err != nil {
		r.logf("ConfigureInterface: %v", err)
		return err
	}

	// Flush DNS on router config change to clear cached DNS entries (solves #1430)
	if err := dns.Flush(); err != nil {
		r.logf("flushdns error: %v", err)
	}

	return nil
}

func hasDefaultRoute(routes []netip.Prefix) bool {
	for _, route := range routes {
		if route.Bits() == 0 {
			return true
		}
	}
	return false
}

func (r *winRouter) Close() error {
	r.firewall.clear()

	if r.routeChangeCallback != nil {
		r.routeChangeCallback.Unregister()
	}

	return nil
}

// firewallTweaker changes the Windows firewall. Normally this wouldn't be so complicated,
// but it can be REALLY SLOW to change the Windows firewall for reasons not understood.
// Like 4 minutes slow. But usually it's tens of milliseconds.
// See https://github.com/tailscale/tailscale/issues/785.
// So this tracks the desired state and runs the actual adjusting code asynchronously.
type firewallTweaker struct {
	logf    logger.Logf
	tunGUID windows.GUID

	mu          sync.Mutex
	didProcRule bool
	running     bool     // doAsyncSet goroutine is running
	known       bool     // firewall is in known state (in lastVal)
	wantLocal   []string // next value we want, or "" to delete the firewall rule
	lastLocal   []string // last set value, if known

	localRoutes     []netip.Prefix
	lastLocalRoutes []netip.Prefix

	wantKillswitch bool
	lastKillswitch bool

	// Only touched by doAsyncSet, so mu doesn't need to be held.

	// fwProc is a subprocess that runs the wireguard-windows firewall
	// killswitch code. It is only non-nil when the default route
	// killswitch is active, and may go back and forth between nil and
	// non-nil any number of times during the process's lifetime.
	fwProc *exec.Cmd
	// stop makes fwProc exit when closed.
	fwProcWriter  io.WriteCloser
	fwProcEncoder *json.Encoder

	// The path to the 'netsh.exe' binary, populated during the first call
	// to runFirewall.
	//
	// not protected by mu; netshPath is only mutated inside netshPathOnce
	netshPathOnce sync.Once
	netshPath     string
}

func (ft *firewallTweaker) clear() { ft.set(nil, nil, nil) }

// set takes CIDRs to allow, and the routes that point into the Tailscale tun interface.
// Empty slices remove firewall rules.
//
// set takes ownership of cidrs, but not routes.
func (ft *firewallTweaker) set(cidrs []string, routes, localRoutes []netip.Prefix) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	if len(cidrs) == 0 {
		ft.logf("marking for removal")
	} else {
		ft.logf("marking allowed %v", cidrs)
	}
	ft.wantLocal = cidrs
	ft.localRoutes = localRoutes
	ft.wantKillswitch = hasDefaultRoute(routes)
	if ft.running {
		// The doAsyncSet goroutine will check ft.wantLocal/wantKillswitch
		// before returning.
		return
	}
	ft.logf("starting netsh goroutine")
	ft.running = true
	go ft.doAsyncSet()
}

// getNetshPath returns the path that should be used to execute netsh.
//
// We've seen a report from a customer that we're triggering the "cannot run
// executable found relative to current directory" protection that was added to
// prevent running possibly attacker-controlled binaries. To mitigate this,
// first try looking up the path to netsh.exe in the System32 directory
// explicitly, and then fall back to the prior behaviour of passing "netsh" to
// os/exec.Command.
func (ft *firewallTweaker) getNetshPath() string {
	ft.netshPathOnce.Do(func() {
		// The default value is the old approach: just run "netsh" and
		// let os/exec resolve that into a full path.
		ft.netshPath = "netsh"

		path, err := windows.KnownFolderPath(windows.FOLDERID_System, 0)
		if err != nil {
			ft.logf("getNetshPath: error getting FOLDERID_System: %v", err)
			return
		}

		expath := filepath.Join(path, "netsh.exe")
		if _, err := os.Stat(expath); err == nil {
			ft.netshPath = expath
			return
		} else if !os.IsNotExist(err) {
			ft.logf("getNetshPath: error checking for existence of %q: %v", expath, err)
		}

		// Keep default
	})
	return ft.netshPath
}

func (ft *firewallTweaker) runFirewall(args ...string) (time.Duration, error) {
	t0 := time.Now()
	args = append([]string{"advfirewall", "firewall"}, args...)
	cmd := exec.Command(ft.getNetshPath(), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS,
	}
	b, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%w: %v", err, string(b))
	}
	return time.Since(t0).Round(time.Millisecond), err
}

func (ft *firewallTweaker) doAsyncSet() {
	bo := backoff.NewBackoff("win-firewall", ft.logf, time.Minute)
	ctx := context.Background()

	ft.mu.Lock()
	for { // invariant: ft.mu must be locked when beginning this block
		val := ft.wantLocal
		if ft.known && slices.Equal(ft.lastLocal, val) && ft.wantKillswitch == ft.lastKillswitch && slices.Equal(ft.localRoutes, ft.lastLocalRoutes) {
			ft.running = false
			ft.logf("ending netsh goroutine")
			ft.mu.Unlock()
			return
		}
		wantKillswitch := ft.wantKillswitch
		needClear := !ft.known || len(ft.lastLocal) > 0 || len(val) == 0
		needProcRule := !ft.didProcRule
		localRoutes := ft.localRoutes
		ft.mu.Unlock()

		err := ft.doSet(val, wantKillswitch, needClear, needProcRule, localRoutes)
		if err != nil {
			ft.logf("set failed: %v", err)
		}
		bo.BackOff(ctx, err)

		ft.mu.Lock()
		ft.lastLocal = val
		ft.lastLocalRoutes = localRoutes
		ft.lastKillswitch = wantKillswitch
		ft.known = (err == nil)
	}
}

// doSet creates and deletes firewall rules to make the system state
// match the values of local, killswitch, clear and procRule.
//
// local is the list of local Tailscale addresses (formatted as CIDR
// prefixes) to allow through the Windows firewall.
// killswitch, if true, enables the wireguard-windows based internet
// killswitch to prevent use of non-Tailscale default routes.
// clear, if true, removes all tailscale address firewall rules before
// adding local.
// procRule, if true, installs a firewall rule that permits the Tailscale
// process to dial out as it pleases.
//
// Must only be invoked from doAsyncSet.
func (ft *firewallTweaker) doSet(local []string, killswitch bool, clear bool, procRule bool, allowedRoutes []netip.Prefix) error {
	if clear {
		ft.logf("clearing Tailscale-In firewall rules...")
		// We ignore the error here, because netsh returns an error for
		// deleting something that doesn't match.
		// TODO(bradfitz): care? That'd involve querying it before/after to see
		// whether it was necessary/worked. But the output format is localized,
		// so can't rely on parsing English. Maybe need to use OLE, not netsh.exe?
		d, _ := ft.runFirewall("delete", "rule", "name=Tailscale-In", "dir=in")
		ft.logf("cleared Tailscale-In firewall rules in %v", d)
	}
	if procRule {
		ft.logf("deleting any prior Tailscale-Process rule...")
		d, err := ft.runFirewall("delete", "rule", "name=Tailscale-Process", "dir=in") // best effort
		if err == nil {
			ft.logf("removed old Tailscale-Process rule in %v", d)
		}
		var exe string
		exe, err = os.Executable()
		if err != nil {
			ft.logf("failed to find Executable for Tailscale-Process rule: %v", err)
		} else {
			ft.logf("adding Tailscale-Process rule to allow UDP for %q ...", exe)
			d, err = ft.runFirewall("add", "rule", "name=Tailscale-Process",
				"dir=in",
				"action=allow",
				"edge=yes",
				"program="+exe,
				"protocol=udp",
				"profile=any",
				"enable=yes",
			)
			if err != nil {
				ft.logf("error adding Tailscale-Process rule: %v", err)
			} else {
				ft.mu.Lock()
				ft.didProcRule = true
				ft.mu.Unlock()
				ft.logf("added Tailscale-Process rule in %v", d)
			}
		}
	}
	for _, cidr := range local {
		ft.logf("adding Tailscale-In rule to allow %v ...", cidr)
		var d time.Duration
		d, err := ft.runFirewall("add", "rule", "name=Tailscale-In", "dir=in", "action=allow", "localip="+cidr, "profile=private,domain", "enable=yes")
		if err != nil {
			ft.logf("error adding Tailscale-In rule to allow %v: %v", cidr, err)
			return err
		}
		ft.logf("added Tailscale-In rule to allow %v in %v", cidr, d)
	}

	if !killswitch {
		if ft.fwProc != nil {
			ft.fwProcWriter.Close()
			ft.fwProcWriter = nil
			ft.fwProc.Wait()
			ft.fwProc = nil
			ft.fwProcEncoder = nil
		}
		return nil
	}
	if ft.fwProc == nil {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		proc := exec.Command(exe, "/firewall", ft.tunGUID.String())
		proc.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: windows.DETACHED_PROCESS,
		}
		in, err := proc.StdinPipe()
		if err != nil {
			return err
		}
		out, err := proc.StdoutPipe()
		if err != nil {
			in.Close()
			return err
		}

		go func(out io.ReadCloser) {
			b := bufio.NewReaderSize(out, 1<<10)
			for {
				line, err := b.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimSpace(line)
				if line != "" {
					ft.logf("fw-child: %s", line)
				}
			}
		}(out)
		proc.Stderr = proc.Stdout

		if err := proc.Start(); err != nil {
			return err
		}
		ft.fwProcWriter = in
		ft.fwProc = proc
		ft.fwProcEncoder = json.NewEncoder(in)
	}
	// Note(maisem): when local lan access toggled, we need to inform the
	// firewall to let the local routes through. The set of routes is passed
	// in via stdin encoded in json.
	return ft.fwProcEncoder.Encode(allowedRoutes)
}
