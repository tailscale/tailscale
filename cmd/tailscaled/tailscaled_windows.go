// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.19
// +build go1.19

package main // import "tailscale.com/cmd/tailscaled"

// TODO: check if administrator, like tswin does.
//
// TODO: try to load wintun.dll early at startup, before wireguard/tun
//       does (which panics) and if we'd fail (e.g. due to access
//       denied, even if administrator), use 'tasklist /m wintun.dll'
//       to see if something else is currently using it and tell user.
//
// TODO: check if Tailscale service is already running, and fail early
//       like tswin does.
//
// TODO: on failure, check if on a UNC drive and recommend copying it
//       to C:\ to run it, like tswin does.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store"
	"tailscale.com/logpolicy"
	"tailscale.com/net/dns"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/safesocket"
	"tailscale.com/types/logger"
	"tailscale.com/util/winutil"
	"tailscale.com/version"
	"tailscale.com/wf"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

const serviceName = "Tailscale"

func isWindowsService() bool {
	v, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("svc.IsWindowsService failed: %v", err)
	}
	return v
}

// syslogf is a logger function that writes to the Windows event log (ie, the
// one that you see in the Windows Event Viewer). tailscaled may optionally
// generate diagnostic messages in the same event timeline as the Windows
// Service Control Manager to assist with diagnosing issues with tailscaled's
// lifetime (such as slow shutdowns).
var syslogf logger.Logf = logger.Discard

// runWindowsService starts running Tailscale under the Windows
// Service environment.
//
// At this point we're still the parent process that
// Windows started.
func runWindowsService(pol *logpolicy.Policy) error {
	if winutil.GetPolicyInteger("LogSCMInteractions", 0) != 0 {
		syslog, err := eventlog.Open(serviceName)
		if err == nil {
			syslogf = func(format string, args ...any) {
				syslog.Info(0, fmt.Sprintf(format, args...))
			}
			defer syslog.Close()
		}
	}

	syslogf("Service entering svc.Run")
	defer syslogf("Service exiting svc.Run")
	return svc.Run(serviceName, &ipnService{Policy: pol})
}

type ipnService struct {
	Policy *logpolicy.Policy
}

// Called by Windows to execute the windows service.
func (service *ipnService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	defer syslogf("SvcStopped notification imminent")

	changes <- svc.Status{State: svc.StartPending}
	syslogf("Service start pending")

	svcAccepts := svc.AcceptStop
	if winutil.GetPolicyInteger("FlushDNSOnSessionUnlock", 0) != 0 {
		svcAccepts |= svc.AcceptSessionChange
	}

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		args := []string{"/subproc", service.Policy.PublicID.String()}
		// Make a logger without a date prefix, as filelogger
		// and logtail both already add their own. All we really want
		// from the log package is the automatic newline.
		// We start with log.Default().Writer(), which is the logtail
		// writer that logpolicy already installed as the global
		// output.
		logger := log.New(log.Default().Writer(), "", 0)
		ipnserver.BabysitProc(ctx, args, logger.Printf)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svcAccepts}
	syslogf("Service running")

	for {
		select {
		case <-doneCh:
			return false, windows.NO_ERROR
		case cmd := <-r:
			log.Printf("Got Windows Service event: %v", cmdName(cmd.Cmd))
			switch cmd.Cmd {
			case svc.Stop:
				changes <- svc.Status{State: svc.StopPending}
				syslogf("Service stop pending")
				cancel() // so BabysitProc will kill the child process
			case svc.Interrogate:
				syslogf("Service interrogation")
				changes <- cmd.CurrentStatus
			case svc.SessionChange:
				syslogf("Service session change notification")
				handleSessionChange(cmd)
				changes <- cmd.CurrentStatus
			}
		}
	}
}

func cmdName(c svc.Cmd) string {
	switch c {
	case svc.Stop:
		return "Stop"
	case svc.Pause:
		return "Pause"
	case svc.Continue:
		return "Continue"
	case svc.Interrogate:
		return "Interrogate"
	case svc.Shutdown:
		return "Shutdown"
	case svc.ParamChange:
		return "ParamChange"
	case svc.NetBindAdd:
		return "NetBindAdd"
	case svc.NetBindRemove:
		return "NetBindRemove"
	case svc.NetBindEnable:
		return "NetBindEnable"
	case svc.NetBindDisable:
		return "NetBindDisable"
	case svc.DeviceEvent:
		return "DeviceEvent"
	case svc.HardwareProfileChange:
		return "HardwareProfileChange"
	case svc.PowerEvent:
		return "PowerEvent"
	case svc.SessionChange:
		return "SessionChange"
	case svc.PreShutdown:
		return "PreShutdown"
	}
	return fmt.Sprintf("Unknown-Service-Cmd-%d", c)
}

func beWindowsSubprocess() bool {
	if beFirewallKillswitch() {
		return true
	}

	if len(os.Args) != 3 || os.Args[1] != "/subproc" {
		return false
	}
	logid := os.Args[2]

	// Remove the date/time prefix; the logtail + file loggers add it.
	log.SetFlags(0)

	log.Printf("Program starting: v%v: %#v", version.Long, os.Args)
	log.Printf("subproc mode: logid=%v", logid)
	if err := envknob.ApplyDiskConfigError(); err != nil {
		log.Printf("Error reading environment config: %v", err)
	}

	go func() {
		b := make([]byte, 16)
		for {
			_, err := os.Stdin.Read(b)
			if err != nil {
				log.Fatalf("stdin err (parent process died): %v", err)
			}
		}
	}()

	err := startIPNServer(context.Background(), logid)
	if err != nil {
		log.Fatalf("ipnserver: %v", err)
	}
	return true
}

func beFirewallKillswitch() bool {
	if len(os.Args) != 3 || os.Args[1] != "/firewall" {
		return false
	}

	log.SetFlags(0)
	log.Printf("killswitch subprocess starting, tailscale GUID is %s", os.Args[2])

	guid, err := windows.GUIDFromString(os.Args[2])
	if err != nil {
		log.Fatalf("invalid GUID %q: %v", os.Args[2], err)
	}

	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil {
		log.Fatalf("no interface with GUID %q: %v", guid, err)
	}

	start := time.Now()
	fw, err := wf.New(uint64(luid))
	if err != nil {
		log.Fatalf("failed to enable firewall: %v", err)
	}
	log.Printf("killswitch enabled, took %s", time.Since(start))

	// Note(maisem): when local lan access toggled, tailscaled needs to
	// inform the firewall to let local routes through. The set of routes
	// is passed in via stdin encoded in json.
	dcd := json.NewDecoder(os.Stdin)
	for {
		var routes []netip.Prefix
		if err := dcd.Decode(&routes); err != nil {
			log.Fatalf("parent process died or requested exit, exiting (%v)", err)
		}
		if err := fw.UpdatePermittedRoutes(routes); err != nil {
			log.Fatalf("failed to update routes (%v)", err)
		}
	}
}

func startIPNServer(ctx context.Context, logid string) error {
	var logf logger.Logf = log.Printf

	linkMon, err := monitor.New(logf)
	if err != nil {
		return fmt.Errorf("monitor: %w", err)
	}
	dialer := new(tsdial.Dialer)

	getEngineRaw := func() (wgengine.Engine, *netstack.Impl, error) {
		dev, devName, err := tstun.New(logf, "Tailscale")
		if err != nil {
			return nil, nil, fmt.Errorf("TUN: %w", err)
		}
		r, err := router.New(logf, dev, nil)
		if err != nil {
			dev.Close()
			return nil, nil, fmt.Errorf("router: %w", err)
		}
		if shouldWrapNetstack() {
			r = netstack.NewSubnetRouterWrapper(r)
		}
		d, err := dns.NewOSConfigurator(logf, devName)
		if err != nil {
			r.Close()
			dev.Close()
			return nil, nil, fmt.Errorf("DNS: %w", err)
		}
		eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
			Tun:         dev,
			Router:      r,
			DNS:         d,
			ListenPort:  41641,
			LinkMonitor: linkMon,
			Dialer:      dialer,
		})
		if err != nil {
			r.Close()
			dev.Close()
			return nil, nil, fmt.Errorf("engine: %w", err)
		}
		ns, err := newNetstack(logf, dialer, eng)
		if err != nil {
			return nil, nil, fmt.Errorf("newNetstack: %w", err)
		}
		ns.ProcessLocalIPs = false
		ns.ProcessSubnets = shouldWrapNetstack()
		if err := ns.Start(); err != nil {
			return nil, nil, fmt.Errorf("failed to start netstack: %w", err)
		}
		return wgengine.NewWatchdog(eng), ns, nil
	}

	type engineOrError struct {
		Engine   wgengine.Engine
		Netstack *netstack.Impl
		Err      error
	}
	engErrc := make(chan engineOrError)
	t0 := time.Now()
	go func() {
		const ms = time.Millisecond
		for try := 1; ; try++ {
			logf("tailscaled: getting engine... (try %v)", try)
			t1 := time.Now()
			eng, ns, err := getEngineRaw()
			d, dt := time.Since(t1).Round(ms), time.Since(t1).Round(ms)
			if err != nil {
				logf("tailscaled: engine fetch error (try %v) in %v (total %v, sysUptime %v): %v",
					try, d, dt, windowsUptime().Round(time.Second), err)
			} else {
				if try > 1 {
					logf("tailscaled: got engine on try %v in %v (total %v)", try, d, dt)
				} else {
					logf("tailscaled: got engine in %v", d)
				}
			}
			timer := time.NewTimer(5 * time.Second)
			engErrc <- engineOrError{eng, ns, err}
			if err == nil {
				timer.Stop()
				return
			}
			<-timer.C
		}
	}()

	// getEngine is called by ipnserver to get the engine. It's
	// not called concurrently and is not called again once it
	// successfully returns an engine.
	getEngine := func() (wgengine.Engine, *netstack.Impl, error) {
		if msg := envknob.String("TS_DEBUG_WIN_FAIL"); msg != "" {
			return nil, nil, fmt.Errorf("pretending to be a service failure: %v", msg)
		}
		for {
			res := <-engErrc
			if res.Engine != nil {
				return res.Engine, res.Netstack, nil
			}
			if time.Since(t0) < time.Minute || windowsUptime() < 10*time.Minute {
				// Ignore errors during early boot. Windows 10 auto logs in the GUI
				// way sooner than the networking stack components start up.
				// So the network will fail for a bit (and require a few tries) while
				// the GUI is still fine.
				continue
			}
			// Return nicer errors to users, annotated with logids, which helps
			// when they file bugs.
			return nil, nil, fmt.Errorf("%w\n\nlogid: %v", res.Err, logid)
		}
	}
	store, err := store.New(logf, statePathOrDefault())
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}

	ln, _, err := safesocket.Listen(args.socketpath, safesocket.WindowsLocalPort)
	if err != nil {
		return fmt.Errorf("safesocket.Listen: %v", err)
	}

	err = ipnserver.Run(ctx, logf, ln, store, linkMon, dialer, logid, getEngine, ipnServerOpts())
	if err != nil {
		logf("ipnserver.Run: %v", err)
	}
	return err
}

func handleSessionChange(chgRequest svc.ChangeRequest) {
	if chgRequest.Cmd != svc.SessionChange || chgRequest.EventType != windows.WTS_SESSION_UNLOCK {
		return
	}

	log.Printf("Received WTS_SESSION_UNLOCK event, initiating DNS flush.")
	go func() {
		err := dns.Flush()
		if err != nil {
			log.Printf("Error flushing DNS on session unlock: %v", err)
		}
	}()
}

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64Proc = kernel32.NewProc("GetTickCount64")
)

func windowsUptime() time.Duration {
	r, _, _ := getTickCount64Proc.Call()
	return time.Duration(int64(r)) * time.Millisecond
}
