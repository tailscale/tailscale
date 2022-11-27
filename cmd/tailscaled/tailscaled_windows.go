// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.19

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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/dblohm7/wingoes/com"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/dns"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/safesocket"
	"tailscale.com/smallzstd"
	"tailscale.com/types/logger"
	"tailscale.com/util/winutil"
	"tailscale.com/version"
	"tailscale.com/wf"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

func init() {
	// Initialize COM process-wide.
	comProcessType := com.Service
	if !isWindowsService() {
		comProcessType = com.ConsoleApp
	}
	if err := com.StartRuntime(comProcessType); err != nil {
		log.Printf("wingoes.com.StartRuntime(%d) failed: %v", comProcessType, err)
	}
}

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
		babysitProc(ctx, args, logger.Printf)
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
	dialer := &tsdial.Dialer{Logf: logf}

	getEngineRaw := func() (wgengine.Engine, *netstack.Impl, error) {
		dev, devName, err := tstun.New(logf, "Tailscale")
		if err != nil {
			if errors.Is(err, windows.ERROR_DEVICE_NOT_AVAILABLE) {
				// Wintun is not installing correctly. Dump the state of NetSetupSvc
				// (which is a user-mode service that must be active for network devices
				// to install) and its dependencies to the log.
				winutil.LogSvcState(logf, "NetSetupSvc")
			}
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

	err = ipnServerRunWithRetries(ctx, logf, ln, store, linkMon, dialer, logid, getEngine, ipnServerOpts())
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

// babysitProc runs the current executable as a child process with the
// provided args, capturing its output, writing it to files, and
// restarting the process on any crashes.
func babysitProc(ctx context.Context, args []string, logf logger.Logf) {

	executable, err := os.Executable()
	if err != nil {
		panic("cannot determine executable: " + err.Error())
	}

	var proc struct {
		mu sync.Mutex
		p  *os.Process
	}

	done := make(chan struct{})
	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		var sig os.Signal
		select {
		case sig = <-interrupt:
			logf("babysitProc: got signal: %v", sig)
			close(done)
		case <-ctx.Done():
			logf("babysitProc: context done")
			sig = os.Kill
			close(done)
		}

		proc.mu.Lock()
		proc.p.Signal(sig)
		proc.mu.Unlock()
	}()

	bo := backoff.NewBackoff("babysitProc", logf, 30*time.Second)

	for {
		startTime := time.Now()
		log.Printf("exec: %#v %v", executable, args)
		cmd := exec.Command(executable, args...)

		// Create a pipe object to use as the subproc's stdin.
		// When the writer goes away, the reader gets EOF.
		// A subproc can watch its stdin and exit when it gets EOF;
		// this is a very reliable way to have a subproc die when
		// its parent (us) disappears.
		// We never need to actually write to wStdin.
		rStdin, wStdin, err := os.Pipe()
		if err != nil {
			log.Printf("os.Pipe 1: %v", err)
			return
		}

		// Create a pipe object to use as the subproc's stdout/stderr.
		// We'll read from this pipe and send it to logf, line by line.
		// We can't use os.exec's io.Writer for this because it
		// doesn't care about lines, and thus ends up merging multiple
		// log lines into one or splitting one line into multiple
		// logf() calls. bufio is more appropriate.
		rStdout, wStdout, err := os.Pipe()
		if err != nil {
			log.Printf("os.Pipe 2: %v", err)
		}
		go func(r *os.File) {
			defer r.Close()
			rb := bufio.NewReader(r)
			for {
				s, err := rb.ReadString('\n')
				if s != "" {
					logf("%s", s)
				}
				if err != nil {
					break
				}
			}
		}(rStdout)

		cmd.Stdin = rStdin
		cmd.Stdout = wStdout
		cmd.Stderr = wStdout
		err = cmd.Start()

		// Now that the subproc is started, get rid of our copy of the
		// pipe reader. Bad things happen on Windows if more than one
		// process owns the read side of a pipe.
		rStdin.Close()
		wStdout.Close()

		if err != nil {
			log.Printf("starting subprocess failed: %v", err)
		} else {
			proc.mu.Lock()
			proc.p = cmd.Process
			proc.mu.Unlock()

			err = cmd.Wait()
			log.Printf("subprocess exited: %v", err)
		}

		// If the process finishes, clean up the write side of the
		// pipe. We'll make a new one when we restart the subproc.
		wStdin.Close()

		if os.Getenv("TS_DEBUG_RESTART_CRASHED") == "0" {
			log.Fatalf("Process ended.")
		}

		if time.Since(startTime) < 60*time.Second {
			bo.BackOff(ctx, fmt.Errorf("subproc early exit: %v", err))
		} else {
			// Reset the timeout, since the process ran for a while.
			bo.BackOff(ctx, nil)
		}

		select {
		case <-done:
			return
		default:
		}
	}
}

// getEngineUntilItWorksWrapper returns a getEngine wrapper that does
// not call getEngine concurrently and stops calling getEngine once
// it's returned a working engine.
func getEngineUntilItWorksWrapper(getEngine func() (wgengine.Engine, *netstack.Impl, error)) func() (wgengine.Engine, *netstack.Impl, error) {
	var mu sync.Mutex
	var engGood wgengine.Engine
	var nsGood *netstack.Impl
	return func() (wgengine.Engine, *netstack.Impl, error) {
		mu.Lock()
		defer mu.Unlock()
		if engGood != nil {
			return engGood, nsGood, nil
		}
		e, ns, err := getEngine()
		if err != nil {
			return nil, nil, err
		}
		engGood = e
		nsGood = ns
		return e, ns, nil
	}
}

// listenerWithReadyConn is a net.Listener wrapper that has
// one net.Conn ready to be accepted already.
type listenerWithReadyConn struct {
	net.Listener

	mu sync.Mutex
	c  net.Conn // if non-nil, ready to be Accepted
}

func (ln *listenerWithReadyConn) Accept() (net.Conn, error) {
	ln.mu.Lock()
	c := ln.c
	ln.c = nil
	ln.mu.Unlock()
	if c != nil {
		return c, nil
	}
	return ln.Listener.Accept()
}

// ipnServerRunWithRetries runs a Tailscale backend service.
//
// The getEngine func is called repeatedly, once per connection, until it
// returns an engine successfully.
//
// This works around issues on Windows with the wgengine.Engine/wintun creation
// failing or hanging. See https://github.com/tailscale/tailscale/issues/6522.
func ipnServerRunWithRetries(ctx context.Context, logf logger.Logf, ln net.Listener, store ipn.StateStore, linkMon *monitor.Mon, dialer *tsdial.Dialer, logid string, getEngine func() (wgengine.Engine, *netstack.Impl, error), opts serverOptions) error {
	getEngine = getEngineUntilItWorksWrapper(getEngine)
	runDone := make(chan struct{})
	defer close(runDone)

	// When the context is closed or when we return, whichever is first, close our listener
	// and all open connections.
	go func() {
		select {
		case <-ctx.Done():
		case <-runDone:
		}
		ln.Close()
	}()
	logf("Listening on %v", ln.Addr())

	bo := backoff.NewBackoff("ipnserver", logf, 30*time.Second)
	var unservedConn net.Conn // if non-nil, accepted, but hasn't served yet

	eng, ns, err := getEngine()
	if err != nil {
		logf("ipnserver: initial getEngine call: %v", err)
		for i := 1; ctx.Err() == nil; i++ {
			c, err := ln.Accept()
			if err != nil {
				logf("%d: Accept: %v", i, err)
				bo.BackOff(ctx, err)
				continue
			}
			logf("ipnserver: try%d: trying getEngine again...", i)
			eng, ns, err = getEngine()
			if err == nil {
				logf("%d: GetEngine worked; exiting failure loop", i)
				unservedConn = c
				break
			}
			logf("ipnserver%d: getEngine failed again: %v", i, err)
			// TODO(bradfitz): queue this error up for the next IPN bus watcher call
			// to get for the Windows GUI? We used to send it over the pre-HTTP
			// protocol to the Windows GUI. Just close it.
			c.Close()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if unservedConn != nil {
		ln = &listenerWithReadyConn{
			Listener: ln,
			c:        unservedConn,
		}
	}

	server := ipnserver.New(logf, logid)

	lb, err := ipnlocal.NewLocalBackend(logf, logid, store, "", dialer, eng, opts.LoginFlags)
	if err != nil {
		return fmt.Errorf("ipnlocal.NewLocalBackend: %w", err)
	}
	lb.SetVarRoot(opts.VarRoot)
	if root := lb.TailscaleVarRoot(); root != "" {
		dnsfallback.SetCachePath(filepath.Join(root, "derpmap.cached.json"))
	}
	lb.SetDecompressor(func() (controlclient.Decompressor, error) {
		return smallzstd.NewDecoder(nil)
	})

	server.SetLocalBackend(lb)
	if ns != nil {
		ns.SetLocalBackend(lb)
	}
	return server.Run(ctx, ln)
}
