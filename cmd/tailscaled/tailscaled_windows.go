// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/dblohm7/wingoes/com"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/drive/driveimpl"
	"tailscale.com/envknob"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tstun"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/osdiag"
	"tailscale.com/util/syspolicy"
	"tailscale.com/util/winutil"
	"tailscale.com/version"
	"tailscale.com/wf"
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

// Application-defined command codes between 128 and 255
// See https://web.archive.org/web/20221007222822/https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice
const (
	cmdUninstallWinTun = svc.Cmd(128 + iota)
)

func init() {
	tstunNew = tstunNewWithWindowsRetries
}

// tstunNewOrRetry is a wrapper around tstun.New that retries on Windows for certain
// errors.
//
// TODO(bradfitz): move this into tstun and/or just fix the problems so it doesn't
// require a few tries to work.
func tstunNewWithWindowsRetries(logf logger.Logf, tunName string) (_ tun.Device, devName string, _ error) {
	bo := backoff.NewBackoff("tstunNew", logf, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for {
		dev, devName, err := tstun.New(logf, tunName)
		if err == nil {
			return dev, devName, err
		}
		if errors.Is(err, windows.ERROR_DEVICE_NOT_AVAILABLE) || windowsUptime() < 10*time.Minute {
			// Wintun is not installing correctly. Dump the state of NetSetupSvc
			// (which is a user-mode service that must be active for network devices
			// to install) and its dependencies to the log.
			winutil.LogSvcState(logf, "NetSetupSvc")
		}
		bo.BackOff(ctx, err)
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
	}
}

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
	go func() {
		logger.Logf(log.Printf).JSON(1, "SupportInfo", osdiag.SupportInfo(osdiag.LogSupportInfoReasonStartup))
	}()

	if syslog, err := eventlog.Open(serviceName); err == nil {
		syslogf = func(format string, args ...any) {
			if logSCMInteractions, _ := syspolicy.GetBoolean(syspolicy.LogSCMInteractions, false); logSCMInteractions {
				syslog.Info(0, fmt.Sprintf(format, args...))
			}
		}
		defer syslog.Close()
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

	svcAccepts := svc.AcceptStop | svc.AcceptSessionChange

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
			case cmdUninstallWinTun:
				syslogf("Stopping tailscaled child process and uninstalling WinTun")
				// At this point, doneCh is the channel which will be closed when the
				// tailscaled subprocess exits. We save that to childDoneCh.
				childDoneCh := doneCh
				// We reset doneCh to a new channel that will keep the event loop
				// running until the uninstallation is done.
				doneCh = make(chan struct{})
				// Trigger subprocess shutdown.
				cancel()
				go func() {
					// When this goroutine completes, tell the service to break out of its
					// event loop.
					defer close(doneCh)
					// Wait for the subprocess to shutdown.
					<-childDoneCh
					// Now uninstall WinTun.
					uninstallWinTun(log.Printf)
				}()
				changes <- svc.Status{State: svc.StopPending}
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
	case cmdUninstallWinTun:
		return "(Application Defined) Uninstall WinTun"
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
	logID := os.Args[2]

	// Remove the date/time prefix; the logtail + file loggers add it.
	log.SetFlags(0)

	log.Printf("Program starting: v%v: %#v", version.Long(), os.Args)
	log.Printf("subproc mode: logid=%v", logID)
	if err := envknob.ApplyDiskConfigError(); err != nil {
		log.Printf("Error reading environment config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		b := make([]byte, 16)
		for {
			_, err := os.Stdin.Read(b)
			if err == io.EOF {
				// Parent wants us to shut down gracefully.
				log.Printf("subproc received EOF from stdin")
				cancel()
				return
			}
			if err != nil {
				log.Fatalf("stdin err (parent process died): %v", err)
			}
		}
	}()

	// Pre-load wintun.dll using a fully-qualified path so that wintun-go
	// loads our copy and not some (possibly outdated) copy dropped in system32.
	// (OSS Issue #10023)
	fqWintunPath := fullyQualifiedWintunPath(log.Printf)
	if _, err := windows.LoadDLL(fqWintunPath); err != nil {
		log.Printf("Error pre-loading \"%s\": %v", fqWintunPath, err)
	}

	sys := new(tsd.System)
	netMon, err := netmon.New(log.Printf)
	if err != nil {
		log.Fatalf("Could not create netMon: %v", err)
	}
	sys.Set(netMon)

	sys.Set(driveimpl.NewFileSystemForRemote(log.Printf))

	publicLogID, _ := logid.ParsePublicID(logID)
	err = startIPNServer(ctx, log.Printf, publicLogID, sys)
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

func handleSessionChange(chgRequest svc.ChangeRequest) {
	if chgRequest.Cmd != svc.SessionChange || chgRequest.EventType != windows.WTS_SESSION_UNLOCK {
		return
	}

	if flushDNSOnSessionUnlock, _ := syspolicy.GetBoolean(syspolicy.FlushDNSOnSessionUnlock, false); flushDNSOnSessionUnlock {
		log.Printf("Received WTS_SESSION_UNLOCK event, initiating DNS flush.")
		go func() {
			err := dns.Flush()
			if err != nil {
				log.Printf("Error flushing DNS on session unlock: %v", err)
			}
		}()
	}
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
		mu     sync.Mutex
		p      *os.Process
		wStdin *os.File
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
			proc.mu.Lock()
			proc.p.Signal(sig)
			proc.mu.Unlock()
		case <-ctx.Done():
			logf("babysitProc: context done")
			close(done)
			proc.mu.Lock()
			// Closing wStdin gives the subprocess a chance to shut down cleanly,
			// which is important for cleaning up DNS settings etc.
			proc.wStdin.Close()
			proc.mu.Unlock()
		}
	}()

	bo := backoff.NewBackoff("babysitProc", logf, 30*time.Second)

	for {
		startTime := time.Now()
		log.Printf("exec: %#v %v", executable, args)
		cmd := exec.Command(executable, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: windows.DETACHED_PROCESS,
		}

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
			proc.wStdin = wStdin
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

func uninstallWinTun(logf logger.Logf) {
	dll := windows.NewLazyDLL(fullyQualifiedWintunPath(logf))
	if err := dll.Load(); err != nil {
		logf("Cannot load wintun.dll for uninstall: %v", err)
		return
	}

	logf("Removing wintun driver...")
	err := wintun.Uninstall()
	logf("Uninstall: %v", err)
}

func fullyQualifiedWintunPath(logf logger.Logf) string {
	var dir string
	imgName, err := winutil.ProcessImageName(windows.CurrentProcess())
	if err != nil {
		logf("ProcessImageName failed: %v", err)
	} else {
		dir = filepath.Dir(imgName)
	}

	return filepath.Join(dir, "wintun.dll")
}
