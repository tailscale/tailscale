// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/logpolicy"
	"tailscale.com/net/dns"
	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wf"
	"tailscale.com/wgengine"
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

func runWindowsService(pol *logpolicy.Policy) error {
	return svc.Run(serviceName, &ipnService{Policy: pol})
}

type ipnService struct {
	Policy *logpolicy.Policy
}

// Called by Windows to execute the windows service.
func (service *ipnService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		args := []string{"/subproc", service.Policy.PublicID.String()}
		ipnserver.BabysitProc(ctx, args, log.Printf)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

	for ctx.Err() == nil {
		select {
		case <-doneCh:
		case cmd := <-r:
			switch cmd.Cmd {
			case svc.Stop:
				cancel()
			case svc.Interrogate:
				changes <- cmd.CurrentStatus
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	return false, windows.NO_ERROR
}

func beWindowsSubprocess() bool {
	if beFirewallKillswitch() {
		return true
	}

	if len(os.Args) != 3 || os.Args[1] != "/subproc" {
		return false
	}
	logid := os.Args[2]

	log.Printf("Program starting: v%v: %#v", version.Long, os.Args)
	log.Printf("subproc mode: logid=%v", logid)

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

	go func() {
		b := make([]byte, 16)
		for {
			_, err := os.Stdin.Read(b)
			if err != nil {
				log.Fatalf("parent process died or requested exit, exiting (%v)", err)
			}
		}
	}()

	guid, err := windows.GUIDFromString(os.Args[2])
	if err != nil {
		log.Fatalf("invalid GUID %q: %v", os.Args[2], err)
	}

	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil {
		log.Fatalf("no interface with GUID %q: %v", guid, err)
	}

	start := time.Now()
	if _, err := wf.New(uint64(luid)); err != nil {
		log.Fatalf("filewall creation failed: %v", err)
	}
	log.Printf("killswitch enabled, took %s", time.Since(start))

	// Block until the monitor goroutine shuts us down.
	select {}
}

func startIPNServer(ctx context.Context, logid string) error {
	var logf logger.Logf = log.Printf

	getEngineRaw := func() (wgengine.Engine, error) {
		dev, devName, err := tstun.New(logf, "Tailscale")
		if err != nil {
			return nil, fmt.Errorf("TUN: %w", err)
		}
		r, err := router.New(logf, dev)
		if err != nil {
			dev.Close()
			return nil, fmt.Errorf("router: %w", err)
		}
		if wrapNetstack {
			r = netstack.NewSubnetRouterWrapper(r)
		}
		d, err := dns.NewOSConfigurator(logf, devName)
		if err != nil {
			r.Close()
			dev.Close()
			return nil, fmt.Errorf("DNS: %w", err)
		}
		eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
			Tun:        dev,
			Router:     r,
			DNS:        d,
			ListenPort: 41641,
		})
		if err != nil {
			r.Close()
			dev.Close()
			return nil, fmt.Errorf("engine: %w", err)
		}
		onlySubnets := true
		if wrapNetstack {
			mustStartNetstack(logf, eng, onlySubnets)
		}
		return wgengine.NewWatchdog(eng), nil
	}

	type engineOrError struct {
		Engine wgengine.Engine
		Err    error
	}
	engErrc := make(chan engineOrError)
	t0 := time.Now()
	go func() {
		const ms = time.Millisecond
		for try := 1; ; try++ {
			logf("tailscaled: getting engine... (try %v)", try)
			t1 := time.Now()
			eng, err := getEngineRaw()
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
			engErrc <- engineOrError{eng, err}
			if err == nil {
				timer.Stop()
				return
			}
			<-timer.C
		}
	}()

	opts := ipnserver.Options{
		Port:               41112,
		SurviveDisconnects: false,
		StatePath:          args.statepath,
	}

	// getEngine is called by ipnserver to get the engine. It's
	// not called concurrently and is not called again once it
	// successfully returns an engine.
	getEngine := func() (wgengine.Engine, error) {
		if msg := os.Getenv("TS_DEBUG_WIN_FAIL"); msg != "" {
			return nil, fmt.Errorf("pretending to be a service failure: %v", msg)
		}
		for {
			res := <-engErrc
			if res.Engine != nil {
				return res.Engine, nil
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
			return nil, fmt.Errorf("%w\n\nlogid: %v", res.Err, logid)
		}
	}
	err := ipnserver.Run(ctx, logf, logid, getEngine, opts)
	if err != nil {
		logf("ipnserver.Run: %v", err)
	}
	return err
}

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64Proc = kernel32.NewProc("GetTickCount64")
)

func windowsUptime() time.Duration {
	r, _, _ := getTickCount64Proc.Call()
	return time.Duration(int64(r)) * time.Millisecond
}
