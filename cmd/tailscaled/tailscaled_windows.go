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
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/logpolicy"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine"
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

func startIPNServer(ctx context.Context, logid string) error {
	var logf logger.Logf = log.Printf
	var eng wgengine.Engine
	var err error

	getEngine := func() (wgengine.Engine, error) {
		eng, err := wgengine.NewUserspaceEngine(logf, "Tailscale", 41641)
		if err != nil {
			return nil, err
		}
		return wgengine.NewWatchdog(eng), nil
	}

	if msg := os.Getenv("TS_DEBUG_WIN_FAIL"); msg != "" {
		err = fmt.Errorf("pretending to be a service failure: %v", msg)
	} else {
		// We have a bunch of bug reports of wgengine.NewUserspaceEngine returning a few different errors,
		// all intermittently. A few times I (Brad) have also seen sporadic failures that simply
		// restarting fixed. So try a few times.
		for try := 1; try <= 5; try++ {
			if try > 1 {
				// Only sleep a bit. Don't do some massive backoff because
				// the frontend GUI has a 30 second timeout on connecting to us,
				// but even 5 seconds is too long for them to get any results.
				// 5 tries * 1 second each seems fine.
				time.Sleep(time.Second)
			}
			eng, err = getEngine()
			if err != nil {
				logf("wgengine.NewUserspaceEngine: (try %v) %v", try, err)
				continue
			}
			if try > 1 {
				logf("wgengine.NewUserspaceEngine: ended up working on try %v", try)
			}
			break
		}
	}
	if err != nil {
		// Log the error, but don't fatalf. We want to
		// propagate the error message to the UI frontend. So
		// we continue and tell the ipnserver to return that
		// in a Notify message.
		logf("wgengine.NewUserspaceEngine: %v", err)
	}
	opts := ipnserver.Options{
		Port:               41112,
		SurviveDisconnects: false,
		StatePath:          args.statepath,
	}
	if err != nil {
		// Return nicer errors to users, annotated with logids, which helps
		// when they file bugs.
		rawGetEngine := getEngine // raw == without verbose logid-containing error
		getEngine = func() (wgengine.Engine, error) {
			eng, err := rawGetEngine()
			if err != nil {
				return nil, fmt.Errorf("wgengine.NewUserspaceEngine: %v\n\nlogid: %v", err, logid)
			}
			return eng, nil
		}
	} else {
		getEngine = ipnserver.FixedEngine(eng)
	}
	err = ipnserver.Run(ctx, logf, logid, getEngine, opts)
	if err != nil {
		logf("ipnserver.Run: %v", err)
	}
	return err
}
