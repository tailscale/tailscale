// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main // import "tailscale.com/cmd/tailscaled"

import (
	"context"
	"log"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/logpolicy"
)

const serviceName = "Tailscale IPN"

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
