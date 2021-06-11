// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package portmapper

import (
	"context"
	"sync"

	"github.com/huin/goupnp/dcps/internetgateway2"
	"golang.org/x/sync/errgroup"
)

// probeUPnP returns true if there are any upnp clients, or false with an error if none can be
// found.
func probeUPnP(ctx context.Context) (bool, error) {
	wg := sync.WaitGroup{}
	any := make(chan bool)
	errChan := make(chan error)
	wg.Add(3)
	go func() {
		ip1Clients, _, err := internetgateway2.NewWANIPConnection1Clients()
		if len(ip1Clients) > 0 {
			any <- true
		}
		wg.Done()
		wg.Wait()
		errChan <- err
	}()
	go func() {
		ip2Clients, _, err := internetgateway2.NewWANIPConnection2Clients()
		if len(ip2Clients) > 0 {
			any <- true
		}
		wg.Done()
		wg.Wait()
		errChan <- err
	}()
	go func() {
		ppp1Clients, _, err := internetgateway2.NewWANPPPConnection1Clients()
		if len(ppp1Clients) > 0 {
			any <- true
		}
		wg.Done()
		wg.Wait()
		errChan <- err
	}()

	select {
	case <-any:
		return true, nil
	case err := <-errChan:
		// TODO probably want to take the non-nil of all the errors? Or something.
		return false, err
	case <-ctx.Done():
		return false, nil
	}
}

type upnpClient interface {
	// http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf
	// Implicitly assume that the calls for all these are uniform, which might be a dangerous
	// assumption.
	AddPortMapping(
		NewRemoteHost string,
		NewExternalPort uint16,
		NewProtocol string,
		NewInternalPort uint16,
		NewInternalClient string,
		NewEnabled bool,
		NewPortMappingDescription string,
		NewLeaseDuration uint32,
	) (err error)

	DeletePortMapping(NewRemoteHost string, NewExternalPort uint16, NewProtocol string) error
	GetStatusInfo() (status string, lastErr string, uptime uint32, err error)

	RequestTermination() error
	RequestConnection() error
}

// getUPnPClients gets a client for interfacing with UPnP, ignoring the underlying protocol for
// now.
// Adapted from https://github.com/huin/goupnp/blob/master/GUIDE.md.
func getUPnPClient(ctx context.Context) (upnpClient, error) {
	tasks, _ := errgroup.WithContext(ctx)
	var ip1Clients []*internetgateway2.WANIPConnection1
	tasks.Go(func() error {
		var err error
		ip1Clients, _, err = internetgateway2.NewWANIPConnection1Clients()
		return err
	})
	var ip2Clients []*internetgateway2.WANIPConnection2
	tasks.Go(func() error {
		var err error
		ip2Clients, _, err = internetgateway2.NewWANIPConnection2Clients()
		return err
	})
	var ppp1Clients []*internetgateway2.WANPPPConnection1
	tasks.Go(func() error {
		var err error
		ppp1Clients, _, err = internetgateway2.NewWANPPPConnection1Clients()
		return err
	})

	err := tasks.Wait()

	switch {
	case len(ip2Clients) > 0:
		return ip2Clients[0], nil
	case len(ip1Clients) > 0:
		return ip1Clients[0], nil
	case len(ppp1Clients) > 0:
		return ppp1Clients[0], nil
	default:
		// Didn't get any outputs, report if there was an error or nil if
		// just no clients.
		return nil, err
	}
}
