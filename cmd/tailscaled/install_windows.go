// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"tailscale.com/cmd/tailscaled/tailscaledhooks"
	"tailscale.com/logtail/backoff"
	"tailscale.com/types/logger"
)

func init() {
	installSystemDaemon = installSystemDaemonWindows
	uninstallSystemDaemon = uninstallSystemDaemonWindows
}

// serviceDependencies lists all system services that tailscaled depends on.
// This list must be kept in sync with the TailscaledDependencies preprocessor
// variable in the installer.
var serviceDependencies = []string{
	"Dnscache",
	"iphlpsvc",
	"netprofm",
	"WinHttpAutoProxySvc",
}

func installSystemDaemonWindows(args []string) (err error) {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows service manager: %v", err)
	}

	service, err := m.OpenService(serviceName)
	if err == nil {
		service.Close()
		return fmt.Errorf("service %q is already installed", serviceName)
	}

	// no such service; proceed to install the service.

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	c := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: serviceDependencies,
		DisplayName:  serviceName,
		Description:  "Connects this computer to others on the Tailscale network.",
	}

	service, err = m.CreateService(serviceName, exe, c)
	if err != nil {
		return fmt.Errorf("failed to create %q service: %v", serviceName, err)
	}
	defer service.Close()

	// Exponential backoff is often too aggressive, so use (mostly)
	// squares instead.
	ra := []mgr.RecoveryAction{
		{mgr.ServiceRestart, 1 * time.Second},
		{mgr.ServiceRestart, 2 * time.Second},
		{mgr.ServiceRestart, 4 * time.Second},
		{mgr.ServiceRestart, 9 * time.Second},
		{mgr.ServiceRestart, 16 * time.Second},
		{mgr.ServiceRestart, 25 * time.Second},
		{mgr.ServiceRestart, 36 * time.Second},
		{mgr.ServiceRestart, 49 * time.Second},
		{mgr.ServiceRestart, 64 * time.Second},
	}
	const resetPeriodSecs = 60
	err = service.SetRecoveryActions(ra, resetPeriodSecs)
	if err != nil {
		return fmt.Errorf("failed to set service recovery actions: %v", err)
	}

	return nil
}

func uninstallSystemDaemonWindows(args []string) (ret error) {
	for _, f := range tailscaledhooks.UninstallSystemDaemonWindows {
		f()
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows service manager: %v", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("failed to open %q service: %v", serviceName, err)
	}

	st, err := service.Query()
	if err != nil {
		service.Close()
		return fmt.Errorf("failed to query service state: %v", err)
	}
	if st.State != svc.Stopped {
		service.Control(svc.Stop)
	}
	err = service.Delete()
	service.Close()
	if err != nil {
		return fmt.Errorf("failed to delete service: %v", err)
	}

	bo := backoff.NewBackoff("uninstall", logger.Discard, 30*time.Second)
	end := time.Now().Add(15 * time.Second)
	for time.Until(end) > 0 {
		service, err = m.OpenService(serviceName)
		if err != nil {
			// service is no longer openable; success!
			break
		}
		service.Close()
		bo.BackOff(context.Background(), errors.New("service not deleted"))
	}
	return nil
}
