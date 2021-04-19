// +build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

type wfpObjectInstaller func() error

func createWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("WireGuard", "WireGuard dynamic session")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func registerBaseObjects(session uintptr) (providerID, sublayerID windows.GUID, err error) {
	providerID, err = windows.GenerateGUID()
	if err != nil {
		return windows.GUID{}, windows.GUID{}, wrapErr(err)
	}
	sublayerID, err = windows.GenerateGUID()
	if err != nil {
		return windows.GUID{}, windows.GUID{}, wrapErr(err)
	}

	//
	// Register provider.
	//
	{
		displayData, err := createWtFwpmDisplayData0("WireGuard", "WireGuard provider")
		if err != nil {
			return windows.GUID{}, windows.GUID{}, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: providerID,
			displayData: *displayData,
		}
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			// TODO: cleanup entire call chain of these if failure?
			return windows.GUID{}, windows.GUID{}, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("WireGuard filters", "Permissive and blocking filters")
		if err != nil {
			return windows.GUID{}, windows.GUID{}, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: sublayerID,
			providerKey: &providerID,
			displayData: *displayData,
			weight:      ^uint16(0),
		}
		err = fwpmSubLayerAdd0(session, &sublayer, 0)
		if err != nil {
			return windows.GUID{}, windows.GUID{}, wrapErr(err)
		}
	}

	return providerID, sublayerID, nil
}

type Firewall struct {
	luid       uint64
	session    uintptr
	providerID windows.GUID
	sublayerID windows.GUID

	routes map[netaddr.IPPrefix][]uint64
}

var (
	firewall *Firewall
)

func New(luid uint64) (*Firewall, error) {
	if firewall != nil {
		if firewall.luid == luid {
			return firewall, nil
		}
		return nil, errors.New("The firewall has already been enabled")
	}

	session, err := createWfpSession()
	if err != nil {
		return nil, wrapErr(err)
	}

	providerID, sublayerID, err := registerBaseObjects(session)
	if err != nil {
		return nil, wrapErr(err)
	}

	firewall = &Firewall{
		luid:       luid,
		session:    session,
		providerID: providerID,
		sublayerID: sublayerID,
		routes:     make(map[netaddr.IPPrefix][]uint64),
	}

	if err := runTransaction(session, func() error {
		return firewall.Enable()
	}); err != nil {
		fwpmEngineClose0(session)
		return nil, wrapErr(err)
	}
	return firewall, nil
}

func (f *Firewall) Disable() error {
	if f.session != 0 {
		if err := fwpmEngineClose0(f.session); err != nil {
			return err
		}
		f.session = 0
	}
	return nil
}

func (f *Firewall) Enable() error {
	if err := f.permitWireGuardService(15); err != nil {
		return wrapErr(err)
	}

	if err := f.allowDNS(); err != nil {
		return wrapErr(err)
	}

	if err := f.permitLoopback(13); err != nil {
		return wrapErr(err)
	}

	if err := f.permitTunInterface(12); err != nil {
		return wrapErr(err)
	}

	if err := f.permitDHCPIPv4(12); err != nil {
		return wrapErr(err)
	}

	if err := f.permitDHCPIPv6(12); err != nil {
		return wrapErr(err)
	}

	if err := f.permitNdp(12); err != nil {
		return wrapErr(err)
	}

	/* TODO: actually evaluate if this does anything and if we need this. It's layer 2; our other rules are layer 3.
	 *  In other words, if somebody complains, try enabling it. For now, keep it off.
	if err := f.permitHyperV(12); err != nil {
		return wrapErr(err)
	}
	*/
	if err := f.blockAll(0); err != nil {
		return wrapErr(err)
	}
	return nil
}

func (f *Firewall) PermitRoutes(routes []netaddr.IPPrefix) error {
	return f.permitRoutes(12, routes)
}
