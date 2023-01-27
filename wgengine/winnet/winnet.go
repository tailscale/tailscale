// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package winnet

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

const CLSID_NetworkListManager = "{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"

var IID_INetwork = ole.NewGUID("{8A40A45D-055C-4B62-ABD7-6D613E2CEAEC}")
var IID_INetworkConnection = ole.NewGUID("{DCB00005-570F-4A9B-8D69-199FDBA5723B}")

type NetworkListManager struct {
	d *ole.Dispatch
}

type INetworkConnection struct {
	ole.IDispatch
}

type ConnectionList []*INetworkConnection

type INetworkConnectionVtbl struct {
	ole.IDispatchVtbl
	GetNetwork                uintptr
	Get_IsConnectedToInternet uintptr
	Get_IsConnected           uintptr
	GetConnectivity           uintptr
	GetConnectionId           uintptr
	GetAdapterId              uintptr
	GetDomainType             uintptr
}

type INetwork struct {
	ole.IDispatch
}

type INetworkVtbl struct {
	ole.IDispatchVtbl
	GetName                    uintptr
	SetName                    uintptr
	GetDescription             uintptr
	SetDescription             uintptr
	GetNetworkId               uintptr
	GetDomainType              uintptr
	GetNetworkConnections      uintptr
	GetTimeCreatedAndConnected uintptr
	Get_IsConnectedToInternet  uintptr
	Get_IsConnected            uintptr
	GetConnectivity            uintptr
	GetCategory                uintptr
	SetCategory                uintptr
}

func NewNetworkListManager(c *ole.Connection) (*NetworkListManager, error) {
	err := c.Create(CLSID_NetworkListManager)
	if err != nil {
		return nil, err
	}
	defer c.Release()

	d, err := c.Dispatch()
	if err != nil {
		return nil, err
	}

	return &NetworkListManager{
		d: d,
	}, nil
}

func (m *NetworkListManager) Release() {
	m.d.Release()
}

func (cl ConnectionList) Release() {
	for _, v := range cl {
		v.Release()
	}
}

func asIID(u ole.UnknownLike, iid *ole.GUID) (*ole.IDispatch, error) {
	if u == nil {
		return nil, fmt.Errorf("asIID: nil UnknownLike")
	}

	d, err := u.QueryInterface(iid)
	u.Release()
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (m *NetworkListManager) GetNetworkConnections() (ConnectionList, error) {
	ncraw, err := m.d.Call("GetNetworkConnections")
	if err != nil {
		return nil, err
	}

	nli := ncraw.ToIDispatch()
	if nli == nil {
		return nil, fmt.Errorf("GetNetworkConnections: not IDispatch")
	}

	cl := ConnectionList{}

	err = oleutil.ForEach(nli, func(v *ole.VARIANT) error {
		nc, err := asIID(v.ToIUnknown(), IID_INetworkConnection)
		if err != nil {
			return err
		}
		nco := (*INetworkConnection)(unsafe.Pointer(nc))
		cl = append(cl, nco)
		return nil
	})

	if err != nil {
		cl.Release()
		return nil, err
	}
	return cl, nil
}

func (n *INetwork) GetName() (string, error) {
	v, err := n.CallMethod("GetName")
	if err != nil {
		return "", err
	}
	return v.ToString(), err
}

func (n *INetwork) GetCategory() (int32, error) {
	var result int32

	r, _, _ := syscall.SyscallN(
		n.VTable().GetCategory,
		uintptr(unsafe.Pointer(n)),
		uintptr(unsafe.Pointer(&result)),
	)
	if int32(r) < 0 {
		return 0, ole.NewError(r)
	}

	return result, nil
}

func (n *INetwork) SetCategory(v int32) error {
	r, _, _ := syscall.SyscallN(
		n.VTable().SetCategory,
		uintptr(unsafe.Pointer(n)),
		uintptr(v),
	)
	if int32(r) < 0 {
		return ole.NewError(r)
	}

	return nil
}

func (n *INetwork) VTable() *INetworkVtbl {
	return (*INetworkVtbl)(unsafe.Pointer(n.RawVTable))
}

func (v *INetworkConnection) VTable() *INetworkConnectionVtbl {
	return (*INetworkConnectionVtbl)(unsafe.Pointer(v.RawVTable))
}

func (v *INetworkConnection) GetNetwork() (*INetwork, error) {
	var result *INetwork

	r, _, _ := syscall.SyscallN(
		v.VTable().GetNetwork,
		uintptr(unsafe.Pointer(v)),
		uintptr(unsafe.Pointer(&result)),
	)
	if int32(r) < 0 {
		return nil, ole.NewError(r)
	}

	return result, nil
}
