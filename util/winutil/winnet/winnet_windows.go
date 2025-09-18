// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package winnet contains Windows-specific networking code.
package winnet

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

type NLM_CONNECTIVITY int32

const (
	NLM_CONNECTIVITY_DISCONNECTED NLM_CONNECTIVITY = 0
	NLM_CONNECTIVITY_IPV4_NOTRAFFIC NLM_CONNECTIVITY = 0x1
	NLM_CONNECTIVITY_IPV6_NOTRAFFIC NLM_CONNECTIVITY = 0x2
	NLM_CONNECTIVITY_IPV4_SUBNET NLM_CONNECTIVITY = 0x10
	NLM_CONNECTIVITY_IPV4_LOCALNETWORK NLM_CONNECTIVITY = 0x20
	NLM_CONNECTIVITY_IPV4_INTERNET NLM_CONNECTIVITY = 0x40
	NLM_CONNECTIVITY_IPV6_SUBNET NLM_CONNECTIVITY = 0x100
	NLM_CONNECTIVITY_IPV6_LOCALNETWORK NLM_CONNECTIVITY = 0x200
	NLM_CONNECTIVITY_IPV6_INTERNET NLM_CONNECTIVITY = 0x400
)

var CLSID_NetworkListManager = ole.NewGUID("{DCB00C01-570F-4A9B-8D69-199FDBA5723B}")

var IID_INetworkListManager = ole.NewGUID("{DCB00000-570F-4A9B-8D69-199FDBA5723B}")
var IID_INetwork = ole.NewGUID("{8A40A45D-055C-4B62-ABD7-6D613E2CEAEC}")
var IID_INetworkConnection = ole.NewGUID("{DCB00005-570F-4A9B-8D69-199FDBA5723B}")

type NetworkListManager struct {
	i *INetworkListManager
}

func (m *NetworkListManager) GetNetwork(networkID windows.GUID) (*INetwork, error) {
	return m.i.GetNetwork(networkID)
}

type INetworkListManager struct {
	ole.IUnknown
}

func (i *INetworkListManager) VTable() *INetworkListManagerVtbl {
	return (*INetworkListManagerVtbl)(unsafe.Pointer(i.RawVTable))
}

type INetworkListManagerVtbl struct {
	ole.IDispatchVtbl
	GetNetworks uintptr
	GetNetwork uintptr
	GetNetworkConnections uintptr
	GetNetworkConnection uintptr
	Get_IsConnectedToInternet uintptr
	Get_IsConnected uintptr
	GetConnectivity uintptr
	SetSimulatedProfileInfo uintptr
	ClearSimulatedProfileInfo uintptr
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

func newNetworkListManager() (*NetworkListManager, error) {
	unk, err := ole.CreateInstance(CLSID_NetworkListManager, IID_INetworkListManager)
	if err != nil {
		return nil, err
	}

	nlm := (*INetworkListManager)(unsafe.Pointer(unk))
	return &NetworkListManager{
		i: nlm,
	}, nil
}

var (
	once sync.Once
	nlm *NetworkListManager
	nlmErr error
)

func GetNetworkListManager() (*NetworkListManager, error) {
	once.Do(func() {
		nlm, nlmErr = newNetworkListManager()
	})
	return nlm, nlmErr
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
	d := ole.Dispatch{
		Object: (*ole.IDispatch)(unsafe.Pointer(m.i)),
	}
	ncraw, err := d.Call("GetNetworkConnections")
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

func (n *INetwork) GetConnectivity() (c NLM_CONNECTIVITY, _ error) {
	r, _, _ := syscall.SyscallN(
		n.VTable().GetConnectivity,
		uintptr(unsafe.Pointer(n)),
		uintptr(unsafe.Pointer(&c)),
	)

	if int32(r) < 0 {
		return 0, ole.NewError(r)
	}

	return c, nil
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

func (v *INetworkConnection) GetAdapterId() (string, error) {
	buf := ole.GUID{}
	hr, _, _ := syscall.Syscall(
		v.VTable().GetAdapterId,
		2,
		uintptr(unsafe.Pointer(v)),
		uintptr(unsafe.Pointer(&buf)),
		0)
	if hr != 0 {
		return "", fmt.Errorf("GetAdapterId failed: %08x", hr)
	}
	return buf.String(), nil
}
