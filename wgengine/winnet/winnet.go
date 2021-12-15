// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

package winnet

import (
	"fmt"
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
	v, err := n.CallMethod("GetCategory")
	if err != nil {
		return 0, err
	}
	return v.Value().(int32), err
}

func (n *INetwork) SetCategory(v uint32) error {
	_, err := n.CallMethod("SetCategory", v)
	return err
}

func (v *INetworkConnection) VTable() *INetworkConnectionVtbl {
	return (*INetworkConnectionVtbl)(unsafe.Pointer(v.RawVTable))
}

func (v *INetworkConnection) GetNetwork() (*INetwork, error) {
	nraw, err := v.CallMethod("GetNetwork")
	if err != nil {
		return nil, err
	}

	n := nraw.ToIDispatch()
	if n == nil {
		return nil, fmt.Errorf("GetNetwork: nil IDispatch")
	}
	if err != nil {
		return nil, err
	}
	return (*INetwork)(unsafe.Pointer(n)), nil
}
