// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

import (
	"encoding/json"
	"errors"

	"tailscale.com/types/opt"
	"tailscale.com/types/views"
)

// View returns a read-only accessor for hi.
func (hi *Hostinfo) View() HostinfoView { return HostinfoView{hi} }

// HostinfoView is a read-only accessor for Hostinfo.
// See Hostinfo.
type HostinfoView struct {
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Hostinfo
}

func (v HostinfoView) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.ж)
}

func (v *HostinfoView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("HostinfoView is already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	hi := &Hostinfo{}
	if err := json.Unmarshal(b, hi); err != nil {
		return err
	}
	v.ж = hi
	return nil
}

// Valid reports whether the underlying value is not nil.
func (v HostinfoView) Valid() bool { return v.ж != nil }

// AsStruct returns a deep-copy of the underlying value.
func (v HostinfoView) AsStruct() *Hostinfo { return v.ж.Clone() }

func (v HostinfoView) IPNVersion() string         { return v.ж.IPNVersion }
func (v HostinfoView) FrontendLogID() string      { return v.ж.FrontendLogID }
func (v HostinfoView) BackendLogID() string       { return v.ж.BackendLogID }
func (v HostinfoView) OS() string                 { return v.ж.OS }
func (v HostinfoView) OSVersion() string          { return v.ж.OSVersion }
func (v HostinfoView) Package() string            { return v.ж.Package }
func (v HostinfoView) DeviceModel() string        { return v.ж.DeviceModel }
func (v HostinfoView) Hostname() string           { return v.ж.Hostname }
func (v HostinfoView) ShieldsUp() bool            { return v.ж.ShieldsUp }
func (v HostinfoView) ShareeNode() bool           { return v.ж.ShareeNode }
func (v HostinfoView) GoArch() string             { return v.ж.GoArch }
func (v HostinfoView) Equal(v2 HostinfoView) bool { return v.ж.Equal(v2.ж) }

func (v HostinfoView) RoutableIPs() views.IPPrefixSlice {
	return views.IPPrefixSliceOf(v.ж.RoutableIPs)
}

func (v HostinfoView) RequestTags() views.Slice[string] {
	return views.SliceOf(v.ж.RequestTags)
}

func (v HostinfoView) SSH_HostKeys() views.Slice[string] {
	return views.SliceOf(v.ж.SSH_HostKeys)
}

func (v HostinfoView) Services() views.Slice[Service] {
	return views.SliceOf(v.ж.Services)
}

func (v HostinfoView) NetInfo() NetInfoView { return v.ж.NetInfo.View() }

// View returns a read-only accessor for ni.
func (ni *NetInfo) View() NetInfoView { return NetInfoView{ni} }

// NetInfoView is a read-only accessor for NetInfo.
// See NetInfo.
type NetInfoView struct {
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *NetInfo
}

// Valid reports whether the underlying value is not nil.
func (v NetInfoView) Valid() bool { return v.ж != nil }

// AsStruct returns a deep-copy of the underlying value.
func (v NetInfoView) AsStruct() *NetInfo { return v.ж.Clone() }

func (v NetInfoView) MappingVariesByDestIP() opt.Bool { return v.ж.MappingVariesByDestIP }
func (v NetInfoView) HairPinning() opt.Bool           { return v.ж.HairPinning }
func (v NetInfoView) WorkingIPv6() opt.Bool           { return v.ж.WorkingIPv6 }
func (v NetInfoView) WorkingUDP() opt.Bool            { return v.ж.WorkingUDP }
func (v NetInfoView) HavePortMap() bool               { return v.ж.HavePortMap }
func (v NetInfoView) UPnP() opt.Bool                  { return v.ж.UPnP }
func (v NetInfoView) PMP() opt.Bool                   { return v.ж.PMP }
func (v NetInfoView) PCP() opt.Bool                   { return v.ж.PCP }
func (v NetInfoView) PreferredDERP() int              { return v.ж.PreferredDERP }
func (v NetInfoView) LinkType() string                { return v.ж.LinkType }
func (v NetInfoView) String() string                  { return v.ж.String() }

// DERPLatencyForEach calls fn for each value in the DERPLatency map.
func (v NetInfoView) DERPLatencyForEach(fn func(k string, v float64)) {
	for k, v := range v.ж.DERPLatency {
		fn(k, v)
	}
}
