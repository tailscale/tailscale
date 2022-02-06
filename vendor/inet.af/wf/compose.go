// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

// toSession0 converts opts into an arena-allocated fwpmSession0.
func toSession0(a *arena, opts *Options) *fwpmSession0 {
	ret := (*fwpmSession0)(a.Alloc(unsafe.Sizeof(fwpmSession0{})))
	*ret = fwpmSession0{
		DisplayData: fwpmDisplayData0{
			Name:        toUint16(a, opts.Name),
			Description: toUint16(a, opts.Description),
		},
		TxnWaitTimeoutMillis: uint32(opts.TransactionStartTimeout.Milliseconds()),
	}
	if opts.Dynamic {
		ret.Flags = fwpmSession0FlagDynamic
	}
	return ret
}

// toSublayerEnumTemplate0 returns an arena-allocated
// fwpmSublayerEnumTemplate0 that filters on the given provider, or
// all if provider is nil.
func toSublayerEnumTemplate0(a *arena, provider ProviderID) *fwpmSublayerEnumTemplate0 {
	ret := (*fwpmSublayerEnumTemplate0)(a.Alloc(unsafe.Sizeof(fwpmSublayerEnumTemplate0{})))
	ret.ProviderKey = toGUID(a, windows.GUID(provider))
	return ret
}

// toSublayer0 converts sl into an arena-allocated fwpmSublayer0.
func toSublayer0(a *arena, sl *Sublayer) *fwpmSublayer0 {
	ret := (*fwpmSublayer0)(a.Alloc(unsafe.Sizeof(fwpmSublayer0{})))
	*ret = fwpmSublayer0{
		SublayerKey: sl.ID,
		DisplayData: fwpmDisplayData0{
			Name:        toUint16(a, sl.Name),
			Description: toUint16(a, sl.Description),
		},
		ProviderKey: toGUID(a, windows.GUID(sl.Provider)),
		ProviderData: fwpByteBlob{
			Size: uint32(len(sl.ProviderData)),
			Data: toBytes(a, sl.ProviderData),
		},
		Weight: sl.Weight,
	}
	if sl.Persistent {
		ret.Flags = fwpmSublayerFlagsPersistent
	}

	return ret
}

// toProvider0 converts p into an arena-allocated fwpmProvider0.
func toProvider0(a *arena, p *Provider) *fwpmProvider0 {
	ret := (*fwpmProvider0)(a.Alloc(unsafe.Sizeof(fwpmProvider0{})))
	*ret = fwpmProvider0{
		ProviderKey: p.ID,
		DisplayData: fwpmDisplayData0{
			Name:        toUint16(a, p.Name),
			Description: toUint16(a, p.Description),
		},
		ProviderData: fwpByteBlob{
			Size: uint32(len(p.Data)),
			Data: toBytes(a, p.Data),
		},
		ServiceName: toUint16(a, p.ServiceName),
	}
	if p.Persistent {
		ret.Flags = fwpmProviderFlagsPersistent
	}

	return ret
}

// toFilter0 converts r into an arena-allocated fwpmFilter0, using lt
// as necessary to correctly cast values.
func toFilter0(a *arena, r *Rule, lt layerTypes) (*fwpmFilter0, error) {
	conds, err := toCondition0(a, r.Conditions, lt[r.Layer])
	if err != nil {
		return nil, err
	}

	typ, val, err := toValue0(a, r.Weight, typeUint64)
	if err != nil {
		return nil, err
	}

	ret := (*fwpmFilter0)(a.Alloc(unsafe.Sizeof(fwpmFilter0{})))
	*ret = fwpmFilter0{
		FilterKey: r.ID,
		DisplayData: fwpmDisplayData0{
			Name:        toUint16(a, r.Name),
			Description: toUint16(a, r.Description),
		},
		ProviderKey: toGUID(a, windows.GUID(r.Provider)),
		ProviderData: fwpByteBlob{
			Size: uint32(len(r.ProviderData)), // todo: overflow?
			Data: toBytes(a, r.ProviderData),
		},
		LayerKey:    r.Layer,
		SublayerKey: r.Sublayer,
		Weight: fwpValue0{
			Type:  typ,
			Value: val,
		},
		NumFilterConditions: uint32(len(r.Conditions)), // TODO: overflow?
		FilterConditions:    conds,
		Action: fwpmAction0{
			Type: r.Action,
			GUID: r.Callout,
		},
	}

	if r.HardAction {
		ret.Flags |= fwpmFilterFlagsClearActionRight
	}
	if r.PermitIfMissing {
		ret.Flags |= fwpmFilterFlagsPermitIfCalloutUnregistered
	}
	if r.Persistent {
		ret.Flags |= fwpmFilterFlagsPersistent
	}
	if r.BootTime {
		ret.Flags |= fwpmFilterFlagsBootTime
	}

	return ret, nil
}

// toCondition0 converts ms into an arena-allocated
// fwpmFilterCondition0 array, using lt as necessary to correctly cast
// values.
func toCondition0(a *arena, ms []*Match, ft fieldTypes) (array *fwpmFilterCondition0, err error) {
	if len(ms) == 0 {
		return nil, nil
	}
	array = (*fwpmFilterCondition0)(a.Alloc(uintptr(len(ms)) * unsafe.Sizeof(fwpmFilterCondition0{})))

	var conds []fwpmFilterCondition0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&conds))
	sh.Cap = len(ms)
	sh.Len = len(ms)
	sh.Data = uintptr(unsafe.Pointer(array))

	for i, m := range ms {
		c := &conds[i]

		typ, val, err := toValue0(a, m.Value, ft[m.Field])
		if err != nil {
			return nil, fmt.Errorf("invalid match %v: %w", m, err)
		}

		*c = fwpmFilterCondition0{
			FieldKey:  m.Field,
			MatchType: m.Op,
			Value: fwpConditionValue0{
				Type:  typ,
				Value: val,
			},
		}
	}

	return array, nil
}

// toValue0 converts v into the component parts of an fwpValue0 or
// fwpConditionValue0.
func toValue0(a *arena, v interface{}, ftype reflect.Type) (typ dataType, val uintptr, err error) {
	mapErr := func() (dataType, uintptr, error) {
		return 0, 0, fmt.Errorf("cannot map Go type %T to field type %s", v, ftype)
	}

	switch ftype {
	case typeUint8:
		typ = dataTypeUint8
		switch u := v.(type) {
		case uint8:
			*(*uint8)(unsafe.Pointer(&val)) = u
		case IPProto:
			*(*uint8)(unsafe.Pointer(&val)) = uint8(u)
		default:
			return mapErr()
		}
	case typeUint16:
		typ = dataTypeUint16
		u, ok := v.(uint16)
		if !ok {
			return mapErr()
		}
		*(*uint16)(unsafe.Pointer(&val)) = u
	case typeUint32:
		typ = dataTypeUint32
		switch u := v.(type) {
		case uint32:
			*(*uint32)(unsafe.Pointer(&val)) = u
		case ConditionFlag:
			*(*uint32)(unsafe.Pointer(&val)) = uint32(u)
		default:
			return mapErr()
		}
	case typeUint64:
		typ = dataTypeUint64
		u, ok := v.(uint64)
		if !ok {
			return mapErr()
		}
		p := a.Alloc(unsafe.Sizeof(u))
		*(*uint64)(p) = u
		val = uintptr(p)
	case typeBytes:
		typ = dataTypeByteBlob
		bb, ok := v.([]byte)
		if !ok {
			return mapErr()
		}

		p := a.Alloc(unsafe.Sizeof(fwpByteBlob{}))
		*(*fwpByteBlob)(p) = fwpByteBlob{
			Size: uint32(len(bb)),
			Data: toBytes(a, bb),
		}
		val = uintptr(p)
	case typeString:
		s, ok := v.(string)
		if !ok {
			return mapErr()
		}
		bb, l := toBytesFromString(a, s)

		p := a.Alloc(unsafe.Sizeof(fwpByteBlob{}))
		*(*fwpByteBlob)(p) = fwpByteBlob{
			Size: uint32(l),
			Data: bb,
		}
		typ = dataTypeByteBlob
		val = uintptr(p)
	case typeSID:
		typ = dataTypeSID
		s, ok := v.(*windows.SID)
		if !ok {
			return mapErr()
		}
		sidLen := windows.GetLengthSid(s)
		p := a.Alloc(uintptr(sidLen))
		if err := windows.CopySid(sidLen, (*windows.SID)(p), s); err != nil {
			return 0, 0, err
		}
		val = uintptr(p)
	case typeArray16:
		typ = dataTypeByteArray16
		bs, ok := v.([16]byte)
		if !ok {
			return mapErr()
		}
		val = uintptr(unsafe.Pointer(toBytes(a, bs[:])))
	case typeMAC:
		typ = dataTypeArray6
		mac, ok := v.(net.HardwareAddr)
		if !ok {
			return mapErr()
		}
		if len(mac) != 6 {
			return mapErr() // TODO: better error
		}
		val = uintptr(unsafe.Pointer(toBytes(a, mac[:])))
	case typeIP:
		switch m := v.(type) {
		case netaddr.IP:
			if m.Is4() {
				typ = dataTypeUint32
				*(*uint32)(unsafe.Pointer(&val)) = u32FromIPv4(m)
			} else {
				typ = dataTypeByteArray16
				b16 := m.As16()
				val = uintptr(unsafe.Pointer(toBytes(a, b16[:])))
			}
		case netaddr.IPPrefix:
			if m.IP().Is4() {
				typ = dataTypeV4AddrMask
				val = uintptr(unsafe.Pointer(toFwpV4AddrAndMask(a, m)))
			} else {
				typ = dataTypeV6AddrMask
				val = uintptr(unsafe.Pointer(toFwpV6AddrAndMask(a, m)))
			}
		case netaddr.IPRange:
			if !m.Valid() {
				return 0, 0, fmt.Errorf("invalid IPRange %v", m)
			}
			r, err := toRange0(a, Range{m.From, m.To}, ftype)
			if err != nil {
				return 0, 0, err
			}
			typ = dataTypeRange
			val = uintptr(unsafe.Pointer(r))
		default:
			return mapErr()
		}
	case typeSecurityDescriptor:
		sd, ok := v.(*windows.SECURITY_DESCRIPTOR)
		if !ok {
			return mapErr()
		}
		csd, err := toSecurityDescriptor(a, sd)
		if err != nil {
			return 0, 0, err
		}

		// This should be a FWP_BYTE_BLOB pointing to a
		// SECURITY_DESCRIPTOR struct according to the Win32
		// Documentation.
		// https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_condition_value0
		p := a.Alloc(unsafe.Sizeof(fwpByteBlob{}))
		*(*fwpByteBlob)(p) = fwpByteBlob{
			Size: uint32(sd.Length()),
			Data: (*uint8)(unsafe.Pointer(csd)),
		}
		typ = dataTypeSecurityDescriptor
		val = uintptr(p)
	case typeRange:
		r, ok := v.(Range)
		if !ok {
			return mapErr()
		}
		r0, err := toRange0(a, r, ftype)
		if err != nil {
			return 0, 0, err
		}
		typ = dataTypeRange
		val = uintptr(unsafe.Pointer(r0))
	default:
		return mapErr()
	}

	// TODO: dataTypeTokenInformation
	// TODO: dataTypeTokenAccessInformation

	return typ, val, nil
}

// toRange0 converts r into an arena-allocated fwpRange0.
func toRange0(a *arena, r Range, ftype reflect.Type) (ret *fwpRange0, err error) {
	if _, ok := r.From.(Range); ok {
		return nil, errors.New("can't have a Range of Ranges")
	}
	if _, ok := r.To.(Range); ok {
		return nil, errors.New("can't have a Range of Ranges")
	}

	ftyp, fval, err := toValue0(a, r.From, ftype)
	if err != nil {
		return nil, err
	}
	ttyp, tval, err := toValue0(a, r.To, ftype)
	if err != nil {
		return nil, err
	}
	if ftyp != ttyp {
		return nil, fmt.Errorf("range type mismatch: %T vs. %T", r.From, r.To)
	}
	ret = (*fwpRange0)(a.Alloc(unsafe.Sizeof(fwpRange0{})))

	*ret = fwpRange0{
		From: fwpValue0{
			Type:  ftyp,
			Value: fval,
		},
		To: fwpValue0{
			Type:  ttyp,
			Value: tval,
		},
	}
	return ret, nil
}

// toUint16 converts s into an arena-allocated, null-terminated UTF-16
// array pointer.
func toUint16(a *arena, s string) *uint16 {
	if len(s) == 0 {
		return nil
	}

	n := windows.StringToUTF16(s)
	ret := a.Alloc(2 * uintptr(len(n)))

	var sl []uint16
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&sl))
	sh.Cap = len(s)
	sh.Len = len(s)
	sh.Data = uintptr(ret)

	copy(sl, n)
	return (*uint16)(ret)
}

// toBytes converts bs into an arena-allocated byte array pointer.
func toBytes(a *arena, bs []byte) *byte {
	if len(bs) == 0 {
		return nil
	}

	ret := a.Alloc(uintptr(len(bs)))

	var sl []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&sl))
	sh.Cap = len(bs)
	sh.Len = len(bs)
	sh.Data = uintptr(ret)

	copy(sl, bs)
	return (*byte)(ret)
}

// toBytes converts s into an arena-allocated byte array pointer,
// containing a utf-16 encoded, null-terminated string.
func toBytesFromString(a *arena, s string) (*byte, int) {
	bs := windows.StringToUTF16(s)

	l := 2 * len(bs)
	ret := a.Alloc(uintptr(l))

	var retSlice []uint16
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&retSlice))
	sh.Cap = len(bs)
	sh.Len = len(bs)
	sh.Data = uintptr(ret)
	copy(retSlice, bs)

	return (*byte)(ret), l
}

// toGUID returns an arena-allocated copy of guid.
func toGUID(a *arena, guid windows.GUID) *windows.GUID {
	if guid == (windows.GUID{}) {
		return nil
	}
	ret := (*windows.GUID)(a.Alloc(unsafe.Sizeof(guid)))
	*ret = guid
	return ret
}

// toFwpV4AddrAndMask converts pfx into an arena-allocated
// fwpV4AddrAndMask.
func toFwpV4AddrAndMask(a *arena, pfx netaddr.IPPrefix) *fwpV4AddrAndMask {
	ret := (*fwpV4AddrAndMask)(a.Alloc(unsafe.Sizeof(fwpV4AddrAndMask{})))
	ret.Addr = u32FromIPv4(pfx.Masked().IP())
	ret.Mask = (^uint32(0)) << (32 - pfx.Bits())
	return ret
}

// toFwpV6AddrAndMask converts pfx into an arena-allocated
// fwpV6AddrAndMask.
func toFwpV6AddrAndMask(a *arena, pfx netaddr.IPPrefix) *fwpV6AddrAndMask {
	ret := (*fwpV6AddrAndMask)(a.Alloc(unsafe.Sizeof(fwpV6AddrAndMask{})))
	ret.Addr = pfx.IP().As16()
	ret.PrefixLength = pfx.Bits()
	return ret
}

// toSecurityDescriptor returns an arena-allocated copy of s.
func toSecurityDescriptor(a *arena, s *windows.SECURITY_DESCRIPTOR) (*windows.SECURITY_DESCRIPTOR, error) {
	s, err := s.ToSelfRelative()
	if err != nil {
		return nil, err
	}

	sl := s.Length()
	var from []byte
	sf := (*reflect.SliceHeader)(unsafe.Pointer(&from))
	sf.Cap = int(sl)
	sf.Len = int(sl)
	sf.Data = uintptr(unsafe.Pointer(s))

	p := a.Alloc(uintptr(s.Length()))
	var to []byte
	st := (*reflect.SliceHeader)(unsafe.Pointer(&to))
	st.Cap = int(sl)
	st.Len = int(sl)
	st.Data = uintptr(p)

	copy(to, from)

	return (*windows.SECURITY_DESCRIPTOR)(p), nil
}

// u32FromIPv4 returns ip as a big-endian uint32.
func u32FromIPv4(ip netaddr.IP) uint32 {
	b4 := ip.As4()
	return binary.BigEndian.Uint32(b4[:])
}
