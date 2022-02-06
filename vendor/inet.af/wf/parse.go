// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wf

import (
	"errors"
	"fmt"
	"math/bits"
	"net"
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

// This file contains parsing code for structures returned by the WFP
// API. These are the structs defined in types.go, allocated out of
// the C heap by WFP. The parsers in this file convert those raw
// structs (which require unsafe pointers to traverse) into safe Go
// types.

var (
	typeUint8                  = reflect.TypeOf(uint8(0))
	typeUint16                 = reflect.TypeOf(uint16(0))
	typeUint32                 = reflect.TypeOf(uint32(0))
	typeUint64                 = reflect.TypeOf(uint64(0))
	typeArray16                = reflect.TypeOf([16]byte{})
	typeBytes                  = reflect.TypeOf([]byte(nil))
	typeSID                    = reflect.TypeOf(&windows.SID{})
	typeSecurityDescriptor     = reflect.TypeOf(windows.SECURITY_DESCRIPTOR{})
	typeTokenInformation       = reflect.TypeOf(TokenInformation{})
	typeTokenAccessInformation = reflect.TypeOf(TokenAccessInformation{})
	typeMAC                    = reflect.TypeOf(net.HardwareAddr{})
	typeBitmapIndex            = reflect.TypeOf(uint8(0))
	typeIP                     = reflect.TypeOf(netaddr.IP{})
	typePrefix                 = reflect.TypeOf(netaddr.IPPrefix{})
	typeRange                  = reflect.TypeOf(Range{})
	typeString                 = reflect.TypeOf("")
)

// fieldTypeMap maps a layer field's dataType to a Go value of that
// type.
var fieldTypeMap = map[dataType]reflect.Type{
	dataTypeUint8:                  typeUint8,
	dataTypeUint16:                 typeUint16,
	dataTypeUint32:                 typeUint32,
	dataTypeUint64:                 typeUint64,
	dataTypeByteArray16:            typeArray16,
	dataTypeByteBlob:               typeBytes,
	dataTypeSID:                    typeSID,
	dataTypeSecurityDescriptor:     typeSecurityDescriptor,
	dataTypeTokenInformation:       typeTokenInformation,
	dataTypeTokenAccessInformation: typeTokenAccessInformation,
	dataTypeArray6:                 typeMAC,
	dataTypeBitmapIndex:            typeBitmapIndex,
	dataTypeV4AddrMask:             typePrefix,
	dataTypeV6AddrMask:             typePrefix,
	dataTypeRange:                  typeRange,
}

// fieldType returns the reflect.Type for a layer field, or an error
// if the field has an unknown type.
func fieldType(f *fwpmField0) (reflect.Type, error) {
	// IP addresses are represented as either a uint32 or a 16-byte
	// array, with a modifier flag indicating that it's an IP
	// address. Use plain IPs when exposing in Go.
	if f.Type == fwpmFieldTypeIPAddress {
		if f.DataType != dataTypeUint32 && f.DataType != dataTypeByteArray16 {
			return nil, fmt.Errorf("field has IP address type, but underlying datatype is %s (want Uint32 or ByteArray16)", f.DataType)
		}
		return typeIP, nil
	}
	// Flags are a uint32 with a modifier. This just checks that there
	// are no surprise flag fields of other types.
	if f.Type == fwpmFieldTypeFlags {
		if f.DataType != dataTypeUint32 {
			return nil, fmt.Errorf("field has flag type, but underlying datatype is %s (want Uint32)", f.DataType)
		}
		return typeUint32, nil
	}

	// FWPM_CONDITION_ALE_APP_ID is provided by WFP as a byte blob
	// (aka []byte), but those bytes are actually a null-terminated,
	// UTF-16 encoded string. Since WFP doesn't use its own "unicode
	// string" datatype for anything, we use Go strings as a special
	// case for thtat one field.
	if f.DataType == dataTypeByteBlob && *f.FieldKey == FieldALEAppID {
		return typeString, nil
	}

	// For everything else, there's a simple mapping.
	if t, ok := fieldTypeMap[f.DataType]; ok {
		return t, nil
	}

	return nil, fmt.Errorf("unknown data type %s", f.DataType)
}

// toLayers converts a C array of *fwpmLayer0 to a safe-to-use *Layer slice.
func fromLayer0(array **fwpmLayer0, num uint32) ([]*Layer, error) {
	var ret []*Layer

	var layers []*fwpmLayer0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&layers))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(array))

	for _, layer := range layers {
		l := &Layer{
			ID:              layer.LayerKey,
			Name:            windows.UTF16PtrToString(layer.DisplayData.Name),
			Description:     windows.UTF16PtrToString(layer.DisplayData.Description),
			DefaultSublayer: layer.DefaultSublayerKey,
			KernelID:        layer.LayerID,
		}

		var fields []fwpmField0
		sh = (*reflect.SliceHeader)(unsafe.Pointer(&fields))
		sh.Cap = int(layer.NumFields)
		sh.Len = int(layer.NumFields)
		sh.Data = uintptr(unsafe.Pointer(layer.Fields))

		for i := range fields {
			field := &fields[i]
			typ, err := fieldType(field)
			if err != nil {
				return nil, fmt.Errorf("finding type of field %s: %w", *field.FieldKey, err)
			}
			l.Fields = append(l.Fields, &Field{
				ID:   *field.FieldKey,
				Type: typ,
			})
		}

		ret = append(ret, l)
	}

	return ret, nil
}

// toSublayers converts a C array of *fwpmSublayer0 to a safe-to-use *Sublayer slice.
func fromSublayer0(array **fwpmSublayer0, num uint32) []*Sublayer {
	var ret []*Sublayer

	var sublayers []*fwpmSublayer0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&sublayers))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(array))

	for _, sublayer := range sublayers {
		s := &Sublayer{
			ID:           sublayer.SublayerKey,
			Name:         windows.UTF16PtrToString(sublayer.DisplayData.Name),
			Description:  windows.UTF16PtrToString(sublayer.DisplayData.Description),
			Persistent:   (sublayer.Flags & fwpmSublayerFlagsPersistent) != 0,
			ProviderData: fromByteBlob(&sublayer.ProviderData),
			Weight:       sublayer.Weight,
		}
		if sublayer.ProviderKey != nil {
			// Make a copy of the GUID, to ensure we're not aliasing C
			// memory.
			s.Provider = ProviderID(*sublayer.ProviderKey)
		}
		ret = append(ret, s)
	}

	return ret
}

// toProviders converts a C array of fwpmProvider0 to a safe-to-use Provider
// slice.
func fromProvider0(array **fwpmProvider0, num uint32) []*Provider {
	var ret []*Provider

	var providers []*fwpmProvider0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&providers))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(array))

	for _, provider := range providers {
		p := &Provider{
			ID:          provider.ProviderKey,
			Name:        windows.UTF16PtrToString(provider.DisplayData.Name),
			Description: windows.UTF16PtrToString(provider.DisplayData.Description),
			Persistent:  (provider.Flags & fwpmProviderFlagsPersistent) != 0,
			Disabled:    (provider.Flags & fwpmProviderFlagsDisabled) != 0,
			Data:        fromByteBlob(&provider.ProviderData),
			ServiceName: windows.UTF16PtrToString(provider.ServiceName),
		}
		ret = append(ret, p)
	}

	return ret
}

// fromNetEvent1 converts a C array of fwpmNetEvent1 to a safe-to-use
// DropEvent slice.
func fromNetEvent1(array **fwpmNetEvent1, num uint32) ([]*DropEvent, error) {
	var ret []*DropEvent

	var events []*fwpmNetEvent1
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&events))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(array))

	for _, event := range events {
		if event.Type != fwpmNetEventClassifyDrop {
			continue
		}

		e := &DropEvent{
			Timestamp:  time.Unix(0, event.Header.Timestamp.Nanoseconds()),
			IPProtocol: event.Header.IPProtocol,
			LocalAddr:  netaddr.IPPortFrom(netaddr.IP{}, event.Header.LocalPort),
			RemoteAddr: netaddr.IPPortFrom(netaddr.IP{}, event.Header.RemotePort),
			LayerID:    event.Drop.LayerID,
			FilterID:   event.Drop.FilterID,
		}
		switch event.Header.IPVersion {
		case fwpIPVersion4:
			localIP := ipv4From32(*(*uint32)(unsafe.Pointer(&event.Header.LocalAddr[0])))
			e.LocalAddr = e.LocalAddr.WithIP(localIP)
			remoteIP := ipv4From32(*(*uint32)(unsafe.Pointer(&event.Header.RemoteAddr[0])))
			e.RemoteAddr = e.RemoteAddr.WithIP(remoteIP)
		case fwpIPVersion6:
			localIP := netaddr.IPFrom16(event.Header.LocalAddr)
			e.LocalAddr = e.LocalAddr.WithIP(localIP)
			remoteIP := netaddr.IPFrom16(event.Header.RemoteAddr)
			e.RemoteAddr = e.RemoteAddr.WithIP(remoteIP)
		}
		appID, err := fromByteBlobToString(&event.Header.AppID)
		if err != nil {
			return nil, err
		}
		e.AppID = appID
		ret = append(ret, e)
	}

	return ret, nil
}

func fromFilter0(array **fwpmFilter0, num uint32, layerTypes layerTypes) ([]*Rule, error) {
	var rules []*fwpmFilter0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&rules))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(array))

	var ret []*Rule

	for _, rule := range rules {
		r := &Rule{
			ID:           rule.FilterKey,
			KernelID:     rule.FilterID,
			Name:         windows.UTF16PtrToString(rule.DisplayData.Name),
			Description:  windows.UTF16PtrToString(rule.DisplayData.Description),
			Layer:        rule.LayerKey,
			Sublayer:     rule.SublayerKey,
			Action:       rule.Action.Type,
			Persistent:   (rule.Flags & fwpmFilterFlagsPersistent) != 0,
			BootTime:     (rule.Flags & fwpmFilterFlagsBootTime) != 0,
			ProviderData: fromByteBlob(&rule.ProviderData),
			Disabled:     (rule.Flags & fwpmFilterFlagsDisabled) != 0,
		}
		if rule.ProviderKey != nil {
			r.Provider = ProviderID(*rule.ProviderKey)
		}
		if rule.EffectiveWeight.Type == dataTypeUint64 {
			r.Weight = **(**uint64)(unsafe.Pointer(&rule.EffectiveWeight.Value))
		}
		if r.Action == ActionCalloutTerminating || r.Action == ActionCalloutInspection || r.Action == ActionCalloutUnknown {
			r.Callout = rule.Action.GUID
		}
		if r.Action == ActionCalloutTerminating || r.Action == ActionCalloutUnknown {
			r.PermitIfMissing = (rule.Flags & fwpmFilterFlagsPermitIfCalloutUnregistered) != 0
		}
		r.HardAction = (rule.Flags & fwpmFilterFlagsClearActionRight) != 0

		ft := layerTypes[r.Layer]
		if ft == nil {
			return nil, fmt.Errorf("unknown layer %s", r.Layer)
		}

		ms, err := fromCondition0(rule.FilterConditions, rule.NumFilterConditions, ft)
		if err != nil {
			return nil, err
		}

		r.Conditions = ms

		ret = append(ret, r)
	}

	return ret, nil
}

func fromCondition0(condArray *fwpmFilterCondition0, num uint32, fieldTypes fieldTypes) ([]*Match, error) {
	var conditions []fwpmFilterCondition0
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&conditions))
	sh.Cap = int(num)
	sh.Len = int(num)
	sh.Data = uintptr(unsafe.Pointer(condArray))

	var ret []*Match

	for i := range conditions {
		cond := &conditions[i]
		fieldType, ok := fieldTypes[cond.FieldKey]
		if !ok {
			return nil, fmt.Errorf("unknown field %s", cond.FieldKey)
		}

		v, err := fromValue0((*fwpValue0)(unsafe.Pointer(&cond.Value)), fieldType)
		if err != nil {
			return nil, fmt.Errorf("getting value for match [%s %s]: %w", cond.FieldKey, cond.MatchType, err)
		}
		m := &Match{
			Field: cond.FieldKey,
			Op:    cond.MatchType,
			Value: v,
		}

		ret = append(ret, m)
	}

	return ret, nil
}

// fromValue converts a fwpValue0 to the corresponding Go value.
func fromValue0(v *fwpValue0, ftype reflect.Type) (interface{}, error) {
	switch v.Type {
	case dataTypeUint8:
		return *(*uint8)(unsafe.Pointer(&v.Value)), nil
	case dataTypeUint16:
		return *(*uint16)(unsafe.Pointer(&v.Value)), nil
	case dataTypeUint32:
		u := *(*uint32)(unsafe.Pointer(&v.Value))
		if ftype == typeIP {
			return ipv4From32(u), nil
		}
		return u, nil
	case dataTypeUint64:
		return **(**uint64)(unsafe.Pointer(&v.Value)), nil
	case dataTypeByteArray16:
		var ret [16]byte
		copy(ret[:], fromBytes(v.Value, 16))
		if ftype == typeIP {
			return netaddr.IPFrom16(ret), nil
		}
		return ret, nil
	case dataTypeByteBlob:
		if ftype == typeString {
			return fromByteBlobToString(*(**fwpByteBlob)(unsafe.Pointer(&v.Value)))
		} else {
			return fromByteBlob(*(**fwpByteBlob)(unsafe.Pointer(&v.Value))), nil
		}
	case dataTypeSID:
		return parseSID(&v.Value)
	case dataTypeSecurityDescriptor:
		return parseSecurityDescriptor(&v.Value)
	case dataTypeArray6:
		ret := make(net.HardwareAddr, 6)
		copy(ret[:], fromBytes(v.Value, 6))
		return ret, nil
	case dataTypeV4AddrMask:
		return parseV4AddrAndMask(&v.Value), nil
	case dataTypeV6AddrMask:
		return parseV6AddrAndMask(&v.Value), nil
	case dataTypeRange:
		return parseRange0(&v.Value, ftype)
	}
	// Deliberately omitted: TokenInformation, TokenAccessInformation
	// and BitmapIndex seem to only be used as field types, but match
	// against other types only.

	return nil, fmt.Errorf("don't know how to map API type %s into Go", v.Type)
}

func parseV4AddrAndMask(v *uintptr) netaddr.IPPrefix {
	v4 := *(**fwpV4AddrAndMask)(unsafe.Pointer(v))
	ip := netaddr.IPv4(uint8(v4.Addr>>24), uint8(v4.Addr>>16), uint8(v4.Addr>>8), uint8(v4.Addr))
	bits := uint8(32 - bits.TrailingZeros32(v4.Mask))
	return netaddr.IPPrefixFrom(ip, bits)
}

func parseV6AddrAndMask(v *uintptr) netaddr.IPPrefix {
	v6 := *(**fwpV6AddrAndMask)(unsafe.Pointer(v))
	return netaddr.IPPrefixFrom(netaddr.IPFrom16(v6.Addr), v6.PrefixLength)
}

func parseSID(v *uintptr) (*windows.SID, error) {
	// TODO: export IsValidSid in x/sys/windows so we can vaguely
	// verify this pointer.
	sid := *(**windows.SID)(unsafe.Pointer(v))
	// Copy the SID into Go memory.
	dsid, err := sid.Copy()
	if err != nil {
		return nil, err
	}
	return dsid, nil
}

func parseSecurityDescriptor(v *uintptr) (*windows.SECURITY_DESCRIPTOR, error) {
	// The security descriptor is embedded in the API response as
	// a byte slice.
	bb := fromByteBlob(*(**fwpByteBlob)(unsafe.Pointer(v)))
	relSD := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&bb[0]))
	return relSD, nil
}

func parseRange0(v *uintptr, ftype reflect.Type) (interface{}, error) {
	r := *(**fwpRange0)(unsafe.Pointer(v))
	from, err := fromValue0(&r.From, ftype)
	if err != nil {
		return nil, err
	}
	to, err := fromValue0(&r.To, ftype)
	if err != nil {
		return nil, err
	}
	if reflect.TypeOf(from) != reflect.TypeOf(to) {
		return nil, fmt.Errorf("range.From and range.To types don't match: %s / %s", reflect.TypeOf(from), reflect.TypeOf(to))
	}
	if reflect.TypeOf(from) == typeIP {
		return netaddr.IPRangeFrom(from.(netaddr.IP), to.(netaddr.IP)), nil
	}
	return Range{from, to}, nil
}

func ipv4From32(v uint32) netaddr.IP {
	return netaddr.IPv4(uint8(v>>24), uint8(v>>16), uint8(v>>8), uint8(v))
}

func fromBytes(bb uintptr, length int) []byte {
	var bs []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	sh.Cap = length
	sh.Len = length
	sh.Data = bb
	return append([]byte(nil), bs...)
}

// fromByteBlob extracts the bytes from bb and returns them as a
// []byte that doesn't alias C memory.
func fromByteBlob(bb *fwpByteBlob) []byte {
	if bb == nil || bb.Size == 0 {
		return nil
	}

	var blob []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&blob))
	sh.Cap = int(bb.Size)
	sh.Len = sh.Cap
	sh.Data = uintptr(unsafe.Pointer(bb.Data))

	return append([]byte(nil), blob...)
}

func fromByteBlobToString(bb *fwpByteBlob) (string, error) {
	if bb == nil || bb.Size == 0 {
		return "", nil
	}
	if bb.Size%2 != 0 {
		return "", errors.New("byte blob should be string, but has odd number of bytes")
	}

	var blob []uint16
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&blob))
	sh.Cap = int(bb.Size) / 2
	sh.Len = sh.Cap
	sh.Data = uintptr(unsafe.Pointer(bb.Data))

	return windows.UTF16ToString(blob), nil
}
