// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wf

import (
	"golang.org/x/sys/windows"
)

//go:notinheap
type fwpmDisplayData0 struct {
	Name        *uint16
	Description *uint16
}

type fwpmSession0Flags uint32

const fwpmSession0FlagDynamic = 1

//go:notinheap
type fwpmSession0 struct {
	SessionKey           windows.GUID
	DisplayData          fwpmDisplayData0
	Flags                fwpmSession0Flags
	TxnWaitTimeoutMillis uint32
	ProcessID            uint32
	SID                  *windows.SID
	Username             *uint16
	KernelMode           uint8
}

type authnService uint32

const (
	authnServiceWinNT   authnService = 0xa
	authnServiceDefault authnService = 0xffffffff
)

//go:notinheap
type fwpmLayerEnumTemplate0 struct {
	reserved uint64
}

//go:notinheap
type fwpmLayer0 struct {
	LayerKey           LayerID
	DisplayData        fwpmDisplayData0
	Flags              uint32
	NumFields          uint32
	Fields             *fwpmField0
	DefaultSublayerKey SublayerID
	LayerID            uint16
}

type fwpmFieldType uint32

const (
	fwpmFieldTypeRawData   fwpmFieldType = iota // no special semantics
	fwpmFieldTypeIPAddress                      // data is an IP address
	fwpmFieldTypeFlags                          // data is a flag bitfield
)

type dataType uint32

const (
	dataTypeEmpty                  dataType = 0
	dataTypeUint8                  dataType = 1
	dataTypeUint16                 dataType = 2
	dataTypeUint32                 dataType = 3
	dataTypeUint64                 dataType = 4
	dataTypeByteArray16            dataType = 11
	dataTypeByteBlob               dataType = 12
	dataTypeSID                    dataType = 13
	dataTypeSecurityDescriptor     dataType = 14
	dataTypeTokenInformation       dataType = 15
	dataTypeTokenAccessInformation dataType = 16
	dataTypeArray6                 dataType = 18
	dataTypeBitmapIndex            dataType = 19
	dataTypeV4AddrMask             dataType = 256
	dataTypeV6AddrMask             dataType = 257
	dataTypeRange                  dataType = 258
)

// Types not implemented, because WFP doesn't seem to use them.
// dataTypeInt8 dataType = 5
// dataTypeInt16 dataType = 6
// dataTypeInt32 dataType = 7
// dataTypeInt64 dataType = 8
// dataTypeFloat dataType = 9
// dataTypeDouble dataType = 10
// dataTypeUnicodeString dataType = 17
// dataTypeBitmapArray64 dataType = 20

//go:notinheap
type fwpmField0 struct {
	FieldKey *FieldID
	Type     fwpmFieldType
	DataType dataType
}

//go:notinheap
type fwpmSublayerEnumTemplate0 struct {
	ProviderKey *windows.GUID
}

//go:notinheap
type fwpByteBlob struct {
	Size uint32
	Data *uint8
}

type fwpmSublayerFlags uint32

const fwpmSublayerFlagsPersistent fwpmSublayerFlags = 1

//go:notinheap
type fwpmSublayer0 struct {
	SublayerKey  SublayerID
	DisplayData  fwpmDisplayData0
	Flags        fwpmSublayerFlags
	ProviderKey  *windows.GUID
	ProviderData fwpByteBlob
	Weight       uint16
}

type fwpmProviderFlags uint32

const (
	fwpmProviderFlagsPersistent fwpmProviderFlags = 0x01
	fwpmProviderFlagsDisabled   fwpmProviderFlags = 0x10
)

//go:notinheap
type fwpmProvider0 struct {
	ProviderKey  ProviderID
	DisplayData  fwpmDisplayData0
	Flags        fwpmProviderFlags
	ProviderData fwpByteBlob
	ServiceName  *uint16
}

//go:notinheap
type fwpValue0 struct {
	Type  dataType
	Value uintptr // unioned value
}

type fwpmFilterFlags uint32

const (
	fwpmFilterFlagsPersistent fwpmFilterFlags = 1 << iota
	fwpmFilterFlagsBootTime
	fwpmFilterFlagsHasProviderContext
	fwpmFilterFlagsClearActionRight
	fwpmFilterFlagsPermitIfCalloutUnregistered
	fwpmFilterFlagsDisabled
	fwpmFilterFlagsIndexed
)

//go:notinheap
type fwpmAction0 struct {
	Type Action
	GUID CalloutID
}

// fwpmFilter0 is the Go representation of FWPM_FILTER0,
// which stores the state associated with a filter.
// See https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
//go:notinheap
type fwpmFilter0 struct {
	FilterKey           RuleID
	DisplayData         fwpmDisplayData0
	Flags               fwpmFilterFlags
	ProviderKey         *windows.GUID
	ProviderData        fwpByteBlob
	LayerKey            LayerID
	SublayerKey         SublayerID
	Weight              fwpValue0
	NumFilterConditions uint32
	FilterConditions    *fwpmFilterCondition0
	Action              fwpmAction0

	// Only one of RawContext/ProviderContextKey must be set.
	RawContext         uint64
	ProviderContextKey windows.GUID

	Reserved        *windows.GUID
	FilterID        uint64
	EffectiveWeight fwpValue0
}

//go:notinheap
type fwpConditionValue0 struct {
	Type  dataType
	Value uintptr
}

//go:notinheap
type fwpmFilterCondition0 struct {
	FieldKey  FieldID
	MatchType MatchType
	Value     fwpConditionValue0
}

//go:notinheap
type fwpV4AddrAndMask struct {
	Addr, Mask uint32
}

//go:notinheap
type fwpV6AddrAndMask struct {
	Addr         [16]byte
	PrefixLength uint8
}

//go:notinheap
type fwpmProviderContextEnumTemplate0 struct {
	ProviderKey         *ProviderID
	ProviderContextType uint32
}

//go:notinheap
type fwpmFilterEnumTemplate0 struct {
	ProviderKey             *ProviderID
	LayerKey                windows.GUID
	EnumType                filterEnumType
	Flags                   filterEnumFlags
	ProviderContextTemplate *fwpmProviderContextEnumTemplate0 // TODO: wtf?
	NumConditions           uint32
	Conditions              *fwpmFilterCondition0
	ActionMask              uint32
	CalloutKey              *windows.GUID
}

//go:notinheap
type fwpRange0 struct {
	From, To fwpValue0
}

type filterEnumType uint32

const (
	filterEnumTypeFullyContained filterEnumType = iota
	filterEnumTypeOverlapping
)

type filterEnumFlags uint32

const (
	filterEnumFlagsBestTerminatingMatch filterEnumFlags = iota + 1
	filterEnumFlagsSorted
	filterEnumFlagsBootTimeOnly
	filterEnumFlagsIncludeBootTime
	filterEnumFlagsIncludeDisabled
)

type fwpIPVersion uint32

const (
	fwpIPVersion4 fwpIPVersion = 0
	fwpIPVersion6 fwpIPVersion = 1
)

//go:notinheap
type fwpmNetEventHeader1 struct {
	Timestamp  windows.Filetime
	Flags      uint32       // enum
	IPVersion  fwpIPVersion // enum
	IPProtocol uint8
	_          [3]byte
	LocalAddr  [16]byte
	RemoteAddr [16]byte
	LocalPort  uint16
	RemotePort uint16
	ScopeID    uint32
	AppID      fwpByteBlob
	UserID     *windows.SID

	// Random reserved fields for an aborted attempt at including
	// Ethernet frame information. Not used, but we have to pad out
	// the struct appropriately.
	_ struct {
		reserved1 uint32
		unused2   struct {
			reserved2  [6]byte
			reserved3  [6]byte
			reserved4  uint32
			reserved5  uint32
			reserved6  uint16
			reserved7  uint32
			reserved8  uint32
			reserved9  uint16
			reserved10 uint64
		}
	}
}

//go:notinheap
type fwpmNetEventClassifyDrop1 struct {
	FilterID        uint64
	LayerID         uint16
	ReauthReason    uint32
	OriginalProfile uint32
	CurrentProfile  uint32
	Direction       uint32
	Loopback        uint32
}

type fwpmNetEventType uint32

const fwpmNetEventClassifyDrop = 3

//go:notinheap
type fwpmNetEvent1 struct {
	Header fwpmNetEventHeader1
	Type   fwpmNetEventType
	Drop   *fwpmNetEventClassifyDrop1
}
