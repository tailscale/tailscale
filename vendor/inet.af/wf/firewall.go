// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wf

import (
	"errors"
	"fmt"
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

type fieldTypes map[FieldID]reflect.Type
type layerTypes map[LayerID]fieldTypes

// Session is a connection to the WFP API.
type Session struct {
	handle windows.Handle
	// layerTypes is a map of layer ID -> field ID -> Go type for that field.
	layerTypes layerTypes
}

// Options configures a Session.
type Options struct {
	// Name is a short name for the session, shown in Windows
	// administrative tools.
	Name string
	// Description is a short description for the session, shown in
	// Windows administrative tools.
	Description string
	// Dynamic, if true, indicates that all objects created during the
	// session should be removed when the session is closed or the
	// current process terminates. Dynamic sessions are meant for
	// adding firewall configuration that should not outlast your
	// program's execution.
	Dynamic bool
	// TransactionStartTimeout is how long the session is willing to
	// wait to acquire the global transaction lock. If zero, WFP's
	// default timeout (15 seconds) is used.
	TransactionStartTimeout time.Duration
}

// New connects to the WFP API.
func New(opts *Options) (*Session, error) {
	if opts == nil {
		opts = &Options{}
	}

	var a arena
	defer a.Dispose()

	s0 := toSession0(&a, opts)

	var handle windows.Handle
	err := fwpmEngineOpen0(nil, authnServiceWinNT, nil, s0, &handle)
	if err != nil {
		return nil, err
	}

	ret := &Session{
		handle:     handle,
		layerTypes: layerTypes{},
	}

	// Populate the layer type cache.
	layers, err := ret.Layers()
	if err != nil {
		ret.Close()
		return nil, err
	}
	for _, layer := range layers {
		fields := fieldTypes{}
		for _, field := range layer.Fields {
			fields[field.ID] = field.Type
		}
		ret.layerTypes[layer.ID] = fields
	}

	return ret, nil
}

// Close implements io.Closer.
func (s *Session) Close() error {
	if s.handle == 0 {
		return nil
	}
	err := fwpmEngineClose0(s.handle)
	s.handle = 0
	return err
}

// LayerID identifies a WFP layer.
type LayerID windows.GUID

func (id LayerID) String() string {
	if s := guidNames[windows.GUID(id)]; s != "" {
		return s
	}
	return windows.GUID(id).String()
}

// IsZero reports whether id is nil or the zero GUID.
func (id *LayerID) IsZero() bool {
	return id == nil || *id == LayerID{}
}

// ConditionFlag represents special conditions that can be tested.
type ConditionFlag uint32 // do not change type, used in C calls

const (
	ConditionFlagIsLoopback             ConditionFlag = 0x00000001
	ConditionFlagIsIPSecSecured         ConditionFlag = 0x00000002
	ConditionFlagIsReauthorize          ConditionFlag = 0x00000004
	ConditionFlagIsWildcardBind         ConditionFlag = 0x00000008
	ConditionFlagIsRawEndpoint          ConditionFlag = 0x00000010
	ConditionFlagIsFragmant             ConditionFlag = 0x00000020
	ConditionFlagIsFragmantGroup        ConditionFlag = 0x00000040
	ConditionFlagIsIPSecNATTReclassify  ConditionFlag = 0x00000080
	ConditionFlagIsRequiresALEClassify  ConditionFlag = 0x00000100
	ConditionFlagIsImplicitBind         ConditionFlag = 0x00000200
	ConditionFlagIsReassembled          ConditionFlag = 0x00000400
	ConditionFlagIsNameAppSpecified     ConditionFlag = 0x00004000
	ConditionFlagIsPromiscuous          ConditionFlag = 0x00008000
	ConditionFlagIsAuthFW               ConditionFlag = 0x00010000
	ConditionFlagIsReclassify           ConditionFlag = 0x00020000
	ConditionFlagIsOutboundPassThru     ConditionFlag = 0x00040000
	ConditionFlagIsInboundPassThru      ConditionFlag = 0x00080000
	ConditionFlagIsConnectionRedirected ConditionFlag = 0x00100000
)

// IPProto represents the protocol being used.
type IPProto uint8 // do not change type, used in C calls

// From: https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
const (
	IPProtoICMP   IPProto = 1
	IPProtoICMPV6 IPProto = 58
	IPProtoTCP    IPProto = 6
	IPProtoUDP    IPProto = 17
)

// AppID returns the application ID associated with the provided file.
func AppID(file string) (string, error) {
	var a arena
	defer a.Dispose()
	fileBytes, _ := toBytesFromString(&a, file)
	var appID *fwpByteBlob
	if err := fwpmGetAppIdFromFileName0(fileBytes, &appID); err != nil {
		return "", err
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&appID)))
	return fromByteBlobToString(appID)
}

// Layer is a point in the packet processing path where filter rules
// can be applied.
type Layer struct {
	// ID is the unique identifier for this layer.
	ID LayerID
	// KernelID is the internal kernel ID for this layer.
	KernelID uint16
	// Name is a short descriptive name.
	Name string
	// Description is a longer description of the layer's function.
	Description string
	// DefaultSublayer is the ID for the default sublayer into which
	// filter rules are added.
	DefaultSublayer SublayerID
	// Fields describes the fields that are available in this layer to
	// be matched against.
	Fields []*Field
}

// FieldID identifies a WFP layer field.
type FieldID windows.GUID

func (id FieldID) String() string {
	if s := guidNames[windows.GUID(id)]; s != "" {
		return s
	}
	return windows.GUID(id).String()
}

// IsZero reports whether id is nil or the zero GUID.
func (id *FieldID) IsZero() bool {
	return id == nil || *id == FieldID{}
}

// Field is a piece of information that a layer makes available to
// filter rules for matching.
type Field struct {
	// ID is the unique identifier for the field.
	ID FieldID
	// Type is the type of the field.
	Type reflect.Type
}

// TokenAccessInformation represents all the information in a token
// that is necessary to perform an access check.
// This type is only present in Layer fields, and cannot be used
// directly as a value in firewall rules.
type TokenAccessInformation struct{}

type Range struct {
	From, To interface{}
}

// TokenInformation defines a set of security identifiers.
// This type is only present in Layer fields, and cannot be used
// directly as a value in firewall rules.
type TokenInformation struct{}

// Layers returns information on available WFP layers.
func (s *Session) Layers() ([]*Layer, error) {
	var enum windows.Handle
	if err := fwpmLayerCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		return nil, err
	}
	defer fwpmLayerDestroyEnumHandle0(s.handle, enum)

	var ret []*Layer

	for {
		layers, err := s.getLayerPage(enum)
		if err != nil {
			return nil, err
		}
		if len(layers) == 0 {
			return ret, nil
		}
		ret = append(ret, layers...)
	}
}

func (s *Session) getLayerPage(enum windows.Handle) ([]*Layer, error) {
	const pageSize = 100
	var (
		array **fwpmLayer0
		num   uint32
	)
	if err := fwpmLayerEnum0(s.handle, enum, pageSize, &array, &num); err != nil {
		return nil, err
	}
	if num == 0 {
		return nil, nil
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&array)))

	return fromLayer0(array, num)
}

// SublayerID identifies a WFP sublayer.
type SublayerID windows.GUID

func (id SublayerID) String() string {
	if s := guidNames[windows.GUID(id)]; s != "" {
		return s
	}
	return windows.GUID(id).String()
}

// IsZero reports whether id is nil or the zero GUID.
func (id *SublayerID) IsZero() bool {
	return id == nil || *id == SublayerID{}
}

// A Sublayer is a container for filtering rules.
type Sublayer struct {
	// ID is the unique identifier for this sublayer.
	ID SublayerID
	// Name is a short descriptive name.
	Name string
	// Description is a longer description of the Sublayer.
	Description string
	// Persistent indicates whether the sublayer is preserved across
	// restarts of the filtering engine.
	Persistent bool
	// Provider optionally identifies the Provider that manages this
	// sublayer.
	Provider ProviderID
	// ProviderData is optional opaque data that can be held on behalf
	// of the Provider.
	ProviderData []byte
	// Weight specifies the priority of this sublayer relative to
	// other sublayers. Higher-weighted sublayers are invoked first.
	Weight uint16
}

// Sublayers returns available Sublayers. If providers are given,
// returns only sublayers registered to those providers.
func (s *Session) Sublayers(providers ...ProviderID) ([]*Sublayer, error) {
	if len(providers) == 0 {
		// Do one lookup with a zero provider, which returns all
		// sublayers.
		providers = []ProviderID{ProviderID{}}
	}

	var ret []*Sublayer
	for _, provider := range providers {
		sls, err := s.getOneProvider(provider)
		if err != nil {
			return nil, err
		}
		ret = append(ret, sls...)
	}

	return ret, nil
}

func (s *Session) getOneProvider(provider ProviderID) ([]*Sublayer, error) {
	var a arena
	defer a.Dispose()

	tpl := toSublayerEnumTemplate0(&a, provider)

	var enum windows.Handle
	if err := fwpmSubLayerCreateEnumHandle0(s.handle, tpl, &enum); err != nil {
		return nil, err
	}
	defer fwpmSubLayerDestroyEnumHandle0(s.handle, enum)

	var ret []*Sublayer

	for {
		sublayers, err := s.getSublayerPage(enum)
		if err != nil {
			return nil, err
		}
		if len(sublayers) == 0 {
			return ret, nil
		}
		ret = append(ret, sublayers...)
	}
}

func (s *Session) getSublayerPage(enum windows.Handle) ([]*Sublayer, error) {
	const pageSize = 100
	var (
		array **fwpmSublayer0
		num   uint32
	)
	if err := fwpmSubLayerEnum0(s.handle, enum, pageSize, &array, &num); err != nil {
		return nil, err
	}
	if num == 0 {
		return nil, nil
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&array)))

	return fromSublayer0(array, num), nil
}

// AddSublayer creates a new Sublayer.
func (s *Session) AddSublayer(sl *Sublayer) error {
	// the WFP API accepts zero GUIDs and interprets it as "give me a
	// random GUID". However, we can't get that GUID back out, so it
	// would be pointless to make such a request. Stop it here.
	if sl.ID.IsZero() {
		return errors.New("Sublayer.ID cannot be zero")
	}

	var a arena
	defer a.Dispose()

	sl0 := toSublayer0(&a, sl)
	return fwpmSubLayerAdd0(s.handle, sl0, nil) // TODO: security descriptor
}

// DeleteSublayer deletes the Sublayer whose GUID is id.
func (s *Session) DeleteSublayer(id SublayerID) error {
	if id.IsZero() {
		return errors.New("GUID cannot be zero")
	}

	return fwpmSubLayerDeleteByKey0(s.handle, &id)
}

// ProviderID identifies a WFP provider.
type ProviderID windows.GUID

func (id ProviderID) String() string {
	if s := guidNames[windows.GUID(id)]; s != "" {
		return s
	}
	return windows.GUID(id).String()
}

// IsZero reports whether id is nil or the zero GUID.
func (id *ProviderID) IsZero() bool {
	return id == nil || *id == ProviderID{}
}

// A Provider is an entity that owns sublayers and filtering rules.
type Provider struct {
	// ID is the unique identifier for this provider.
	ID ProviderID
	// Name is a short descriptive name.
	Name string
	// Description is a longer description of the provider.
	Description string
	// Persistent indicates whether the provider is preserved across
	// restarts of the filtering engine.
	Persistent bool
	// Data is optional opaque data that can be held on behalf of the
	// Provider.
	Data []byte
	// ServiceName is an optional Windows service name. If present,
	// the rules owned by this Provider are only activated when the
	// service is active.
	ServiceName string

	// Disabled indicates whether the rules owned by this Provider are
	// disabled due to its associated service being
	// disabled. Read-only, ignored on Provider creation.
	Disabled bool
}

func (s *Session) Providers() ([]*Provider, error) {
	var enum windows.Handle
	if err := fwpmProviderCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		return nil, err
	}
	defer fwpmProviderDestroyEnumHandle0(s.handle, enum)

	var ret []*Provider

	for {
		providers, err := s.getProviderPage(enum)
		if err != nil {
			return nil, err
		}
		if len(providers) == 0 {
			return ret, nil
		}
		ret = append(ret, providers...)
	}
}

func (s *Session) getProviderPage(enum windows.Handle) ([]*Provider, error) {
	const pageSize = 100
	var (
		array **fwpmProvider0
		num   uint32
	)
	if err := fwpmProviderEnum0(s.handle, enum, pageSize, &array, &num); err != nil {
		return nil, err
	}
	if num == 0 {
		return nil, nil
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&array)))

	return fromProvider0(array, num), nil
}

// AddProvider creates a new provider.
func (s *Session) AddProvider(p *Provider) error {
	if p.ID.IsZero() {
		return errors.New("Provider.ID cannot be zero")
	}

	var a arena
	defer a.Dispose()

	p0 := toProvider0(&a, p)

	return fwpmProviderAdd0(s.handle, p0, nil)
}

// DeleteProvider deletes the Provider whose GUID is id. A provider
// can only be deleted once all the resources it owns have been
// deleted.
func (s *Session) DeleteProvider(id ProviderID) error {
	if id.IsZero() {
		return errors.New("GUID cannot be zero")
	}

	return fwpmProviderDeleteByKey0(s.handle, &id)
}

// MatchType is the operator to use when testing a field in a Match.
type MatchType uint32 // do not change type, used in C calls

const (
	MatchTypeEqual MatchType = iota
	MatchTypeGreater
	MatchTypeLess
	MatchTypeGreaterOrEqual
	MatchTypeLessOrEqual
	MatchTypeRange // true if the field value is within the Range.
	MatchTypeFlagsAllSet
	MatchTypeFlagsAnySet
	MatchTypeFlagsNoneSet
	MatchTypeEqualCaseInsensitive // only valid on strings, no string fields exist
	MatchTypeNotEqual
	MatchTypePrefix    // TODO: not well documented. Is this prefix.Contains(ip) ?
	MatchTypeNotPrefix // TODO: see above.
)

var mtStr = map[MatchType]string{
	MatchTypeEqual:                "==",
	MatchTypeGreater:              ">",
	MatchTypeLess:                 "<",
	MatchTypeGreaterOrEqual:       ">=",
	MatchTypeLessOrEqual:          "<=",
	MatchTypeRange:                "in",
	MatchTypeFlagsAllSet:          "F[all]",
	MatchTypeFlagsAnySet:          "F[any]",
	MatchTypeFlagsNoneSet:         "F[none]",
	MatchTypeEqualCaseInsensitive: "i==",
	MatchTypeNotEqual:             "!=",
	MatchTypePrefix:               "pfx",
	MatchTypeNotPrefix:            "!pfx",
}

func (m MatchType) String() string {
	return mtStr[m]
}

// Match is a matching test that gets run against a layer's field.
type Match struct {
	Field FieldID
	Op    MatchType
	Value interface{}
}

func (m Match) String() string {
	return fmt.Sprintf("%s %s %v (%T)", m.Field, m.Op, m.Value, m.Value)
}

// Action is an action the filtering engine can execute.
type Action uint32

const (
	// ActionBlock blocks a packet or session.
	ActionBlock Action = 0x1001
	// ActionPermit permits a packet or session.
	ActionPermit Action = 0x1002
	// ActionCalloutTerminating invokes a callout that must return a
	// permit or block verdict.
	ActionCalloutTerminating Action = 0x5003
	// ActionCalloutInspection invokes a callout that is expected to
	// not return a verdict (i.e. a read-only callout).
	ActionCalloutInspection Action = 0x6004
	// ActionCalloutUnknown invokes a callout that may return a permit
	// or block verdict.
	ActionCalloutUnknown Action = 0x4005
)

// RuleID identifies a WFP filtering rule.
type RuleID windows.GUID

func (id RuleID) String() string {
	if s := guidNames[windows.GUID(id)]; s != "" {
		return s
	}
	return windows.GUID(id).String()
}

// IsZero reports whether id is nil or the zero GUID.
func (id *RuleID) IsZero() bool {
	return id == nil || *id == RuleID{}
}

// CalloutID identifies a WFP callout function.
type CalloutID windows.GUID

func (id CalloutID) String() string {
	if s := guidNames[windows.GUID(id)]; s != "" {
		return s
	}
	return windows.GUID(id).String()
}

// IsZero reports whether id is nil or the zero GUID.
func (id *CalloutID) IsZero() bool {
	return id == nil || *id == CalloutID{}
}

// A Rule is an action to take on packets that match a set of
// conditions.
type Rule struct {
	// ID is the unique identifier for this rule.
	ID RuleID
	// KernelID is the kernel ID for this rule.
	KernelID uint64
	// Name is a short descriptive name.
	Name string
	// Description is a longer description of the rule.
	Description string
	// Layer is the ID of the layer in which the rule runs.
	Layer LayerID
	// Sublayer is the ID of the sublayer in which the rule runs.
	Sublayer SublayerID
	// Weight is the priority of the rule relative to other rules in
	// its sublayer.
	Weight uint64
	// Conditions are the tests which must pass for this rule to apply
	// to a packet.
	Conditions []*Match
	// Action is the action to take on matching packets.
	Action Action
	// Callout is the ID of the callout to invoke. Only valid if
	// Action is ActionCalloutTerminating, ActionCalloutInspection, or
	// ActionCalloutUnknown.
	Callout CalloutID
	// PermitIfMissing, if set, indicates that a callout action to a
	// callout ID that isn't registered should be translated into an
	// ActionPermit, rather than an ActionBlock. Only relevant if
	// Action is ActionCalloutTerminating or ActionCalloutUnknown.
	PermitIfMissing bool
	// HardAction, if set, indicates that the action type is hard and cannot
	// be overridden except by a Veto.
	HardAction bool

	// Persistent indicates whether the rule is preserved across
	// restarts of the filtering engine.
	Persistent bool
	// BootTime indicates that this rule applies only during early
	// boot, before the filtering engine fully starts and hands off to
	// the normal runtime rules.
	BootTime bool

	// Provider optionally identifies the Provider that manages this
	// rule.
	Provider ProviderID
	// ProviderData is optional opaque data that can be held on behalf
	// of the Provider.
	ProviderData []byte

	// Disabled indicates whether the rule is currently disabled due
	// to its provider being associated with an inactive Windows
	// service. See Provider.ServiceName for details.
	Disabled bool
}

// TODO: figure out what currently unexposed flags do: Indexed
// TODO: figure out what ProviderContextKey is about. MSDN doesn't explain what contexts are.

func (s *Session) Rules() ([]*Rule, error) { // TODO: support filter settings
	var enum windows.Handle
	if err := fwpmFilterCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		return nil, err
	}
	defer fwpmFilterDestroyEnumHandle0(s.handle, enum)

	var ret []*Rule

	for {
		rules, err := s.getRulePage(enum)
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 {
			return ret, nil
		}
		ret = append(ret, rules...)
	}
}

func (s *Session) getRulePage(enum windows.Handle) ([]*Rule, error) {
	const pageSize = 100
	var (
		array **fwpmFilter0
		num   uint32
	)
	if err := fwpmFilterEnum0(s.handle, enum, pageSize, &array, &num); err != nil {
		return nil, err
	}
	if num == 0 {
		return nil, nil
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&array)))

	return fromFilter0(array, num, s.layerTypes)
}

func (s *Session) AddRule(r *Rule) error {
	if r.ID.IsZero() {
		return errors.New("Provider.ID cannot be zero")
	}

	var a arena
	defer a.Dispose()

	f, err := toFilter0(&a, r, s.layerTypes)
	if err != nil {
		return err
	}
	if err := fwpmFilterAdd0(s.handle, f, nil, &f.FilterID); err != nil {
		return err
	}

	return nil
}

func (s *Session) DeleteRule(id RuleID) error {
	if id.IsZero() {
		return errors.New("GUID cannot be zero")
	}

	return fwpmFilterDeleteByKey0(s.handle, &id)
}

type DropEvent struct {
	Timestamp  time.Time
	IPProtocol uint8
	LocalAddr  netaddr.IPPort
	RemoteAddr netaddr.IPPort
	AppID      string

	LayerID  uint16
	FilterID uint64
}

func (s *Session) DropEvents() ([]*DropEvent, error) {
	var enum windows.Handle
	if err := fwpmNetEventCreateEnumHandle0(s.handle, nil, &enum); err != nil {
		return nil, err
	}
	defer fwpmNetEventDestroyEnumHandle0(s.handle, enum)

	var ret []*DropEvent

	for {
		events, err := s.getEventPage(enum)
		if err != nil {
			return nil, err
		}
		if len(events) == 0 {
			return ret, nil
		}
		ret = append(ret, events...)
	}
}

func (s *Session) getEventPage(enum windows.Handle) ([]*DropEvent, error) {
	const pageSize = 100
	var (
		array **fwpmNetEvent1
		num   uint32
	)
	if err := fwpmNetEventEnum1(s.handle, enum, pageSize, &array, &num); err != nil {
		return nil, err
	}
	if num == 0 {
		return nil, nil
	}
	defer fwpmFreeMemory0((*struct{})(unsafe.Pointer(&array)))

	return fromNetEvent1(array, num)
}
