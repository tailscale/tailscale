package appc

import (
	"errors"
	"sync"

	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
)

type PacketAction func(*packet.Parsed)

type FlowData struct {
	Tuple  flowtrack.Tuple
	Action PacketAction
}

type Origin uint8

const (
	FromTun Origin = iota
	FromWireguard
)

type cachedFlow struct {
	flow   FlowData
	paired flowtrack.Tuple // tuple for the other direction
	allow  Origin          // which lookup is allowed to hit this entry
}

var (
	FlowNotFoundError   = errors.New("flow not found")
	WrongDirectionError = errors.New("flow exists but wrong direction for lookup")
)

type FlowTable struct {
	mu  sync.Mutex
	lru flowtrack.Cache[cachedFlow] // guarded by mu
}

func NewFlowTable(maxEntries int) *FlowTable {
	t := &FlowTable{}
	t.lru.MaxEntries = maxEntries
	return t
}

func opposite(o Origin) Origin {
	if o == FromTun {
		return FromWireguard
	}
	return FromTun
}

// LookupFromTunDevice looks up a flow action that is valid to run for packets
// observed on the tun-device path.
func (t *FlowTable) LookupFromTunDevice(k flowtrack.Tuple) (FlowData, error) {
	return t.lookup(k, FromTun)
}

// LookupFromWireguard looks up a flow action that is valid to run for packets
// observed on the wireguard path.
func (t *FlowTable) LookupFromWireguard(k flowtrack.Tuple) (FlowData, error) {
	return t.lookup(k, FromWireguard)
}

func (t *FlowTable) lookup(k flowtrack.Tuple, want Origin) (FlowData, error) {
	t.mu.Lock()
	v, ok := t.lru.Get(k)
	if !ok {
		t.mu.Unlock()
		return FlowData{}, FlowNotFoundError
	}
	if v.allow != want {
		t.mu.Unlock()
		return FlowData{}, WrongDirectionError
	}
	out := v.flow // copy
	t.mu.Unlock()
	return out, nil
}

// NewFlowFromTunDevice installs (or overwrites) both the forward and return entries.
// The forward tuple is tagged as FromTun, and the return tuple is tagged as FromWireguard.
// If overwriting, it removes the old paired tuple for the forward key to avoid stale reverse mappings.
func (t *FlowTable) NewFlowFromTunDevice(fwd, ret FlowData) (FlowData, error) {
	return t.newFlow(FromTun, fwd, ret)
}

// NewFlowFromWireguard installs (or overwrites) both the forward and return entries,
// but tags the forward tuple as FromWireguard and the return tuple as FromTun.
// (Whether you *want* to allow installs from this direction is a separate policy question.)
func (t *FlowTable) NewFlowFromWireguard(fwd, ret FlowData) (FlowData, error) {
	return t.newFlow(FromWireguard, fwd, ret)
}

func (t *FlowTable) newFlow(primaryAllow Origin, fwd, ret FlowData) (FlowData, error) {
	t.mu.Lock()

	// If overwriting an existing primary entry, remove its previously-paired mapping so
	// we don't leave stale reverse tuples around.
	if old, ok := t.lru.Get(fwd.Tuple); ok && old != nil {
		t.lru.Remove(old.paired)
	}

	t.lru.Add(fwd.Tuple, cachedFlow{
		flow:   fwd,
		paired: ret.Tuple, allow: primaryAllow,
	})
	t.lru.Add(ret.Tuple, cachedFlow{
		flow:   ret,
		paired: fwd.Tuple,
		allow:  opposite(primaryAllow),
	})

	t.mu.Unlock()
	return fwd, nil
}
