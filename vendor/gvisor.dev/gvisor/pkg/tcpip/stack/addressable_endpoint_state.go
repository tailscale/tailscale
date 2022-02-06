// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var _ AddressableEndpoint = (*AddressableEndpointState)(nil)

// AddressableEndpointState is an implementation of an AddressableEndpoint.
type AddressableEndpointState struct {
	networkEndpoint NetworkEndpoint

	// Lock ordering (from outer to inner lock ordering):
	//
	// AddressableEndpointState.mu
	//   addressState.mu
	mu struct {
		sync.RWMutex

		endpoints map[tcpip.Address]*addressState
		primary   []*addressState
	}
}

// Init initializes the AddressableEndpointState with networkEndpoint.
//
// Must be called before calling any other function on m.
func (a *AddressableEndpointState) Init(networkEndpoint NetworkEndpoint) {
	a.networkEndpoint = networkEndpoint

	a.mu.Lock()
	defer a.mu.Unlock()
	a.mu.endpoints = make(map[tcpip.Address]*addressState)
}

// GetAddress returns the AddressEndpoint for the passed address.
//
// GetAddress does not increment the address's reference count or check if the
// address is considered bound to the endpoint.
//
// Returns nil if the passed address is not associated with the endpoint.
func (a *AddressableEndpointState) GetAddress(addr tcpip.Address) AddressEndpoint {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ep, ok := a.mu.endpoints[addr]
	if !ok {
		return nil
	}
	return ep
}

// ForEachEndpoint calls f for each address.
//
// Once f returns false, f will no longer be called.
func (a *AddressableEndpointState) ForEachEndpoint(f func(AddressEndpoint) bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, ep := range a.mu.endpoints {
		if !f(ep) {
			return
		}
	}
}

// ForEachPrimaryEndpoint calls f for each primary address.
//
// Once f returns false, f will no longer be called.
func (a *AddressableEndpointState) ForEachPrimaryEndpoint(f func(AddressEndpoint) bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, ep := range a.mu.primary {
		if !f(ep) {
			return
		}
	}
}

func (a *AddressableEndpointState) releaseAddressState(addrState *addressState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseAddressStateLocked(addrState)
}

// releaseAddressState removes addrState from s's address state (primary and endpoints list).
//
// Preconditions: a.mu must be write locked.
func (a *AddressableEndpointState) releaseAddressStateLocked(addrState *addressState) {
	oldPrimary := a.mu.primary
	for i, s := range a.mu.primary {
		if s == addrState {
			a.mu.primary = append(a.mu.primary[:i], a.mu.primary[i+1:]...)
			oldPrimary[len(oldPrimary)-1] = nil
			break
		}
	}
	delete(a.mu.endpoints, addrState.addr.Address)
}

// AddAndAcquirePermanentAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties AddressProperties) (AddressEndpoint, tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ep, err := a.addAndAcquireAddressLocked(addr, properties, true /* permanent */)
	// From https://golang.org/doc/faq#nil_error:
	//
	// Under the covers, interfaces are implemented as two elements, a type T and
	// a value V.
	//
	// An interface value is nil only if the V and T are both unset, (T=nil, V is
	// not set), In particular, a nil interface will always hold a nil type. If we
	// store a nil pointer of type *int inside an interface value, the inner type
	// will be *int regardless of the value of the pointer: (T=*int, V=nil). Such
	// an interface value will therefore be non-nil even when the pointer value V
	// inside is nil.
	//
	// Since addAndAcquireAddressLocked returns a nil value with a non-nil type,
	// we need to explicitly return nil below if ep is (a typed) nil.
	if ep == nil {
		return nil, err
	}
	return ep, err
}

// AddAndAcquireTemporaryAddress adds a temporary address.
//
// Returns *tcpip.ErrDuplicateAddress if the address exists.
//
// The temporary address's endpoint is acquired and returned.
func (a *AddressableEndpointState) AddAndAcquireTemporaryAddress(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior) (AddressEndpoint, tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ep, err := a.addAndAcquireAddressLocked(addr, AddressProperties{PEB: peb}, false /* permanent */)
	// From https://golang.org/doc/faq#nil_error:
	//
	// Under the covers, interfaces are implemented as two elements, a type T and
	// a value V.
	//
	// An interface value is nil only if the V and T are both unset, (T=nil, V is
	// not set), In particular, a nil interface will always hold a nil type. If we
	// store a nil pointer of type *int inside an interface value, the inner type
	// will be *int regardless of the value of the pointer: (T=*int, V=nil). Such
	// an interface value will therefore be non-nil even when the pointer value V
	// inside is nil.
	//
	// Since addAndAcquireAddressLocked returns a nil value with a non-nil type,
	// we need to explicitly return nil below if ep is (a typed) nil.
	if ep == nil {
		return nil, err
	}
	return ep, err
}

// addAndAcquireAddressLocked adds, acquires and returns a permanent or
// temporary address.
//
// If the addressable endpoint already has the address in a non-permanent state,
// and addAndAcquireAddressLocked is adding a permanent address, that address is
// promoted in place and its properties set to the properties provided. If the
// address already exists in any other state, then *tcpip.ErrDuplicateAddress is
// returned, regardless the kind of address that is being added.
//
// Precondition: a.mu must be write locked.
func (a *AddressableEndpointState) addAndAcquireAddressLocked(addr tcpip.AddressWithPrefix, properties AddressProperties, permanent bool) (*addressState, tcpip.Error) {
	// attemptAddToPrimary is false when the address is already in the primary
	// address list.
	attemptAddToPrimary := true
	addrState, ok := a.mu.endpoints[addr.Address]
	if ok {
		if !permanent {
			// We are adding a non-permanent address but the address exists. No need
			// to go any further since we can only promote existing temporary/expired
			// addresses to permanent.
			return nil, &tcpip.ErrDuplicateAddress{}
		}

		addrState.mu.Lock()
		if addrState.mu.kind.IsPermanent() {
			addrState.mu.Unlock()
			// We are adding a permanent address but a permanent address already
			// exists.
			return nil, &tcpip.ErrDuplicateAddress{}
		}

		if addrState.mu.refs == 0 {
			panic(fmt.Sprintf("found an address that should have been released (ref count == 0); address = %s", addrState.addr))
		}

		// We now promote the address.
		for i, s := range a.mu.primary {
			if s == addrState {
				switch properties.PEB {
				case CanBePrimaryEndpoint:
					// The address is already in the primary address list.
					attemptAddToPrimary = false
				case FirstPrimaryEndpoint:
					if i == 0 {
						// The address is already first in the primary address list.
						attemptAddToPrimary = false
					} else {
						a.mu.primary = append(a.mu.primary[:i], a.mu.primary[i+1:]...)
					}
				case NeverPrimaryEndpoint:
					a.mu.primary = append(a.mu.primary[:i], a.mu.primary[i+1:]...)
				default:
					panic(fmt.Sprintf("unrecognized primary endpoint behaviour = %d", properties.PEB))
				}
				break
			}
		}
	}

	if addrState == nil {
		addrState = &addressState{
			addressableEndpointState: a,
			addr:                     addr,
			// Cache the subnet in addrState to avoid calls to addr.Subnet() as that
			// results in allocations on every call.
			subnet: addr.Subnet(),
		}
		a.mu.endpoints[addr.Address] = addrState
		addrState.mu.Lock()
		// We never promote an address to temporary - it can only be added as such.
		// If we are actaully adding a permanent address, it is promoted below.
		addrState.mu.kind = Temporary
	}

	// At this point we have an address we are either promoting from an expired or
	// temporary address to permanent, promoting an expired address to temporary,
	// or we are adding a new temporary or permanent address.
	//
	// The address MUST be write locked at this point.
	defer addrState.mu.Unlock() // +checklocksforce

	if permanent {
		if addrState.mu.kind.IsPermanent() {
			panic(fmt.Sprintf("only non-permanent addresses should be promoted to permanent; address = %s", addrState.addr))
		}

		// Primary addresses are biased by 1.
		addrState.mu.refs++
		addrState.mu.kind = Permanent
	}
	// Acquire the address before returning it.
	addrState.mu.refs++
	addrState.mu.deprecated = properties.Deprecated
	addrState.mu.configType = properties.ConfigType

	if attemptAddToPrimary {
		switch properties.PEB {
		case NeverPrimaryEndpoint:
		case CanBePrimaryEndpoint:
			a.mu.primary = append(a.mu.primary, addrState)
		case FirstPrimaryEndpoint:
			if cap(a.mu.primary) == len(a.mu.primary) {
				a.mu.primary = append([]*addressState{addrState}, a.mu.primary...)
			} else {
				// Shift all the endpoints by 1 to make room for the new address at the
				// front. We could have just created a new slice but this saves
				// allocations when the slice has capacity for the new address.
				primaryCount := len(a.mu.primary)
				a.mu.primary = append(a.mu.primary, nil)
				if n := copy(a.mu.primary[1:], a.mu.primary); n != primaryCount {
					panic(fmt.Sprintf("copied %d elements; expected = %d elements", n, primaryCount))
				}
				a.mu.primary[0] = addrState
			}
		default:
			panic(fmt.Sprintf("unrecognized primary endpoint behaviour = %d", properties.PEB))
		}
	}

	return addrState, nil
}

// RemovePermanentAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) RemovePermanentAddress(addr tcpip.Address) tcpip.Error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.removePermanentAddressLocked(addr)
}

// removePermanentAddressLocked is like RemovePermanentAddress but with locking
// requirements.
//
// Precondition: a.mu must be write locked.
func (a *AddressableEndpointState) removePermanentAddressLocked(addr tcpip.Address) tcpip.Error {
	addrState, ok := a.mu.endpoints[addr]
	if !ok {
		return &tcpip.ErrBadLocalAddress{}
	}

	return a.removePermanentEndpointLocked(addrState)
}

// RemovePermanentEndpoint removes the passed endpoint if it is associated with
// a and permanent.
func (a *AddressableEndpointState) RemovePermanentEndpoint(ep AddressEndpoint) tcpip.Error {
	addrState, ok := ep.(*addressState)
	if !ok || addrState.addressableEndpointState != a {
		return &tcpip.ErrInvalidEndpointState{}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	return a.removePermanentEndpointLocked(addrState)
}

// removePermanentAddressLocked is like RemovePermanentAddress but with locking
// requirements.
//
// Precondition: a.mu must be write locked.
func (a *AddressableEndpointState) removePermanentEndpointLocked(addrState *addressState) tcpip.Error {
	if !addrState.GetKind().IsPermanent() {
		return &tcpip.ErrBadLocalAddress{}
	}

	addrState.SetKind(PermanentExpired)
	a.decAddressRefLocked(addrState)
	return nil
}

// decAddressRef decrements the address's reference count and releases it once
// the reference count hits 0.
func (a *AddressableEndpointState) decAddressRef(addrState *addressState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decAddressRefLocked(addrState)
}

// decAddressRefLocked is like decAddressRef but with locking requirements.
//
// Precondition: a.mu must be write locked.
func (a *AddressableEndpointState) decAddressRefLocked(addrState *addressState) {
	addrState.mu.Lock()
	defer addrState.mu.Unlock()

	if addrState.mu.refs == 0 {
		panic(fmt.Sprintf("attempted to decrease ref count for AddressEndpoint w/ addr = %s when it is already released", addrState.addr))
	}

	addrState.mu.refs--

	if addrState.mu.refs != 0 {
		return
	}

	// A non-expired permanent address must not have its reference count dropped
	// to 0.
	if addrState.mu.kind.IsPermanent() {
		panic(fmt.Sprintf("permanent addresses should be removed through the AddressableEndpoint: addr = %s, kind = %d", addrState.addr, addrState.mu.kind))
	}

	a.releaseAddressStateLocked(addrState)
}

// MainAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) MainAddress() tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ep := a.acquirePrimaryAddressRLocked(func(ep *addressState) bool {
		return ep.GetKind() == Permanent
	})
	if ep == nil {
		return tcpip.AddressWithPrefix{}
	}

	addr := ep.AddressWithPrefix()
	a.decAddressRefLocked(ep)
	return addr
}

// acquirePrimaryAddressRLocked returns an acquired primary address that is
// valid according to isValid.
//
// Precondition: e.mu must be read locked
func (a *AddressableEndpointState) acquirePrimaryAddressRLocked(isValid func(*addressState) bool) *addressState {
	var deprecatedEndpoint *addressState
	for _, ep := range a.mu.primary {
		if !isValid(ep) {
			continue
		}

		if !ep.Deprecated() {
			if ep.IncRef() {
				// ep is not deprecated, so return it immediately.
				//
				// If we kept track of a deprecated endpoint, decrement its reference
				// count since it was incremented when we decided to keep track of it.
				if deprecatedEndpoint != nil {
					a.decAddressRefLocked(deprecatedEndpoint)
					deprecatedEndpoint = nil
				}

				return ep
			}
		} else if deprecatedEndpoint == nil && ep.IncRef() {
			// We prefer an endpoint that is not deprecated, but we keep track of
			// ep in case a doesn't have any non-deprecated endpoints.
			//
			// If we end up finding a more preferred endpoint, ep's reference count
			// will be decremented.
			deprecatedEndpoint = ep
		}
	}

	return deprecatedEndpoint
}

// AcquireAssignedAddressOrMatching returns an address endpoint that is
// considered assigned to the addressable endpoint.
//
// If the address is an exact match with an existing address, that address is
// returned. Otherwise, if f is provided, f is called with each address and
// the address that f returns true for is returned.
//
// If there is no matching address, a temporary address will be returned if
// allowTemp is true.
//
// Regardless how the address was obtained, it will be acquired before it is
// returned.
func (a *AddressableEndpointState) AcquireAssignedAddressOrMatching(localAddr tcpip.Address, f func(AddressEndpoint) bool, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint {
	lookup := func() *addressState {
		if addrState, ok := a.mu.endpoints[localAddr]; ok {
			if !addrState.IsAssigned(allowTemp) {
				return nil
			}

			if !addrState.IncRef() {
				panic(fmt.Sprintf("failed to increase the reference count for address = %s", addrState.addr))
			}

			return addrState
		}

		if f != nil {
			for _, addrState := range a.mu.endpoints {
				if addrState.IsAssigned(allowTemp) && f(addrState) && addrState.IncRef() {
					return addrState
				}
			}
		}
		return nil
	}
	// Avoid exclusive lock on mu unless we need to add a new address.
	a.mu.RLock()
	ep := lookup()
	a.mu.RUnlock()

	if ep != nil {
		return ep
	}

	if !allowTemp {
		return nil
	}

	// Acquire state lock in exclusive mode as we need to add a new temporary
	// endpoint.
	a.mu.Lock()
	defer a.mu.Unlock()

	// Do the lookup again in case another goroutine added the address in the time
	// we released and acquired the lock.
	ep = lookup()
	if ep != nil {
		return ep
	}

	// Proceed to add a new temporary endpoint.
	addr := localAddr.WithPrefix()
	ep, err := a.addAndAcquireAddressLocked(addr, AddressProperties{PEB: tempPEB}, false /* permanent */)
	if err != nil {
		// addAndAcquireAddressLocked only returns an error if the address is
		// already assigned but we just checked above if the address exists so we
		// expect no error.
		panic(fmt.Sprintf("a.addAndAcquireAddressLocked(%s, AddressProperties{PEB: %s}, false): %s", addr, tempPEB, err))
	}

	// From https://golang.org/doc/faq#nil_error:
	//
	// Under the covers, interfaces are implemented as two elements, a type T and
	// a value V.
	//
	// An interface value is nil only if the V and T are both unset, (T=nil, V is
	// not set), In particular, a nil interface will always hold a nil type. If we
	// store a nil pointer of type *int inside an interface value, the inner type
	// will be *int regardless of the value of the pointer: (T=*int, V=nil). Such
	// an interface value will therefore be non-nil even when the pointer value V
	// inside is nil.
	//
	// Since addAndAcquireAddressLocked returns a nil value with a non-nil type,
	// we need to explicitly return nil below if ep is (a typed) nil.
	if ep == nil {
		return nil
	}
	return ep
}

// AcquireAssignedAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint {
	return a.AcquireAssignedAddressOrMatching(localAddr, nil, allowTemp, tempPEB)
}

// AcquireOutgoingPrimaryAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AcquireOutgoingPrimaryAddress(remoteAddr tcpip.Address, allowExpired bool) AddressEndpoint {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ep := a.acquirePrimaryAddressRLocked(func(ep *addressState) bool {
		return ep.IsAssigned(allowExpired)
	})

	// From https://golang.org/doc/faq#nil_error:
	//
	// Under the covers, interfaces are implemented as two elements, a type T and
	// a value V.
	//
	// An interface value is nil only if the V and T are both unset, (T=nil, V is
	// not set), In particular, a nil interface will always hold a nil type. If we
	// store a nil pointer of type *int inside an interface value, the inner type
	// will be *int regardless of the value of the pointer: (T=*int, V=nil). Such
	// an interface value will therefore be non-nil even when the pointer value V
	// inside is nil.
	//
	// Since acquirePrimaryAddressRLocked returns a nil value with a non-nil type,
	// we need to explicitly return nil below if ep is (a typed) nil.
	if ep == nil {
		return nil
	}

	return ep
}

// PrimaryAddresses implements AddressableEndpoint.
func (a *AddressableEndpointState) PrimaryAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	for _, ep := range a.mu.primary {
		// Don't include tentative, expired or temporary endpoints
		// to avoid confusion and prevent the caller from using
		// those.
		switch ep.GetKind() {
		case PermanentTentative, PermanentExpired, Temporary:
			continue
		}

		addrs = append(addrs, ep.AddressWithPrefix())
	}

	return addrs
}

// PermanentAddresses implements AddressableEndpoint.
func (a *AddressableEndpointState) PermanentAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	for _, ep := range a.mu.endpoints {
		if !ep.GetKind().IsPermanent() {
			continue
		}

		addrs = append(addrs, ep.AddressWithPrefix())
	}

	return addrs
}

// Cleanup forcefully leaves all groups and removes all permanent addresses.
func (a *AddressableEndpointState) Cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, ep := range a.mu.endpoints {
		// removePermanentEndpointLocked returns *tcpip.ErrBadLocalAddress if ep is
		// not a permanent address.
		switch err := a.removePermanentEndpointLocked(ep); err.(type) {
		case nil, *tcpip.ErrBadLocalAddress:
		default:
			panic(fmt.Sprintf("unexpected error from removePermanentEndpointLocked(%s): %s", ep.addr, err))
		}
	}
}

var _ AddressEndpoint = (*addressState)(nil)

// addressState holds state for an address.
type addressState struct {
	addressableEndpointState *AddressableEndpointState
	addr                     tcpip.AddressWithPrefix
	subnet                   tcpip.Subnet
	// Lock ordering (from outer to inner lock ordering):
	//
	// AddressableEndpointState.mu
	//   addressState.mu
	mu struct {
		sync.RWMutex

		refs       uint32
		kind       AddressKind
		configType AddressConfigType
		deprecated bool
	}
}

// AddressWithPrefix implements AddressEndpoint.
func (a *addressState) AddressWithPrefix() tcpip.AddressWithPrefix {
	return a.addr
}

// Subnet implements AddressEndpoint.
func (a *addressState) Subnet() tcpip.Subnet {
	return a.subnet
}

// GetKind implements AddressEndpoint.
func (a *addressState) GetKind() AddressKind {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mu.kind
}

// SetKind implements AddressEndpoint.
func (a *addressState) SetKind(kind AddressKind) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mu.kind = kind
}

// IsAssigned implements AddressEndpoint.
func (a *addressState) IsAssigned(allowExpired bool) bool {
	if !a.addressableEndpointState.networkEndpoint.Enabled() {
		return false
	}

	switch a.GetKind() {
	case PermanentTentative:
		return false
	case PermanentExpired:
		return allowExpired
	default:
		return true
	}
}

// IncRef implements AddressEndpoint.
func (a *addressState) IncRef() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mu.refs == 0 {
		return false
	}

	a.mu.refs++
	return true
}

// DecRef implements AddressEndpoint.
func (a *addressState) DecRef() {
	a.addressableEndpointState.decAddressRef(a)
}

// ConfigType implements AddressEndpoint.
func (a *addressState) ConfigType() AddressConfigType {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mu.configType
}

// SetDeprecated implements AddressEndpoint.
func (a *addressState) SetDeprecated(d bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mu.deprecated = d
}

// Deprecated implements AddressEndpoint.
func (a *addressState) Deprecated() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mu.deprecated
}
