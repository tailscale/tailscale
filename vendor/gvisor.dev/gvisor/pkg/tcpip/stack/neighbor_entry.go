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
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// immediateDuration is a duration of zero for scheduling work that needs to
	// be done immediately but asynchronously to avoid deadlock.
	immediateDuration time.Duration = 0
)

// NeighborEntry describes a neighboring device in the local network.
type NeighborEntry struct {
	Addr      tcpip.Address
	LinkAddr  tcpip.LinkAddress
	State     NeighborState
	UpdatedAt time.Time
}

// NeighborState defines the state of a NeighborEntry within the Neighbor
// Unreachability Detection state machine, as per RFC 4861 section 7.3.2 and
// RFC 7048.
type NeighborState uint8

const (
	// Unknown means reachability has not been verified yet. This is the initial
	// state of entries that have been created automatically by the Neighbor
	// Unreachability Detection state machine.
	Unknown NeighborState = iota
	// Incomplete means that there is an outstanding request to resolve the
	// address.
	Incomplete
	// Reachable means the path to the neighbor is functioning properly for both
	// receive and transmit paths.
	Reachable
	// Stale means reachability to the neighbor is unknown, but packets are still
	// able to be transmitted to the possibly stale link address.
	Stale
	// Delay means reachability to the neighbor is unknown and pending
	// confirmation from an upper-level protocol like TCP, but packets are still
	// able to be transmitted to the possibly stale link address.
	Delay
	// Probe means a reachability confirmation is actively being sought by
	// periodically retransmitting reachability probes until a reachability
	// confirmation is received, or until the maximum number of probes has been
	// sent.
	Probe
	// Static describes entries that have been explicitly added by the user. They
	// do not expire and are not deleted until explicitly removed.
	Static
	// Unreachable means reachability confirmation failed; the maximum number of
	// reachability probes has been sent and no replies have been received.
	//
	// TODO(gvisor.dev/issue/5472): Add the following sentence when we implement
	// RFC 7048: "Packets continue to be sent to the neighbor while
	// re-attempting to resolve the address."
	Unreachable
)

type timer struct {
	// done indicates to the timer that the timer was stopped.
	done *bool

	timer tcpip.Timer
}

// neighborEntry implements a neighbor entry's individual node behavior, as per
// RFC 4861 section 7.3.3. Neighbor Unreachability Detection operates in
// parallel with the sending of packets to a neighbor, necessitating the
// entry's lock to be acquired for all operations.
type neighborEntry struct {
	neighborEntryEntry

	cache *neighborCache

	// nudState points to the Neighbor Unreachability Detection configuration.
	nudState *NUDState

	mu struct {
		sync.RWMutex

		neigh NeighborEntry

		// done is closed when address resolution is complete. It is nil iff s is
		// incomplete and resolution is not yet in progress.
		done chan struct{}

		// onResolve is called with the result of address resolution.
		onResolve []func(LinkResolutionResult)

		isRouter bool

		timer timer
	}
}

// newNeighborEntry creates a neighbor cache entry starting at the default
// state, Unknown. Transition out of Unknown by calling either
// `handlePacketQueuedLocked` or `handleProbeLocked` on the newly created
// neighborEntry.
func newNeighborEntry(cache *neighborCache, remoteAddr tcpip.Address, nudState *NUDState) *neighborEntry {
	n := &neighborEntry{
		cache:    cache,
		nudState: nudState,
	}
	n.mu.Lock()
	n.mu.neigh = NeighborEntry{
		Addr:  remoteAddr,
		State: Unknown,
	}
	n.mu.Unlock()
	return n

}

// newStaticNeighborEntry creates a neighbor cache entry starting at the
// Static state. The entry can only transition out of Static by directly
// calling `setStateLocked`.
func newStaticNeighborEntry(cache *neighborCache, addr tcpip.Address, linkAddr tcpip.LinkAddress, state *NUDState) *neighborEntry {
	entry := NeighborEntry{
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     Static,
		UpdatedAt: cache.nic.stack.clock.Now(),
	}
	n := &neighborEntry{
		cache:    cache,
		nudState: state,
	}
	n.mu.Lock()
	n.mu.neigh = entry
	n.mu.Unlock()
	return n
}

// notifyCompletionLocked notifies those waiting for address resolution, with
// the link address if resolution completed successfully.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) notifyCompletionLocked(err tcpip.Error) {
	res := LinkResolutionResult{LinkAddress: e.mu.neigh.LinkAddr, Err: err}
	for _, callback := range e.mu.onResolve {
		callback(res)
	}
	e.mu.onResolve = nil
	if ch := e.mu.done; ch != nil {
		close(ch)
		e.mu.done = nil
		// Dequeue the pending packets asynchronously to not hold up the current
		// goroutine as writing packets may be a costly operation.
		//
		// At the time of writing, when writing packets, a neighbor's link address
		// is resolved (which ends up obtaining the entry's lock) while holding the
		// link resolution queue's lock. Dequeuing packets asynchronously avoids a
		// lock ordering violation.
		//
		// NB: this is equivalent to spawning a goroutine directly using the go
		// keyword but allows tests that use manual clocks to deterministically
		// wait for this work to complete.
		e.cache.nic.stack.clock.AfterFunc(0, func() {
			e.cache.nic.linkResQueue.dequeue(ch, e.mu.neigh.LinkAddr, err)
		})
	}
}

// dispatchAddEventLocked signals to stack's NUD Dispatcher that the entry has
// been added.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) dispatchAddEventLocked() {
	if nudDisp := e.cache.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborAdded(e.cache.nic.id, e.mu.neigh)
	}
}

// dispatchChangeEventLocked signals to stack's NUD Dispatcher that the entry
// has changed state or link-layer address.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) dispatchChangeEventLocked() {
	if nudDisp := e.cache.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborChanged(e.cache.nic.id, e.mu.neigh)
	}
}

// dispatchRemoveEventLocked signals to stack's NUD Dispatcher that the entry
// has been removed.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) dispatchRemoveEventLocked() {
	if nudDisp := e.cache.nic.stack.nudDisp; nudDisp != nil {
		nudDisp.OnNeighborRemoved(e.cache.nic.id, e.mu.neigh)
	}
}

// cancelTimerLocked cancels the currently scheduled action, if there is one.
// Entries in Unknown, Stale, or Static state do not have a scheduled action.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) cancelTimerLocked() {
	if e.mu.timer.timer != nil {
		e.mu.timer.timer.Stop()
		*e.mu.timer.done = true

		e.mu.timer = timer{}
	}
}

// removeLocked prepares the entry for removal.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) removeLocked() {
	e.mu.neigh.UpdatedAt = e.cache.nic.stack.clock.Now()
	e.dispatchRemoveEventLocked()
	e.cancelTimerLocked()
	// TODO(https://gvisor.dev/issues/5583): test the case where this function is
	// called during resolution; that can happen in at least these scenarios:
	//
	// - manual address removal during resolution
	//
	// - neighbor cache eviction during resolution
	e.notifyCompletionLocked(&tcpip.ErrAborted{})
}

// setStateLocked transitions the entry to the specified state immediately.
//
// Follows the logic defined in RFC 4861 section 7.3.3.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) setStateLocked(next NeighborState) {
	e.cancelTimerLocked()

	prev := e.mu.neigh.State
	e.mu.neigh.State = next
	e.mu.neigh.UpdatedAt = e.cache.nic.stack.clock.Now()
	config := e.nudState.Config()

	switch next {
	case Incomplete:
		panic(fmt.Sprintf("should never transition to Incomplete with setStateLocked; neigh = %#v, prev state = %s", e.mu.neigh, prev))

	case Reachable:
		// Protected by e.mu.
		done := false

		e.mu.timer = timer{
			done: &done,
			timer: e.cache.nic.stack.Clock().AfterFunc(e.nudState.ReachableTime(), func() {
				e.mu.Lock()
				defer e.mu.Unlock()

				if done {
					// The timer was stopped because the entry changed state.
					return
				}

				e.setStateLocked(Stale)
				e.dispatchChangeEventLocked()
			}),
		}

	case Delay:
		// Protected by e.mu.
		done := false

		e.mu.timer = timer{
			done: &done,
			timer: e.cache.nic.stack.Clock().AfterFunc(config.DelayFirstProbeTime, func() {
				e.mu.Lock()
				defer e.mu.Unlock()

				if done {
					// The timer was stopped because the entry changed state.
					return
				}

				e.setStateLocked(Probe)
				e.dispatchChangeEventLocked()
			}),
		}

	case Probe:
		// Protected by e.mu.
		done := false

		remaining := config.MaxUnicastProbes
		addr := e.mu.neigh.Addr
		linkAddr := e.mu.neigh.LinkAddr

		// Send a probe in another gorountine to free this thread of execution
		// for finishing the state transition. This is necessary to escape the
		// currently held lock so we can send the probe message without holding
		// a shared lock.
		e.mu.timer = timer{
			done: &done,
			timer: e.cache.nic.stack.Clock().AfterFunc(immediateDuration, func() {
				var err tcpip.Error = &tcpip.ErrTimeout{}
				if remaining != 0 {
					err = e.cache.linkRes.LinkAddressRequest(addr, "" /* localAddr */, linkAddr)
				}

				e.mu.Lock()
				defer e.mu.Unlock()

				if done {
					// The timer was stopped because the entry changed state.
					return
				}

				if err != nil {
					e.setStateLocked(Unreachable)
					e.notifyCompletionLocked(err)
					e.dispatchChangeEventLocked()
					return
				}

				remaining--
				e.mu.timer.timer.Reset(config.RetransmitTimer)
			}),
		}

	case Unreachable:

	case Unknown, Stale, Static:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid state transition from %q to %q", prev, next))
	}
}

// handlePacketQueuedLocked advances the state machine according to a packet
// being queued for outgoing transmission.
//
// Follows the logic defined in RFC 4861 section 7.3.3.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) handlePacketQueuedLocked(localAddr tcpip.Address) {
	switch e.mu.neigh.State {
	case Unknown, Unreachable:
		prev := e.mu.neigh.State
		e.mu.neigh.State = Incomplete
		e.mu.neigh.UpdatedAt = e.cache.nic.stack.clock.Now()

		switch prev {
		case Unknown:
			e.dispatchAddEventLocked()
		case Unreachable:
			e.dispatchChangeEventLocked()
			e.cache.nic.stats.neighbor.unreachableEntryLookups.Increment()
		}

		config := e.nudState.Config()

		// Protected by e.mu.
		done := false

		remaining := config.MaxMulticastProbes
		addr := e.mu.neigh.Addr

		// Send a probe in another gorountine to free this thread of execution
		// for finishing the state transition. This is necessary to escape the
		// currently held lock so we can send the probe message without holding
		// a shared lock.
		e.mu.timer = timer{
			done: &done,
			timer: e.cache.nic.stack.Clock().AfterFunc(immediateDuration, func() {
				var err tcpip.Error = &tcpip.ErrTimeout{}
				if remaining != 0 {
					// As per RFC 4861 section 7.2.2:
					//
					//  If the source address of the packet prompting the solicitation is
					//  the same as one of the addresses assigned to the outgoing interface,
					//  that address SHOULD be placed in the IP Source Address of the
					//  outgoing solicitation.
					//
					err = e.cache.linkRes.LinkAddressRequest(addr, localAddr, "" /* linkAddr */)
				}

				e.mu.Lock()
				defer e.mu.Unlock()

				if done {
					// The timer was stopped because the entry changed state.
					return
				}

				if err != nil {
					e.setStateLocked(Unreachable)
					e.notifyCompletionLocked(err)
					e.dispatchChangeEventLocked()
					return
				}

				remaining--
				e.mu.timer.timer.Reset(config.RetransmitTimer)
			}),
		}

	case Stale:
		e.setStateLocked(Delay)
		e.dispatchChangeEventLocked()

	case Incomplete, Reachable, Delay, Probe, Static:
		// Do nothing
	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.mu.neigh.State))
	}
}

// handleProbeLocked processes an incoming neighbor probe (e.g. ARP request or
// Neighbor Solicitation for ARP or NDP, respectively).
//
// Follows the logic defined in RFC 4861 section 7.2.3.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) handleProbeLocked(remoteLinkAddr tcpip.LinkAddress) {
	// Probes MUST be silently discarded if the target address is tentative, does
	// not exist, or not bound to the NIC as per RFC 4861 section 7.2.3. These
	// checks MUST be done by the NetworkEndpoint.

	switch e.mu.neigh.State {
	case Unknown:
		e.mu.neigh.LinkAddr = remoteLinkAddr
		e.setStateLocked(Stale)
		e.dispatchAddEventLocked()

	case Incomplete:
		// "If an entry already exists, and the cached link-layer address
		// differs from the one in the received Source Link-Layer option, the
		// cached address should be replaced by the received address, and the
		// entry's reachability state MUST be set to STALE."
		//  - RFC 4861 section 7.2.3
		e.mu.neigh.LinkAddr = remoteLinkAddr
		e.setStateLocked(Stale)
		e.notifyCompletionLocked(nil)
		e.dispatchChangeEventLocked()

	case Reachable, Delay, Probe:
		if e.mu.neigh.LinkAddr != remoteLinkAddr {
			e.mu.neigh.LinkAddr = remoteLinkAddr
			e.setStateLocked(Stale)
			e.dispatchChangeEventLocked()
		}

	case Stale:
		if e.mu.neigh.LinkAddr != remoteLinkAddr {
			e.mu.neigh.LinkAddr = remoteLinkAddr
			e.dispatchChangeEventLocked()
		}

	case Unreachable:
		// TODO(gvisor.dev/issue/5472): Do not change the entry if the link
		// address is the same, as per RFC 7048.
		e.mu.neigh.LinkAddr = remoteLinkAddr
		e.setStateLocked(Stale)
		e.dispatchChangeEventLocked()

	case Static:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.mu.neigh.State))
	}
}

// handleConfirmationLocked processes an incoming neighbor confirmation
// (e.g. ARP reply or Neighbor Advertisement for ARP or NDP, respectively).
//
// Follows the state machine defined by RFC 4861 section 7.2.5.
//
// TODO(gvisor.dev/issue/2277): To protect against ARP poisoning and other
// attacks against NDP functions, Secure Neighbor Discovery (SEND) Protocol
// should be deployed where preventing access to the broadcast segment might
// not be possible. SEND uses RSA key pairs to produce Cryptographically
// Generated Addresses (CGA), as defined in RFC 3972. This ensures that the
// claimed source of an NDP message is the owner of the claimed address.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) handleConfirmationLocked(linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags) {
	switch e.mu.neigh.State {
	case Incomplete:
		if len(linkAddr) == 0 {
			// "If the link layer has addresses and no Target Link-Layer Address
			// option is included, the receiving node SHOULD silently discard the
			// received advertisement." - RFC 4861 section 7.2.5
			break
		}

		e.mu.neigh.LinkAddr = linkAddr
		if flags.Solicited {
			e.setStateLocked(Reachable)
		} else {
			e.setStateLocked(Stale)
		}
		e.dispatchChangeEventLocked()
		e.mu.isRouter = flags.IsRouter
		e.notifyCompletionLocked(nil)

		// "Note that the Override flag is ignored if the entry is in the
		// INCOMPLETE state." - RFC 4861 section 7.2.5

	case Reachable, Stale, Delay, Probe:
		isLinkAddrDifferent := len(linkAddr) != 0 && e.mu.neigh.LinkAddr != linkAddr

		if isLinkAddrDifferent {
			if !flags.Override {
				if e.mu.neigh.State == Reachable {
					e.setStateLocked(Stale)
					e.dispatchChangeEventLocked()
				}
				break
			}

			e.mu.neigh.LinkAddr = linkAddr

			if !flags.Solicited {
				if e.mu.neigh.State != Stale {
					e.setStateLocked(Stale)
					e.dispatchChangeEventLocked()
				} else {
					// Notify the LinkAddr change, even though NUD state hasn't changed.
					e.dispatchChangeEventLocked()
				}
				break
			}
		}

		if flags.Solicited && (flags.Override || !isLinkAddrDifferent) {
			wasReachable := e.mu.neigh.State == Reachable
			// Set state to Reachable again to refresh timers.
			e.setStateLocked(Reachable)
			e.notifyCompletionLocked(nil)
			if !wasReachable {
				e.dispatchChangeEventLocked()
			}
		}

		if e.mu.isRouter && !flags.IsRouter && header.IsV6UnicastAddress(e.mu.neigh.Addr) {
			// "In those cases where the IsRouter flag changes from TRUE to FALSE as
			// a result of this update, the node MUST remove that router from the
			// Default Router List and update the Destination Cache entries for all
			// destinations using that neighbor as a router as specified in Section
			// 7.3.3.  This is needed to detect when a node that is used as a router
			// stops forwarding packets due to being configured as a host."
			//  - RFC 4861 section 7.2.5
			//
			// TODO(gvisor.dev/issue/4085): Remove the special casing we do for IPv6
			// here.
			ep, ok := e.cache.nic.networkEndpoints[header.IPv6ProtocolNumber]
			if !ok {
				panic(fmt.Sprintf("have a neighbor entry for an IPv6 router but no IPv6 network endpoint"))
			}

			if ndpEP, ok := ep.(NDPEndpoint); ok {
				ndpEP.InvalidateDefaultRouter(e.mu.neigh.Addr)
			}
		}
		e.mu.isRouter = flags.IsRouter

	case Unknown, Unreachable, Static:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.mu.neigh.State))
	}
}

// handleUpperLevelConfirmationLocked processes an incoming upper-level protocol
// (e.g. TCP acknowledgements) reachability confirmation.
//
// Precondition: e.mu MUST be locked.
func (e *neighborEntry) handleUpperLevelConfirmationLocked() {
	switch e.mu.neigh.State {
	case Reachable, Stale, Delay, Probe:
		wasReachable := e.mu.neigh.State == Reachable
		// Set state to Reachable again to refresh timers.
		e.setStateLocked(Reachable)
		if !wasReachable {
			e.dispatchChangeEventLocked()
		}

	case Unknown, Incomplete, Unreachable, Static:
		// Do nothing

	default:
		panic(fmt.Sprintf("Invalid cache entry state: %s", e.mu.neigh.State))
	}
}
