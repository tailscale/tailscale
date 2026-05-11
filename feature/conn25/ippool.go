// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"errors"
	"net/netip"

	"go4.org/netipx"
	"tailscale.com/util/set"
)

// errPoolExhausted is returned when there are no more addresses to iterate over.
var errPoolExhausted = errors.New("ip pool exhausted")

// errNotOurAddress is returned if a provided address is not from our pool
var errNotOurAddress = errors.New("not our address")

// errAddrExists is returned if a returned address is already in the returned pool.
var errAddrExists = errors.New("address already returned")

// errUninitializedIPPool is returned if the pool is used when it's not initialized
var errUninitializedIPPool = errors.New("uninitialized ippool")

// ipSetIterator allows for round robin iteration over all the addresses within a netipx.IPSet.
// netipx.IPSet has a Ranges call that returns the "minimum and sorted set of IP ranges that covers [the set]".
// netipx.IPRange is "an inclusive range of IP addresses from the same address family.". So we can iterate over
// all the addresses in the set by keeping a track of the last address we returned, calling Next on the last address
// to get the new one, and if we run off the edge of the current range, starting on the next one, or back at the beginning.
type ipSetIterator struct {
	// ranges defines the addresses in the pool
	ranges []netipx.IPRange
	// last is internal tracking of which the last address provided was.
	last netip.Addr
	// rangeIdx is internal tracking of which netipx.IPRange from the IPSet we are currently on.
	rangeIdx int
}

// next returns the next address from the set.
func (ipsi *ipSetIterator) next() (netip.Addr, error) {
	if len(ipsi.ranges) == 0 {
		// ipset is empty
		return netip.Addr{}, errPoolExhausted
	}
	if !ipsi.last.IsValid() {
		// not initialized yet
		ipsi.last = ipsi.ranges[0].From()
		return ipsi.last, nil
	}
	currRange := ipsi.ranges[ipsi.rangeIdx]
	if ipsi.last == currRange.To() {
		// then we need to move to the next range
		ipsi.rangeIdx++
		if ipsi.rangeIdx >= len(ipsi.ranges) {
			// back to the beginning
			ipsi.rangeIdx = 0
		}
		ipsi.last = ipsi.ranges[ipsi.rangeIdx].From()
		return ipsi.last, nil
	}
	ipsi.last = ipsi.last.Next()
	return ipsi.last, nil
}

func newIPPool(ipset *netipx.IPSet) *ippool {
	if ipset == nil {
		return &ippool{}
	}
	return &ippool{
		ipSet:         ipset,
		ipSetIterator: &ipSetIterator{ranges: ipset.Ranges()},
		inUse:         &set.Set[netip.Addr]{},
	}
}

type ippool struct {
	// ipSet defines the addresses within the ippool, it is configured by the user.
	ipSet *netipx.IPSet
	// ipSetIterator keeps track of iteration through the ippool.
	ipSetIterator *ipSetIterator
	// inUse is a set of addresses that have been handed out and not yet returned.
	// Addresses in inUse won't be returned from next.
	// Addresses in inUse may no longer be in the ipSet definition of the pool bounds
	// if the ippool has been reconfigured.
	inUse *set.Set[netip.Addr]
}

// next returns the next available address from within the ippool.
// next will return errPoolExhausted if there are no more unused addresses.
func (ipp *ippool) next() (netip.Addr, error) {
	if ipp == nil || ipp.ipSetIterator == nil {
		return netip.Addr{}, errUninitializedIPPool
	}
	a, err := ipp.ipSetIterator.next()
	if err != nil {
		return netip.Addr{}, err
	}
	startedAt := a
	for ipp.inUse.Contains(a) {
		a, err = ipp.ipSetIterator.next()
		if err != nil {
			return a, err
		}
		if a == startedAt {
			return netip.Addr{}, errPoolExhausted
		}
	}
	ipp.inUse.Add(a)
	return a, nil
}

// returnAddr puts an address back into the ippool, that address will
// now be available to be handed out when we iterate back around to it.
// returnAddr will return an error if the provided address is not one
// that's currently in inUse.
func (ipp *ippool) returnAddr(a netip.Addr) error {
	if ipp.inUse.Contains(a) {
		ipp.inUse.Delete(a)
		return nil
	}
	if !ipp.ipSet.Contains(a) {
		return errNotOurAddress
	}
	return errAddrExists
}

// reconfig changes the definition of the addresses that are in the ippool
// while keeping track of the addresses that are currently in inUse.
func (ipp *ippool) reconfig(ipSet *netipx.IPSet) *ippool {
	if ipp != nil && ipSet != nil && ipSet.Equal(ipp.ipSet) {
		// in the common case that the definition has not changed, do nothing.
		return ipp
	}
	newPool := newIPPool(ipSet)
	if ipp != nil {
		// even if the definition of which addresses are in the pool has changed
		// we don't want to lose track of which addresses are currently in use
		newPool.inUse = ipp.inUse
	}
	return newPool
}
