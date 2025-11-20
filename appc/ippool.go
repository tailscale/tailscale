// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"errors"
	"net/netip"

	"go4.org/netipx"
)

// errPoolExhausted is returned when there are no more addresses to iterate over.
var errPoolExhausted = errors.New("ip pool exhausted")

// ippool allows for iteration over all the addresses within a netipx.IPSet.
// netipx.IPSet has a Ranges call that returns the "minimum and sorted set of IP ranges that covers [the set]".
// netipx.IPRange is "an inclusive range of IP addresses from the same address family.". So we can iterate over
// all the addresses in the set by keeping a track of the last address we returned, calling Next on the last address
// to get the new one, and if we run off the edge of the current range, starting on the next one.
type ippool struct {
	// ranges defines the addresses in the pool
	ranges []netipx.IPRange
	// last is internal tracking of which the last address provided was.
	last netip.Addr
	// rangeIdx is internal tracking of which netipx.IPRange from the IPSet we are currently on.
	rangeIdx int
}

func newIPPool(ipset *netipx.IPSet) *ippool {
	if ipset == nil {
		return &ippool{}
	}
	return &ippool{ranges: ipset.Ranges()}
}

// next returns the next address from the set, or errPoolExhausted if we have
// iterated over the whole set.
func (ipp *ippool) next() (netip.Addr, error) {
	if ipp.rangeIdx >= len(ipp.ranges) {
		// ipset is empty or we have iterated off the end
		return netip.Addr{}, errPoolExhausted
	}
	if !ipp.last.IsValid() {
		// not initialized yet
		ipp.last = ipp.ranges[0].From()
		return ipp.last, nil
	}
	currRange := ipp.ranges[ipp.rangeIdx]
	if ipp.last == currRange.To() {
		// then we need to move to the next range
		ipp.rangeIdx++
		if ipp.rangeIdx >= len(ipp.ranges) {
			return netip.Addr{}, errPoolExhausted
		}
		ipp.last = ipp.ranges[ipp.rangeIdx].From()
		return ipp.last, nil
	}
	ipp.last = ipp.last.Next()
	return ipp.last, nil
}
