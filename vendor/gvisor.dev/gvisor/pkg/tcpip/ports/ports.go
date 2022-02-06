// Copyright 2018 The gVisor Authors.
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

// Package ports provides PortManager that manages allocating, reserving and
// releasing ports.
package ports

import (
	"math"
	"math/rand"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	firstEphemeral               = 16000
	anyIPAddress   tcpip.Address = ""
)

// Reservation describes a port reservation.
type Reservation struct {
	// Networks is a list of network protocols to which the reservation
	// applies. Can be IPv4, IPv6, or both.
	Networks []tcpip.NetworkProtocolNumber

	// Transport is the transport protocol to which the reservation applies.
	Transport tcpip.TransportProtocolNumber

	// Addr is the address of the local endpoint.
	Addr tcpip.Address

	// Port is the local port number.
	Port uint16

	// Flags describe features of the reservation.
	Flags Flags

	// BindToDevice is the NIC to which the reservation applies.
	BindToDevice tcpip.NICID

	// Dest is the destination address.
	Dest tcpip.FullAddress
}

func (rs Reservation) dst() destination {
	return destination{
		rs.Dest.Addr,
		rs.Dest.Port,
	}
}

type portDescriptor struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
	port      uint16
}

type destination struct {
	addr tcpip.Address
	port uint16
}

// destToCounter maps each destination to the FlagCounter that represents
// endpoints to that destination.
//
// destToCounter is never empty. When it has no elements, it is removed from
// the map that references it.
type destToCounter map[destination]FlagCounter

// intersectionFlags calculates the intersection of flag bit values which affect
// the specified destination.
//
// If no destinations are present, all flag values are returned as there are no
// entries to limit possible flag values of a new entry.
//
// In addition to the intersection, the number of intersecting refs is
// returned.
func (dc destToCounter) intersectionFlags(res Reservation) (BitFlags, int) {
	intersection := FlagMask
	var count int

	for dest, counter := range dc {
		if dest == res.dst() {
			intersection &= counter.SharedFlags()
			count++
			continue
		}
		// Wildcard destinations affect all destinations for TupleOnly.
		if dest.addr == anyIPAddress || res.Dest.Addr == anyIPAddress {
			// Only bitwise and the TupleOnlyFlag.
			intersection &= (^TupleOnlyFlag) | counter.SharedFlags()
			count++
		}
	}

	return intersection, count
}

// deviceToDest maps NICs to destinations for which there are port reservations.
//
// deviceToDest is never empty. When it has no elements, it is removed from the
// map that references it.
type deviceToDest map[tcpip.NICID]destToCounter

// isAvailable checks whether binding is possible by device. If not binding to
// a device, check against all FlagCounters. If binding to a specific device,
// check against the unspecified device and the provided device.
//
// If either of the port reuse flags is enabled on any of the nodes, all nodes
// sharing a port must share at least one reuse flag. This matches Linux's
// behavior.
func (dd deviceToDest) isAvailable(res Reservation, portSpecified bool) bool {
	flagBits := res.Flags.Bits()
	if res.BindToDevice == 0 {
		intersection := FlagMask
		for _, dest := range dd {
			flags, count := dest.intersectionFlags(res)
			if count == 0 {
				continue
			}
			intersection &= flags
			if intersection&flagBits == 0 {
				// Can't bind because the (addr,port) was
				// previously bound without reuse.
				return false
			}
		}
		if !portSpecified && res.Transport == header.TCPProtocolNumber {
			return false
		}
		return true
	}

	intersection := FlagMask

	if dests, ok := dd[0]; ok {
		var count int
		intersection, count = dests.intersectionFlags(res)
		if count > 0 {
			if intersection&flagBits == 0 {
				return false
			}
			if !portSpecified && res.Transport == header.TCPProtocolNumber {
				return false
			}
		}
	}

	if dests, ok := dd[res.BindToDevice]; ok {
		flags, count := dests.intersectionFlags(res)
		intersection &= flags
		if count > 0 {
			if intersection&flagBits == 0 {
				return false
			}
			if !portSpecified && res.Transport == header.TCPProtocolNumber {
				return false
			}
		}
	}

	return true
}

// addrToDevice maps IP addresses to NICs that have port reservations.
type addrToDevice map[tcpip.Address]deviceToDest

// isAvailable checks whether an IP address is available to bind to. If the
// address is the "any" address, check all other addresses. Otherwise, just
// check against the "any" address and the provided address.
func (ad addrToDevice) isAvailable(res Reservation, portSpecified bool) bool {
	if res.Addr == anyIPAddress {
		// If binding to the "any" address then check that there are no
		// conflicts with all addresses.
		for _, devices := range ad {
			if !devices.isAvailable(res, portSpecified) {
				return false
			}
		}
		return true
	}

	// Check that there is no conflict with the "any" address.
	if devices, ok := ad[anyIPAddress]; ok {
		if !devices.isAvailable(res, portSpecified) {
			return false
		}
	}

	// Check that this is no conflict with the provided address.
	if devices, ok := ad[res.Addr]; ok {
		if !devices.isAvailable(res, portSpecified) {
			return false
		}
	}

	return true
}

// PortManager manages allocating, reserving and releasing ports.
type PortManager struct {
	// mu protects allocatedPorts.
	// LOCK ORDERING: mu > ephemeralMu.
	mu sync.RWMutex
	// allocatedPorts is a nesting of maps that ultimately map Reservations
	// to FlagCounters describing whether the Reservation is valid and can
	// be reused.
	allocatedPorts map[portDescriptor]addrToDevice

	// ephemeralMu protects firstEphemeral and numEphemeral.
	ephemeralMu    sync.RWMutex
	firstEphemeral uint16
	numEphemeral   uint16

	// hint is used to pick ports ephemeral ports in a stable order for
	// a given port offset.
	//
	// hint must be accessed using the portHint/incPortHint helpers.
	// TODO(gvisor.dev/issue/940): S/R this field.
	hint uint32
}

// NewPortManager creates new PortManager.
func NewPortManager() *PortManager {
	return &PortManager{
		allocatedPorts: make(map[portDescriptor]addrToDevice),
		firstEphemeral: firstEphemeral,
		numEphemeral:   math.MaxUint16 - firstEphemeral + 1,
	}
}

// PortTester indicates whether the passed in port is suitable. Returning an
// error causes the function to which the PortTester is passed to return that
// error.
type PortTester func(port uint16) (good bool, err tcpip.Error)

// PickEphemeralPort randomly chooses a starting point and iterates over all
// possible ephemeral ports, allowing the caller to decide whether a given port
// is suitable for its needs, and stopping when a port is found or an error
// occurs.
func (pm *PortManager) PickEphemeralPort(rng *rand.Rand, testPort PortTester) (port uint16, err tcpip.Error) {
	pm.ephemeralMu.RLock()
	firstEphemeral := pm.firstEphemeral
	numEphemeral := pm.numEphemeral
	pm.ephemeralMu.RUnlock()

	offset := uint32(rng.Int31n(int32(numEphemeral)))
	return pickEphemeralPort(offset, firstEphemeral, numEphemeral, testPort)
}

// portHint atomically reads and returns the pm.hint value.
func (pm *PortManager) portHint() uint32 {
	return atomic.LoadUint32(&pm.hint)
}

// incPortHint atomically increments pm.hint by 1.
func (pm *PortManager) incPortHint() {
	atomic.AddUint32(&pm.hint, 1)
}

// PickEphemeralPortStable starts at the specified offset + pm.portHint and
// iterates over all ephemeral ports, allowing the caller to decide whether a
// given port is suitable for its needs and stopping when a port is found or an
// error occurs.
func (pm *PortManager) PickEphemeralPortStable(offset uint32, testPort PortTester) (port uint16, err tcpip.Error) {
	pm.ephemeralMu.RLock()
	firstEphemeral := pm.firstEphemeral
	numEphemeral := pm.numEphemeral
	pm.ephemeralMu.RUnlock()

	p, err := pickEphemeralPort(pm.portHint()+offset, firstEphemeral, numEphemeral, testPort)
	if err == nil {
		pm.incPortHint()
	}
	return p, err
}

// pickEphemeralPort starts at the offset specified from the FirstEphemeral port
// and iterates over the number of ports specified by count and allows the
// caller to decide whether a given port is suitable for its needs, and stopping
// when a port is found or an error occurs.
func pickEphemeralPort(offset uint32, first, count uint16, testPort PortTester) (port uint16, err tcpip.Error) {
	for i := uint32(0); i < uint32(count); i++ {
		port := uint16(uint32(first) + (offset+i)%uint32(count))
		ok, err := testPort(port)
		if err != nil {
			return 0, err
		}

		if ok {
			return port, nil
		}
	}

	return 0, &tcpip.ErrNoPortAvailable{}
}

// ReservePort marks a port/IP combination as reserved so that it cannot be
// reserved by another endpoint. If port is zero, ReservePort will search for
// an unreserved ephemeral port and reserve it, returning its value in the
// "port" return value.
//
// An optional PortTester can be passed in which if provided will be used to
// test if the picked port can be used. The function should return true if the
// port is safe to use, false otherwise.
func (pm *PortManager) ReservePort(rng *rand.Rand, res Reservation, testPort PortTester) (reservedPort uint16, err tcpip.Error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// If a port is specified, just try to reserve it for all network
	// protocols.
	if res.Port != 0 {
		if !pm.reserveSpecificPortLocked(res, true /* portSpecified */) {
			return 0, &tcpip.ErrPortInUse{}
		}
		if testPort != nil {
			ok, err := testPort(res.Port)
			if err != nil {
				pm.releasePortLocked(res)
				return 0, err
			}
			if !ok {
				pm.releasePortLocked(res)
				return 0, &tcpip.ErrPortInUse{}
			}
		}
		return res.Port, nil
	}

	// A port wasn't specified, so try to find one.
	return pm.PickEphemeralPort(rng, func(p uint16) (bool, tcpip.Error) {
		res.Port = p
		if !pm.reserveSpecificPortLocked(res, false /* portSpecified */) {
			return false, nil
		}
		if testPort != nil {
			ok, err := testPort(p)
			if err != nil {
				pm.releasePortLocked(res)
				return false, err
			}
			if !ok {
				pm.releasePortLocked(res)
				return false, nil
			}
		}
		return true, nil
	})
}

// reserveSpecificPortLocked tries to reserve the given port on all given
// protocols.
func (pm *PortManager) reserveSpecificPortLocked(res Reservation, portSpecified bool) bool {
	// Make sure the port is available.
	for _, network := range res.Networks {
		desc := portDescriptor{network, res.Transport, res.Port}
		if addrs, ok := pm.allocatedPorts[desc]; ok {
			if !addrs.isAvailable(res, portSpecified) {
				return false
			}
		}
	}

	// Reserve port on all network protocols.
	flagBits := res.Flags.Bits()
	dst := res.dst()
	for _, network := range res.Networks {
		desc := portDescriptor{network, res.Transport, res.Port}
		addrToDev, ok := pm.allocatedPorts[desc]
		if !ok {
			addrToDev = make(addrToDevice)
			pm.allocatedPorts[desc] = addrToDev
		}
		devToDest, ok := addrToDev[res.Addr]
		if !ok {
			devToDest = make(deviceToDest)
			addrToDev[res.Addr] = devToDest
		}
		destToCntr := devToDest[res.BindToDevice]
		if destToCntr == nil {
			destToCntr = make(destToCounter)
		}
		counter := destToCntr[dst]
		counter.AddRef(flagBits)
		destToCntr[dst] = counter
		devToDest[res.BindToDevice] = destToCntr
	}

	return true
}

// ReserveTuple adds a port reservation for the tuple on all given protocol.
func (pm *PortManager) ReserveTuple(res Reservation) bool {
	flagBits := res.Flags.Bits()
	dst := res.dst()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// It is easier to undo the entire reservation, so if we find that the
	// tuple can't be fully added, finish and undo the whole thing.
	undo := false

	// Reserve port on all network protocols.
	for _, network := range res.Networks {
		desc := portDescriptor{network, res.Transport, res.Port}
		addrToDev, ok := pm.allocatedPorts[desc]
		if !ok {
			addrToDev = make(addrToDevice)
			pm.allocatedPorts[desc] = addrToDev
		}
		devToDest, ok := addrToDev[res.Addr]
		if !ok {
			devToDest = make(deviceToDest)
			addrToDev[res.Addr] = devToDest
		}
		destToCntr := devToDest[res.BindToDevice]
		if destToCntr == nil {
			destToCntr = make(destToCounter)
		}

		counter := destToCntr[dst]
		if counter.TotalRefs() != 0 && counter.SharedFlags()&flagBits == 0 {
			// Tuple already exists.
			undo = true
		}
		counter.AddRef(flagBits)
		destToCntr[dst] = counter
		devToDest[res.BindToDevice] = destToCntr
	}

	if undo {
		// releasePortLocked decrements the counts (rather than setting
		// them to zero), so it will undo the incorrect incrementing
		// above.
		pm.releasePortLocked(res)
		return false
	}

	return true
}

// ReleasePort releases the reservation on a port/IP combination so that it can
// be reserved by other endpoints.
func (pm *PortManager) ReleasePort(res Reservation) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.releasePortLocked(res)
}

func (pm *PortManager) releasePortLocked(res Reservation) {
	dst := res.dst()
	for _, network := range res.Networks {
		desc := portDescriptor{network, res.Transport, res.Port}
		addrToDev, ok := pm.allocatedPorts[desc]
		if !ok {
			continue
		}
		devToDest, ok := addrToDev[res.Addr]
		if !ok {
			continue
		}
		destToCounter, ok := devToDest[res.BindToDevice]
		if !ok {
			continue
		}
		counter, ok := destToCounter[dst]
		if !ok {
			continue
		}
		counter.DropRef(res.Flags.Bits())
		if counter.TotalRefs() > 0 {
			destToCounter[dst] = counter
			continue
		}
		delete(destToCounter, dst)
		if len(destToCounter) > 0 {
			continue
		}
		delete(devToDest, res.BindToDevice)
		if len(devToDest) > 0 {
			continue
		}
		delete(addrToDev, res.Addr)
		if len(addrToDev) > 0 {
			continue
		}
		delete(pm.allocatedPorts, desc)
	}
}

// PortRange returns the UDP and TCP inclusive range of ephemeral ports used in
// both IPv4 and IPv6.
func (pm *PortManager) PortRange() (uint16, uint16) {
	pm.ephemeralMu.RLock()
	defer pm.ephemeralMu.RUnlock()
	return pm.firstEphemeral, pm.firstEphemeral + pm.numEphemeral - 1
}

// SetPortRange sets the UDP and TCP IPv4 and IPv6 ephemeral port range
// (inclusive).
func (pm *PortManager) SetPortRange(start uint16, end uint16) tcpip.Error {
	if start > end {
		return &tcpip.ErrInvalidPortRange{}
	}
	pm.ephemeralMu.Lock()
	defer pm.ephemeralMu.Unlock()
	pm.firstEphemeral = start
	pm.numEphemeral = end - start + 1
	return nil
}
