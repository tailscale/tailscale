// Copyright 2021 The gVisor Authors.
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

// Package ip holds IPv4/IPv6 common utilities.
package ip

import (
	"bytes"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type extendRequest int

const (
	notRequested extendRequest = iota
	requested
	extended
)

type dadState struct {
	nonce         []byte
	extendRequest extendRequest

	done  *bool
	timer tcpip.Timer

	completionHandlers []stack.DADCompletionHandler
}

// DADProtocol is a protocol whose core state machine can be represented by DAD.
type DADProtocol interface {
	// SendDADMessage attempts to send a DAD probe message.
	SendDADMessage(tcpip.Address, []byte) tcpip.Error
}

// DADOptions holds options for DAD.
type DADOptions struct {
	Clock              tcpip.Clock
	SecureRNG          io.Reader
	NonceSize          uint8
	ExtendDADTransmits uint8
	Protocol           DADProtocol
	NICID              tcpip.NICID
}

// DAD performs duplicate address detection for addresses.
type DAD struct {
	opts    DADOptions
	configs stack.DADConfigurations

	protocolMU sync.Locker
	addresses  map[tcpip.Address]dadState
}

// Init initializes the DAD state.
//
// Must only be called once for the lifetime of d; Init will panic if it is
// called twice.
//
// The lock will only be taken when timers fire.
func (d *DAD) Init(protocolMU sync.Locker, configs stack.DADConfigurations, opts DADOptions) {
	if d.addresses != nil {
		panic("attempted to initialize DAD state twice")
	}

	if opts.NonceSize != 0 && opts.ExtendDADTransmits == 0 {
		panic(fmt.Sprintf("given a non-zero value for NonceSize (%d) but zero for ExtendDADTransmits", opts.NonceSize))
	}

	configs.Validate()

	*d = DAD{
		opts:       opts,
		configs:    configs,
		protocolMU: protocolMU,
		addresses:  make(map[tcpip.Address]dadState),
	}
}

// CheckDuplicateAddressLocked performs DAD for an address, calling the
// completion handler once DAD resolves.
//
// If DAD is already performing for the provided address, h will be called when
// the currently running process completes.
//
// Precondition: d.protocolMU must be locked.
func (d *DAD) CheckDuplicateAddressLocked(addr tcpip.Address, h stack.DADCompletionHandler) stack.DADCheckAddressDisposition {
	if d.configs.DupAddrDetectTransmits == 0 {
		return stack.DADDisabled
	}

	ret := stack.DADAlreadyRunning
	s, ok := d.addresses[addr]
	if !ok {
		ret = stack.DADStarting

		remaining := d.configs.DupAddrDetectTransmits

		// Protected by d.protocolMU.
		done := false

		s = dadState{
			done: &done,
			timer: d.opts.Clock.AfterFunc(0, func() {
				dadDone := remaining == 0

				nonce, earlyReturn := func() ([]byte, bool) {
					d.protocolMU.Lock()
					defer d.protocolMU.Unlock()

					if done {
						return nil, true
					}

					s, ok := d.addresses[addr]
					if !ok {
						panic(fmt.Sprintf("dad: timer fired but missing state for %s on NIC(%d)", addr, d.opts.NICID))
					}

					// As per RFC 7527 section 4
					//
					//   If any probe is looped back within RetransTimer milliseconds
					//   after having sent DupAddrDetectTransmits NS(DAD) messages, the
					//   interface continues with another MAX_MULTICAST_SOLICIT number of
					//   NS(DAD) messages transmitted RetransTimer milliseconds apart.
					if dadDone && s.extendRequest == requested {
						dadDone = false
						remaining = d.opts.ExtendDADTransmits
						s.extendRequest = extended
					}

					if !dadDone && d.opts.NonceSize != 0 {
						if s.nonce == nil {
							s.nonce = make([]byte, d.opts.NonceSize)
						}

						if n, err := io.ReadFull(d.opts.SecureRNG, s.nonce); err != nil {
							panic(fmt.Sprintf("SecureRNG.Read(...): %s", err))
						} else if n != len(s.nonce) {
							panic(fmt.Sprintf("expected to read %d bytes from secure RNG, only read %d bytes", len(s.nonce), n))
						}
					}

					d.addresses[addr] = s
					return s.nonce, false
				}()
				if earlyReturn {
					return
				}

				var err tcpip.Error
				if !dadDone {
					err = d.opts.Protocol.SendDADMessage(addr, nonce)
				}

				d.protocolMU.Lock()
				defer d.protocolMU.Unlock()

				if done {
					return
				}

				s, ok := d.addresses[addr]
				if !ok {
					panic(fmt.Sprintf("dad: timer fired but missing state for %s on NIC(%d)", addr, d.opts.NICID))
				}

				if !dadDone && err == nil {
					remaining--
					s.timer.Reset(d.configs.RetransmitTimer)
					return
				}

				// At this point we know that either DAD has resolved or we hit an error
				// sending the last DAD message. Either way, clear the DAD state.
				done = false
				s.timer.Stop()
				delete(d.addresses, addr)

				var res stack.DADResult = &stack.DADSucceeded{}
				if err != nil {
					res = &stack.DADError{Err: err}
				}
				for _, h := range s.completionHandlers {
					h(res)
				}
			}),
		}
	}

	s.completionHandlers = append(s.completionHandlers, h)
	d.addresses[addr] = s
	return ret
}

// ExtendIfNonceEqualLockedDisposition enumerates the possible results from
// ExtendIfNonceEqualLocked.
type ExtendIfNonceEqualLockedDisposition int

const (
	// Extended indicates that the DAD process was extended.
	Extended ExtendIfNonceEqualLockedDisposition = iota

	// AlreadyExtended indicates that the DAD process was already extended.
	AlreadyExtended

	// NoDADStateFound indicates that DAD state was not found for the address.
	NoDADStateFound

	// NonceDisabled indicates that nonce values are not sent with DAD messages.
	NonceDisabled

	// NonceNotEqual indicates that the nonce value passed and the nonce in the
	// last send DAD message are not equal.
	NonceNotEqual
)

// ExtendIfNonceEqualLocked extends the DAD process if the provided nonce is the
// same as the nonce sent in the last DAD message.
//
// Precondition: d.protocolMU must be locked.
func (d *DAD) ExtendIfNonceEqualLocked(addr tcpip.Address, nonce []byte) ExtendIfNonceEqualLockedDisposition {
	s, ok := d.addresses[addr]
	if !ok {
		return NoDADStateFound
	}

	if d.opts.NonceSize == 0 {
		return NonceDisabled
	}

	if s.extendRequest != notRequested {
		return AlreadyExtended
	}

	// As per RFC 7527 section 4
	//
	//   If any probe is looped back within RetransTimer milliseconds after having
	//   sent DupAddrDetectTransmits NS(DAD) messages, the interface continues
	//   with another MAX_MULTICAST_SOLICIT number of NS(DAD) messages transmitted
	//   RetransTimer milliseconds apart.
	//
	// If a DAD message has already been sent and the nonce value we observed is
	// the same as the nonce value we last sent, then we assume our probe was
	// looped back and request an extension to the DAD process.
	//
	// Note, the first DAD message is sent asynchronously so we need to make sure
	// that we sent a DAD message by checking if we have a nonce value set.
	if s.nonce != nil && bytes.Equal(s.nonce, nonce) {
		s.extendRequest = requested
		d.addresses[addr] = s
		return Extended
	}

	return NonceNotEqual
}

// StopLocked stops a currently running DAD process.
//
// Precondition: d.protocolMU must be locked.
func (d *DAD) StopLocked(addr tcpip.Address, reason stack.DADResult) {
	s, ok := d.addresses[addr]
	if !ok {
		return
	}

	*s.done = true
	s.timer.Stop()
	delete(d.addresses, addr)

	for _, h := range s.completionHandlers {
		h(reason)
	}
}

// SetConfigsLocked sets the DAD configurations.
//
// Precondition: d.protocolMU must be locked.
func (d *DAD) SetConfigsLocked(c stack.DADConfigurations) {
	c.Validate()
	d.configs = c
}
