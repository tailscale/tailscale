/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	sync.Mutex
	buffer  *[MaxMessageSize]byte // slice holding the packet data
	packet  []byte                // slice of "buffer" (always!)
	nonce   uint64                // nonce for encryption
	keypair *Keypair              // keypair for encryption
	peer    *Peer                 // related peer
}

func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetMessageBuffer()
	elem.Mutex = sync.Mutex{}
	elem.nonce = 0
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() {
	if len(peer.queue.staged) == 0 && peer.isRunning.Get() {
		elem := peer.device.NewOutboundElement()
		select {
		case peer.queue.staged <- elem:
			peer.device.log.Verbosef("%v - Sending keepalive packet", peer)
		default:
			peer.device.PutMessageBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
		}
	}
	peer.SendStagedPackets()
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		atomic.StoreUint32(&peer.timers.handshakeAttempts, 0)
	}

	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		return err
	}

	var buff [MessageInitiationSize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err = peer.SendBuffer(packet)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake response", peer)

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		return err
	}

	var buff [MessageResponseSize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, response)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err = peer.SendBuffer(packet)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	device.log.Verbosef("Sending cookie response for denied handshake message for %v", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	reply, err := device.cookieChecker.CreateReply(initiatingElem.packet, sender, initiatingElem.endpoint.DstToBytes())
	if err != nil {
		device.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}

	var buff [MessageCookieReplySize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, reply)
	device.net.bind.Send(writer.Bytes(), initiatingElem.endpoint)
	return nil
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := atomic.LoadUint64(&keypair.sendNonce)
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > RekeyAfterTime) {
		peer.SendHandshakeInitiation(false)
	}
}

/* Reads packets from the TUN and inserts
 * into staged queue for peer
 *
 * Obs. Single instance per TUN device
 */
func (device *Device) RoutineReadFromTUN() {
	defer func() {
		device.log.Verbosef("Routine: TUN reader - stopped")
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("Routine: TUN reader - started")

	var elem *QueueOutboundElement

	for {
		if elem != nil {
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		elem = device.NewOutboundElement()

		// read packet

		offset := MessageTransportHeaderSize
		size, err := device.tun.device.Read(elem.buffer[:], offset)

		if err != nil {
			if !device.isClosed() {
				if !errors.Is(err, os.ErrClosed) {
					device.log.Errorf("Failed to read packet from TUN device: %v", err)
				}
				go device.Close()
			}
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
			return
		}

		if size == 0 || size > MaxContentSize {
			continue
		}

		elem.packet = elem.buffer[offset : offset+size]

		// lookup peer

		var peer *Peer
		switch elem.packet[0] >> 4 {
		case ipv4.Version:
			if len(elem.packet) < ipv4.HeaderLen {
				continue
			}
			dst := elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
			peer = device.allowedips.Lookup(dst)

		case ipv6.Version:
			if len(elem.packet) < ipv6.HeaderLen {
				continue
			}
			dst := elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
			peer = device.allowedips.Lookup(dst)

		default:
			device.log.Verbosef("Received packet with unknown IP version")
		}

		if peer == nil {
			continue
		}
		if peer.isRunning.Get() {
			peer.StagePacket(elem)
			elem = nil
			peer.SendStagedPackets()
		}
	}
}

func (peer *Peer) StagePacket(elem *QueueOutboundElement) {
	for {
		select {
		case peer.queue.staged <- elem:
			return
		default:
		}
		select {
		case tooOld := <-peer.queue.staged:
			peer.device.PutMessageBuffer(tooOld.buffer)
			peer.device.PutOutboundElement(tooOld)
		default:
		}
	}
}

func (peer *Peer) SendStagedPackets() {
top:
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	keypair := peer.keypairs.Current()
	if keypair == nil || atomic.LoadUint64(&keypair.sendNonce) >= RejectAfterMessages || time.Since(keypair.created) >= RejectAfterTime {
		peer.SendHandshakeInitiation(false)
		return
	}

	for {
		select {
		case elem := <-peer.queue.staged:
			elem.peer = peer
			elem.nonce = atomic.AddUint64(&keypair.sendNonce, 1) - 1
			if elem.nonce >= RejectAfterMessages {
				atomic.StoreUint64(&keypair.sendNonce, RejectAfterMessages)
				peer.StagePacket(elem) // XXX: Out of order, but we can't front-load go chans
				goto top
			}

			elem.keypair = keypair
			elem.Lock()

			// add to parallel and sequential queue
			if peer.isRunning.Get() {
				peer.queue.outbound.c <- elem
				peer.device.queue.encryption.c <- elem
			} else {
				peer.device.PutMessageBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
		default:
			return
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case elem := <-peer.queue.staged:
			peer.device.PutMessageBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption(id int) {
	var paddingZeros [PaddingMultiple]byte
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: encryption worker %d - stopped", id)
	device.log.Verbosef("Routine: encryption worker %d - started", id)

	for elem := range device.queue.encryption.c {
		// populate header fields
		header := elem.buffer[:MessageTransportHeaderSize]

		fieldType := header[0:4]
		fieldReceiver := header[4:8]
		fieldNonce := header[8:16]

		binary.LittleEndian.PutUint32(fieldType, MessageTransportType)
		binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
		binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

		// pad content to multiple of 16
		paddingSize := calculatePaddingSize(len(elem.packet), int(atomic.LoadInt32(&device.tun.mtu)))
		elem.packet = append(elem.packet, paddingZeros[:paddingSize]...)

		// encrypt content and release to consumer

		binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
		elem.packet = elem.keypair.send.Seal(
			header,
			nonce[:],
			elem.packet,
			nil,
		)
		elem.Unlock()
	}
}

/* Sequentially reads packets from queue and sends to endpoint
 *
 * Obs. Single instance per peer.
 * The routine terminates then the outbound queue is closed.
 */
func (peer *Peer) RoutineSequentialSender() {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)

	for elem := range peer.queue.outbound.c {
		if elem == nil {
			return
		}
		elem.Lock()
		if !peer.isRunning.Get() {
			// peer has been stopped; return re-usable elems to the shared pool.
			// This is an optimization only. It is possible for the peer to be stopped
			// immediately after this check, in which case, elem will get processed.
			// The timers and SendBuffer code are resilient to a few stragglers.
			// TODO: rework peer shutdown order to ensure
			// that we never accidentally keep timers alive longer than necessary.
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
			continue
		}

		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		// send message and return buffer to pool

		err := peer.SendBuffer(elem.packet)
		if len(elem.packet) != MessageKeepaliveSize {
			peer.timersDataSent()
		}
		device.PutMessageBuffer(elem.buffer)
		device.PutOutboundElement(elem)
		if err != nil {
			device.log.Errorf("%v - Failed to send data packet: %v", peer, err)
			continue
		}

		peer.keepKeyFreshSending()
	}
}
