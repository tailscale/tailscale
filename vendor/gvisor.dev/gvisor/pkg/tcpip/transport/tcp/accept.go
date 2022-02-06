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

package tcp

import (
	"container/list"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"time"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// tsLen is the length, in bits, of the timestamp in the SYN cookie.
	tsLen = 8

	// tsMask is a mask for timestamp values (i.e., tsLen bits).
	tsMask = (1 << tsLen) - 1

	// tsOffset is the offset, in bits, of the timestamp in the SYN cookie.
	tsOffset = 24

	// hashMask is the mask for hash values (i.e., tsOffset bits).
	hashMask = (1 << tsOffset) - 1

	// maxTSDiff is the maximum allowed difference between a received cookie
	// timestamp and the current timestamp. If the difference is greater
	// than maxTSDiff, the cookie is expired.
	maxTSDiff = 2
)

var (
	// mssTable is a slice containing the possible MSS values that we
	// encode in the SYN cookie with two bits.
	mssTable = []uint16{536, 1300, 1440, 1460}
)

func encodeMSS(mss uint16) uint32 {
	for i := len(mssTable) - 1; i > 0; i-- {
		if mss >= mssTable[i] {
			return uint32(i)
		}
	}
	return 0
}

// listenContext is used by a listening endpoint to store state used while
// listening for connections. This struct is allocated by the listen goroutine
// and must not be accessed or have its methods called concurrently as they
// may mutate the stored objects.
type listenContext struct {
	stack    *stack.Stack
	protocol *protocol

	// rcvWnd is the receive window that is sent by this listening context
	// in the initial SYN-ACK.
	rcvWnd seqnum.Size

	// nonce are random bytes that are initialized once when the context
	// is created and used to seed the hash function when generating
	// the SYN cookie.
	nonce [2][sha1.BlockSize]byte

	// listenEP is a reference to the listening endpoint associated with
	// this context. Can be nil if the context is created by the forwarder.
	listenEP *endpoint

	// hasherMu protects hasher.
	hasherMu sync.Mutex
	// hasher is the hash function used to generate a SYN cookie.
	hasher hash.Hash

	// v6Only is true if listenEP is a dual stack socket and has the
	// IPV6_V6ONLY option set.
	v6Only bool

	// netProto indicates the network protocol(IPv4/v6) for the listening
	// endpoint.
	netProto tcpip.NetworkProtocolNumber
}

// timeStamp returns an 8-bit timestamp with a granularity of 64 seconds.
func timeStamp(clock tcpip.Clock) uint32 {
	return uint32(clock.NowMonotonic().Sub(tcpip.MonotonicTime{}).Seconds()) >> 6 & tsMask
}

// newListenContext creates a new listen context.
func newListenContext(stk *stack.Stack, protocol *protocol, listenEP *endpoint, rcvWnd seqnum.Size, v6Only bool, netProto tcpip.NetworkProtocolNumber) *listenContext {
	l := &listenContext{
		stack:    stk,
		protocol: protocol,
		rcvWnd:   rcvWnd,
		hasher:   sha1.New(),
		v6Only:   v6Only,
		netProto: netProto,
		listenEP: listenEP,
	}

	for i := range l.nonce {
		if _, err := io.ReadFull(stk.SecureRNG(), l.nonce[i][:]); err != nil {
			panic(err)
		}
	}

	return l
}

// cookieHash calculates the cookieHash for the given id, timestamp and nonce
// index. The hash is used to create and validate cookies.
func (l *listenContext) cookieHash(id stack.TransportEndpointID, ts uint32, nonceIndex int) uint32 {

	// Initialize block with fixed-size data: local ports and v.
	var payload [8]byte
	binary.BigEndian.PutUint16(payload[0:], id.LocalPort)
	binary.BigEndian.PutUint16(payload[2:], id.RemotePort)
	binary.BigEndian.PutUint32(payload[4:], ts)

	// Feed everything to the hasher.
	l.hasherMu.Lock()
	l.hasher.Reset()

	// Per hash.Hash.Writer:
	//
	// It never returns an error.
	l.hasher.Write(payload[:])
	l.hasher.Write(l.nonce[nonceIndex][:])
	l.hasher.Write([]byte(id.LocalAddress))
	l.hasher.Write([]byte(id.RemoteAddress))

	// Finalize the calculation of the hash and return the first 4 bytes.
	h := l.hasher.Sum(nil)
	l.hasherMu.Unlock()

	return binary.BigEndian.Uint32(h[:])
}

// createCookie creates a SYN cookie for the given id and incoming sequence
// number.
func (l *listenContext) createCookie(id stack.TransportEndpointID, seq seqnum.Value, data uint32) seqnum.Value {
	ts := timeStamp(l.stack.Clock())
	v := l.cookieHash(id, 0, 0) + uint32(seq) + (ts << tsOffset)
	v += (l.cookieHash(id, ts, 1) + data) & hashMask
	return seqnum.Value(v)
}

// isCookieValid checks if the supplied cookie is valid for the given id and
// sequence number. If it is, it also returns the data originally encoded in the
// cookie when createCookie was called.
func (l *listenContext) isCookieValid(id stack.TransportEndpointID, cookie seqnum.Value, seq seqnum.Value) (uint32, bool) {
	ts := timeStamp(l.stack.Clock())
	v := uint32(cookie) - l.cookieHash(id, 0, 0) - uint32(seq)
	cookieTS := v >> tsOffset
	if ((ts - cookieTS) & tsMask) > maxTSDiff {
		return 0, false
	}

	return (v - l.cookieHash(id, cookieTS, 1)) & hashMask, true
}

// createConnectingEndpoint creates a new endpoint in a connecting state, with
// the connection parameters given by the arguments.
func (l *listenContext) createConnectingEndpoint(s *segment, rcvdSynOpts header.TCPSynOptions, queue *waiter.Queue) (*endpoint, tcpip.Error) {
	// Create a new endpoint.
	netProto := l.netProto
	if netProto == 0 {
		netProto = s.netProto
	}

	route, err := l.stack.FindRoute(s.nicID, s.dstAddr, s.srcAddr, s.netProto, false /* multicastLoop */)
	if err != nil {
		return nil, err
	}

	n := newEndpoint(l.stack, l.protocol, netProto, queue)
	n.ops.SetV6Only(l.v6Only)
	n.TransportEndpointInfo.ID = s.id
	n.boundNICID = s.nicID
	n.route = route
	n.effectiveNetProtos = []tcpip.NetworkProtocolNumber{s.netProto}
	n.ops.SetReceiveBufferSize(int64(l.rcvWnd), false /* notify */)
	n.amss = calculateAdvertisedMSS(n.userMSS, n.route)
	n.setEndpointState(StateConnecting)

	n.maybeEnableTimestamp(rcvdSynOpts)
	n.maybeEnableSACKPermitted(rcvdSynOpts)

	n.initGSO()

	// Bootstrap the auto tuning algorithm. Starting at zero will result in
	// a large step function on the first window adjustment causing the
	// window to grow to a really large value.
	n.rcvQueueInfo.RcvAutoParams.PrevCopiedBytes = n.initialReceiveWindow()

	return n, nil
}

// startHandshake creates a new endpoint in connecting state and then sends
// the SYN-ACK for the TCP 3-way handshake. It returns the state of the
// handshake in progress, which includes the new endpoint in the SYN-RCVD
// state.
//
// On success, a handshake h is returned with h.ep.mu held.
//
// Precondition: if l.listenEP != nil, l.listenEP.mu must be locked.
func (l *listenContext) startHandshake(s *segment, opts header.TCPSynOptions, queue *waiter.Queue, owner tcpip.PacketOwner) (*handshake, tcpip.Error) {
	// Create new endpoint.
	irs := s.sequenceNumber
	isn := generateSecureISN(s.id, l.stack.Clock(), l.protocol.seqnumSecret)
	ep, err := l.createConnectingEndpoint(s, opts, queue)
	if err != nil {
		return nil, err
	}

	// Lock the endpoint before registering to ensure that no out of
	// band changes are possible due to incoming packets etc till
	// the endpoint is done initializing.
	ep.mu.Lock()
	ep.owner = owner

	// listenEP is nil when listenContext is used by tcp.Forwarder.
	deferAccept := time.Duration(0)
	if l.listenEP != nil {
		if l.listenEP.EndpointState() != StateListen {

			// Ensure we release any registrations done by the newly
			// created endpoint.
			ep.mu.Unlock()
			ep.Close()

			return nil, &tcpip.ErrConnectionAborted{}
		}

		// Propagate any inheritable options from the listening endpoint
		// to the newly created endpoint.
		l.listenEP.propagateInheritableOptionsLocked(ep) // +checklocksforce

		if !ep.reserveTupleLocked() {
			ep.mu.Unlock()
			ep.Close()

			return nil, &tcpip.ErrConnectionAborted{}
		}

		deferAccept = l.listenEP.deferAccept
	}

	// Register new endpoint so that packets are routed to it.
	if err := ep.stack.RegisterTransportEndpoint(
		ep.effectiveNetProtos,
		ProtocolNumber,
		ep.TransportEndpointInfo.ID,
		ep,
		ep.boundPortFlags,
		ep.boundBindToDevice,
	); err != nil {
		ep.mu.Unlock()
		ep.Close()

		ep.drainClosingSegmentQueue()

		return nil, err
	}

	ep.isRegistered = true

	// Initialize and start the handshake.
	h := ep.newPassiveHandshake(isn, irs, opts, deferAccept)
	h.listenEP = l.listenEP
	h.start()
	return h, nil
}

// performHandshake performs a TCP 3-way handshake. On success, the new
// established endpoint is returned with e.mu held.
//
// Precondition: if l.listenEP != nil, l.listenEP.mu must be locked.
func (l *listenContext) performHandshake(s *segment, opts header.TCPSynOptions, queue *waiter.Queue, owner tcpip.PacketOwner) (*endpoint, tcpip.Error) {
	h, err := l.startHandshake(s, opts, queue, owner)
	if err != nil {
		return nil, err
	}
	ep := h.ep

	// N.B. the endpoint is generated above by startHandshake, and will be
	// returned locked. This first call is forced.
	if err := h.complete(); err != nil { // +checklocksforce
		ep.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		ep.stats.FailedConnectionAttempts.Increment()
		l.cleanupFailedHandshake(h)
		return nil, err
	}
	l.cleanupCompletedHandshake(h)
	return ep, nil
}

// +checklocks:h.ep.mu
func (l *listenContext) cleanupFailedHandshake(h *handshake) {
	e := h.ep
	e.mu.Unlock()
	e.Close()
	e.notifyAborted()
	e.drainClosingSegmentQueue()
	e.h = nil
}

// cleanupCompletedHandshake transfers any state from the completed handshake to
// the new endpoint.
//
// +checklocks:h.ep.mu
func (l *listenContext) cleanupCompletedHandshake(h *handshake) {
	e := h.ep
	e.isConnectNotified = true

	// Update the receive window scaling. We can't do it before the
	// handshake because it's possible that the peer doesn't support window
	// scaling.
	e.rcv.RcvWndScale = e.h.effectiveRcvWndScale()

	// Clean up handshake state stored in the endpoint so that it can be GCed.
	e.h = nil
}

// propagateInheritableOptionsLocked propagates any options set on the listening
// endpoint to the newly created endpoint.
//
// +checklocks:e.mu
// +checklocks:n.mu
func (e *endpoint) propagateInheritableOptionsLocked(n *endpoint) {
	n.userTimeout = e.userTimeout
	n.portFlags = e.portFlags
	n.boundBindToDevice = e.boundBindToDevice
	n.boundPortFlags = e.boundPortFlags
	n.userMSS = e.userMSS
}

// reserveTupleLocked reserves an accepted endpoint's tuple.
//
// Precondition: e.propagateInheritableOptionsLocked has been called.
//
// +checklocks:e.mu
func (e *endpoint) reserveTupleLocked() bool {
	dest := tcpip.FullAddress{
		Addr: e.TransportEndpointInfo.ID.RemoteAddress,
		Port: e.TransportEndpointInfo.ID.RemotePort,
	}
	portRes := ports.Reservation{
		Networks:     e.effectiveNetProtos,
		Transport:    ProtocolNumber,
		Addr:         e.TransportEndpointInfo.ID.LocalAddress,
		Port:         e.TransportEndpointInfo.ID.LocalPort,
		Flags:        e.boundPortFlags,
		BindToDevice: e.boundBindToDevice,
		Dest:         dest,
	}
	if !e.stack.ReserveTuple(portRes) {
		e.stack.Stats().TCP.FailedPortReservations.Increment()
		return false
	}

	e.isPortReserved = true
	e.boundDest = dest
	return true
}

// notifyAborted wakes up any waiters on registered, but not accepted
// endpoints.
//
// This is strictly not required normally as a socket that was never accepted
// can't really have any registered waiters except when stack.Wait() is called
// which waits for all registered endpoints to stop and expects an EventHUp.
func (e *endpoint) notifyAborted() {
	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

func (e *endpoint) acceptQueueIsFull() bool {
	e.acceptMu.Lock()
	full := e.acceptQueue.isFull()
	e.acceptMu.Unlock()
	return full
}

// +stateify savable
type acceptQueue struct {
	// NB: this could be an endpointList, but ilist only permits endpoints to
	// belong to one list at a time, and endpoints are already stored in the
	// dispatcher's list.
	endpoints list.List `state:".([]*endpoint)"`

	// pendingEndpoints is a set of all endpoints for which a handshake is
	// in progress.
	pendingEndpoints map[*endpoint]struct{}

	// capacity is the maximum number of endpoints that can be in endpoints.
	capacity int
}

func (a *acceptQueue) isFull() bool {
	return a.endpoints.Len() == a.capacity
}

// handleListenSegment is called when a listening endpoint receives a segment
// and needs to handle it.
//
// +checklocks:e.mu
func (e *endpoint) handleListenSegment(ctx *listenContext, s *segment) tcpip.Error {
	e.rcvQueueInfo.rcvQueueMu.Lock()
	rcvClosed := e.rcvQueueInfo.RcvClosed
	e.rcvQueueInfo.rcvQueueMu.Unlock()
	if rcvClosed || s.flags.Contains(header.TCPFlagSyn|header.TCPFlagAck) {
		// If the endpoint is shutdown, reply with reset.
		//
		// RFC 793 section 3.4 page 35 (figure 12) outlines that a RST
		// must be sent in response to a SYN-ACK while in the listen
		// state to prevent completing a handshake from an old SYN.
		return replyWithReset(e.stack, s, e.sendTOS, e.ipv4TTL, e.ipv6HopLimit)
	}

	switch {
	case s.flags.Contains(header.TCPFlagRst):
		e.stack.Stats().DroppedPackets.Increment()
		return nil

	case s.flags.Contains(header.TCPFlagSyn):
		if e.acceptQueueIsFull() {
			e.stack.Stats().TCP.ListenOverflowSynDrop.Increment()
			e.stats.ReceiveErrors.ListenOverflowSynDrop.Increment()
			e.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		opts := parseSynSegmentOptions(s)

		useSynCookies, err := func() (bool, tcpip.Error) {
			var alwaysUseSynCookies tcpip.TCPAlwaysUseSynCookies
			if err := e.stack.TransportProtocolOption(header.TCPProtocolNumber, &alwaysUseSynCookies); err != nil {
				panic(fmt.Sprintf("TransportProtocolOption(%d, %T) = %s", header.TCPProtocolNumber, alwaysUseSynCookies, err))
			}
			if alwaysUseSynCookies {
				return true, nil
			}
			e.acceptMu.Lock()
			defer e.acceptMu.Unlock()

			// The capacity of the accepted queue would always be one greater than the
			// listen backlog. But, the SYNRCVD connections count is always checked
			// against the listen backlog value for Linux parity reason.
			// https://github.com/torvalds/linux/blob/7acac4b3196/include/net/inet_connection_sock.h#L280
			if len(e.acceptQueue.pendingEndpoints) == e.acceptQueue.capacity-1 {
				return true, nil
			}

			h, err := ctx.startHandshake(s, opts, &waiter.Queue{}, e.owner)
			if err != nil {
				e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
				e.stats.FailedConnectionAttempts.Increment()
				return false, err
			}

			e.acceptQueue.pendingEndpoints[h.ep] = struct{}{}
			e.pendingAccepted.Add(1)

			go func() {
				defer func() {
					e.pendingAccepted.Done()

					e.acceptMu.Lock()
					defer e.acceptMu.Unlock()
					delete(e.acceptQueue.pendingEndpoints, h.ep)
				}()

				// Note that startHandshake returns a locked endpoint. The force call
				// here just makes it so.
				if err := h.complete(); err != nil { // +checklocksforce
					e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
					e.stats.FailedConnectionAttempts.Increment()
					ctx.cleanupFailedHandshake(h)
					return
				}
				ctx.cleanupCompletedHandshake(h)
				h.ep.startAcceptedLoop()
				e.stack.Stats().TCP.PassiveConnectionOpenings.Increment()

				// Deliver the endpoint to the accept queue.
				//
				// Drop the lock before notifying to avoid deadlock in user-specified
				// callbacks.
				delivered := func() bool {
					e.acceptMu.Lock()
					defer e.acceptMu.Unlock()
					for {
						// The listener is transitioning out of the Listen state; bail.
						if e.acceptQueue.capacity == 0 {
							return false
						}
						if e.acceptQueue.isFull() {
							e.acceptCond.Wait()
							continue
						}

						e.acceptQueue.endpoints.PushBack(h.ep)
						return true
					}
				}()

				if delivered {
					e.waiterQueue.Notify(waiter.ReadableEvents)
				} else {
					h.ep.notifyProtocolGoroutine(notifyReset)
				}
			}()

			return false, nil
		}()
		if err != nil {
			return err
		}
		if !useSynCookies {
			return nil
		}

		route, err := e.stack.FindRoute(s.nicID, s.dstAddr, s.srcAddr, s.netProto, false /* multicastLoop */)
		if err != nil {
			return err
		}
		defer route.Release()

		// Send SYN without window scaling because we currently
		// don't encode this information in the cookie.
		//
		// Enable Timestamp option if the original syn did have
		// the timestamp option specified.
		//
		// Use the user supplied MSS on the listening socket for
		// new connections, if available.
		synOpts := header.TCPSynOptions{
			WS:    -1,
			TS:    opts.TS,
			TSEcr: opts.TSVal,
			MSS:   calculateAdvertisedMSS(e.userMSS, route),
		}
		if opts.TS {
			offset := e.protocol.tsOffset(s.dstAddr, s.srcAddr)
			now := e.stack.Clock().NowMonotonic()
			synOpts.TSVal = offset.TSVal(now)
		}
		cookie := ctx.createCookie(s.id, s.sequenceNumber, encodeMSS(opts.MSS))
		fields := tcpFields{
			id:     s.id,
			ttl:    calculateTTL(route, e.ipv4TTL, e.ipv6HopLimit),
			tos:    e.sendTOS,
			flags:  header.TCPFlagSyn | header.TCPFlagAck,
			seq:    cookie,
			ack:    s.sequenceNumber + 1,
			rcvWnd: ctx.rcvWnd,
		}
		if err := e.sendSynTCP(route, fields, synOpts); err != nil {
			return err
		}
		e.stack.Stats().TCP.ListenOverflowSynCookieSent.Increment()
		return nil

	case s.flags.Contains(header.TCPFlagAck):
		iss := s.ackNumber - 1
		irs := s.sequenceNumber - 1

		// Since SYN cookies are in use this is potentially an ACK to a
		// SYN-ACK we sent but don't have a half open connection state
		// as cookies are being used to protect against a potential SYN
		// flood. In such cases validate the cookie and if valid create
		// a fully connected endpoint and deliver to the accept queue.
		//
		// If not, silently drop the ACK to avoid leaking information
		// when under a potential syn flood attack.
		//
		// Validate the cookie.
		data, ok := ctx.isCookieValid(s.id, iss, irs)
		if !ok || int(data) >= len(mssTable) {
			e.stack.Stats().TCP.ListenOverflowInvalidSynCookieRcvd.Increment()
			e.stack.Stats().DroppedPackets.Increment()

			// When not using SYN cookies, as per RFC 793, section 3.9, page 64:
			// Any acknowledgment is bad if it arrives on a connection still in
			// the LISTEN state.  An acceptable reset segment should be formed
			// for any arriving ACK-bearing segment.  The RST should be
			// formatted as follows:
			//
			//  <SEQ=SEG.ACK><CTL=RST>
			//
			// Send a reset as this is an ACK for which there is no
			// half open connections and we are not using cookies
			// yet.
			//
			// The only time we should reach here when a connection
			// was opened and closed really quickly and a delayed
			// ACK was received from the sender.
			return replyWithReset(e.stack, s, e.sendTOS, e.ipv4TTL, e.ipv6HopLimit)
		}

		// Keep hold of acceptMu until the new endpoint is in the accept queue (or
		// if there is an error), to guarantee that we will keep our spot in the
		// queue even if another handshake from the syn queue completes.
		e.acceptMu.Lock()
		if e.acceptQueue.isFull() {
			// Silently drop the ack as the application can't accept
			// the connection at this point. The ack will be
			// retransmitted by the sender anyway and we can
			// complete the connection at the time of retransmit if
			// the backlog has space.
			e.acceptMu.Unlock()
			e.stack.Stats().TCP.ListenOverflowAckDrop.Increment()
			e.stats.ReceiveErrors.ListenOverflowAckDrop.Increment()
			e.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		e.stack.Stats().TCP.ListenOverflowSynCookieRcvd.Increment()
		// Create newly accepted endpoint and deliver it.
		rcvdSynOptions := header.TCPSynOptions{
			MSS: mssTable[data],
			// Disable Window scaling as original SYN is
			// lost.
			WS: -1,
		}

		// When syn cookies are in use we enable timestamp only
		// if the ack specifies the timestamp option assuming
		// that the other end did in fact negotiate the
		// timestamp option in the original SYN.
		if s.parsedOptions.TS {
			rcvdSynOptions.TS = true
			rcvdSynOptions.TSVal = s.parsedOptions.TSVal
			rcvdSynOptions.TSEcr = s.parsedOptions.TSEcr
		}

		n, err := ctx.createConnectingEndpoint(s, rcvdSynOptions, &waiter.Queue{})
		if err != nil {
			e.acceptMu.Unlock()
			return err
		}

		n.mu.Lock()

		// Propagate any inheritable options from the listening endpoint
		// to the newly created endpoint.
		e.propagateInheritableOptionsLocked(n)

		if !n.reserveTupleLocked() {
			n.mu.Unlock()
			e.acceptMu.Unlock()
			n.Close()

			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
			return nil
		}

		// Register new endpoint so that packets are routed to it.
		if err := n.stack.RegisterTransportEndpoint(
			n.effectiveNetProtos,
			ProtocolNumber,
			n.TransportEndpointInfo.ID,
			n,
			n.boundPortFlags,
			n.boundBindToDevice,
		); err != nil {
			n.mu.Unlock()
			e.acceptMu.Unlock()
			n.Close()

			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
			return err
		}

		n.isRegistered = true
		n.TSOffset = n.protocol.tsOffset(s.dstAddr, s.srcAddr)

		// Switch state to connected.
		n.isConnectNotified = true
		h := handshake{
			ep:                  n,
			iss:                 iss,
			ackNum:              irs + 1,
			rcvWnd:              seqnum.Size(n.initialReceiveWindow()),
			sndWnd:              s.window,
			rcvWndScale:         e.rcvWndScaleForHandshake(),
			sndWndScale:         rcvdSynOptions.WS,
			mss:                 rcvdSynOptions.MSS,
			sampleRTTWithTSOnly: true,
		}
		h.transitionToStateEstablishedLocked(s)

		// Requeue the segment if the ACK completing the handshake has more info
		// to be procesed by the newly established endpoint.
		if (s.flags.Contains(header.TCPFlagFin) || s.data.Size() > 0) && n.enqueueSegment(s) {
			s.incRef()
			n.newSegmentWaker.Assert()
		}

		// Start the protocol goroutine.
		n.startAcceptedLoop()
		e.stack.Stats().TCP.PassiveConnectionOpenings.Increment()

		// Deliver the endpoint to the accept queue.
		e.acceptQueue.endpoints.PushBack(n)
		e.acceptMu.Unlock()

		e.waiterQueue.Notify(waiter.ReadableEvents)
		return nil

	default:
		e.stack.Stats().DroppedPackets.Increment()
		return nil
	}
}

// protocolListenLoop is the main loop of a listening TCP endpoint. It runs in
// its own goroutine and is responsible for handling connection requests.
func (e *endpoint) protocolListenLoop(rcvWnd seqnum.Size) {
	e.mu.Lock()
	v6Only := e.ops.GetV6Only()
	ctx := newListenContext(e.stack, e.protocol, e, rcvWnd, v6Only, e.NetProto)

	defer func() {
		e.setEndpointState(StateClose)

		// Do cleanup if needed.
		e.completeWorkerLocked()

		if e.drainDone != nil {
			close(e.drainDone)
		}
		e.mu.Unlock()

		e.drainClosingSegmentQueue()

		// Notify waiters that the endpoint is shutdown.
		e.waiterQueue.Notify(waiter.ReadableEvents | waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
	}()

	var s sleep.Sleeper
	s.AddWaker(&e.notificationWaker)
	s.AddWaker(&e.newSegmentWaker)
	defer s.Done()
	for {
		e.mu.Unlock()
		w := s.Fetch(true)
		e.mu.Lock()
		switch w {
		case &e.notificationWaker:
			n := e.fetchNotifications()
			if n&notifyClose != 0 {
				return
			}
			if n&notifyDrain != 0 {
				for !e.segmentQueue.empty() {
					s := e.segmentQueue.dequeue()
					// TODO(gvisor.dev/issue/4690): Better handle errors instead of
					// silently dropping.
					_ = e.handleListenSegment(ctx, s)
					s.decRef()
				}
				close(e.drainDone)
				e.mu.Unlock()
				<-e.undrain
				e.mu.Lock()
			}

		case &e.newSegmentWaker:
			// Process at most maxSegmentsPerWake segments.
			mayRequeue := true
			for i := 0; i < maxSegmentsPerWake; i++ {
				s := e.segmentQueue.dequeue()
				if s == nil {
					mayRequeue = false
					break
				}

				// TODO(gvisor.dev/issue/4690): Better handle errors instead of
				// silently dropping.
				_ = e.handleListenSegment(ctx, s)
				s.decRef()
			}

			// If the queue is not empty, make sure we'll wake up
			// in the next iteration.
			if mayRequeue && !e.segmentQueue.empty() {
				e.newSegmentWaker.Assert()
			}
		}
	}
}
