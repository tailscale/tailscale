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
	"fmt"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// +checklocks:e.mu
func (e *endpoint) drainSegmentLocked() {
	// Drain only up to once.
	if e.drainDone != nil {
		return
	}

	e.drainDone = make(chan struct{})
	e.undrain = make(chan struct{})
	e.mu.Unlock()

	e.notifyProtocolGoroutine(notifyDrain)
	<-e.drainDone

	e.mu.Lock()
}

// beforeSave is invoked by stateify.
func (e *endpoint) beforeSave() {
	// Stop incoming packets.
	e.segmentQueue.freeze()

	e.mu.Lock()
	defer e.mu.Unlock()

	epState := e.EndpointState()
	switch {
	case epState == StateInitial || epState == StateBound:
	case epState.connected() || epState.handshake():
		if !e.route.HasSaveRestoreCapability() {
			if !e.route.HasDisconncetOkCapability() {
				panic(&tcpip.ErrSaveRejection{
					Err: fmt.Errorf("endpoint cannot be saved in connected state: local %s:%d, remote %s:%d", e.TransportEndpointInfo.ID.LocalAddress, e.TransportEndpointInfo.ID.LocalPort, e.TransportEndpointInfo.ID.RemoteAddress, e.TransportEndpointInfo.ID.RemotePort),
				})
			}
			e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
			e.mu.Unlock()
			e.Close()
			e.mu.Lock()
		}
		if !e.workerRunning {
			// The endpoint must be in the accepted queue or has been just
			// disconnected and closed.
			break
		}
		fallthrough
	case epState == StateListen || epState == StateConnecting:
		e.drainSegmentLocked()
		// Refresh epState, since drainSegmentLocked may have changed it.
		epState = e.EndpointState()
		if !epState.closed() {
			if !e.workerRunning {
				panic("endpoint has no worker running in listen, connecting, or connected state")
			}
		}
	case epState.closed():
		for e.workerRunning {
			e.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
			e.mu.Lock()
		}
		if e.workerRunning {
			panic(fmt.Sprintf("endpoint: %+v still has worker running in closed or error state", e.TransportEndpointInfo.ID))
		}
	default:
		panic(fmt.Sprintf("endpoint in unknown state %v", e.EndpointState()))
	}

	if e.waiterQueue != nil && !e.waiterQueue.IsEmpty() {
		panic("endpoint still has waiters upon save")
	}
}

// saveEndpoints is invoked by stateify.
func (a *acceptQueue) saveEndpoints() []*endpoint {
	acceptedEndpoints := make([]*endpoint, a.endpoints.Len())
	for i, e := 0, a.endpoints.Front(); e != nil; i, e = i+1, e.Next() {
		acceptedEndpoints[i] = e.Value.(*endpoint)
	}
	return acceptedEndpoints
}

// loadEndpoints is invoked by stateify.
func (a *acceptQueue) loadEndpoints(acceptedEndpoints []*endpoint) {
	for _, ep := range acceptedEndpoints {
		a.endpoints.PushBack(ep)
	}
}

// saveState is invoked by stateify.
func (e *endpoint) saveState() EndpointState {
	return e.EndpointState()
}

// Endpoint loading must be done in the following ordering by their state, to
// avoid dangling connecting w/o listening peer, and to avoid conflicts in port
// reservation.
var connectedLoading sync.WaitGroup
var listenLoading sync.WaitGroup
var connectingLoading sync.WaitGroup

// Bound endpoint loading happens last.

// loadState is invoked by stateify.
func (e *endpoint) loadState(epState EndpointState) {
	// This is to ensure that the loading wait groups include all applicable
	// endpoints before any asynchronous calls to the Wait() methods.
	// For restore purposes we treat TimeWait like a connected endpoint.
	if epState.connected() || epState == StateTimeWait {
		connectedLoading.Add(1)
	}
	switch {
	case epState == StateListen:
		listenLoading.Add(1)
	case epState.connecting():
		connectingLoading.Add(1)
	}
	// Directly update the state here rather than using e.setEndpointState
	// as the endpoint is still being loaded and the stack reference is not
	// yet initialized.
	atomic.StoreUint32((*uint32)(&e.state), uint32(epState))
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	e.origEndpointState = e.state
	// Restore the endpoint to InitialState as it will be moved to
	// its origEndpointState during Resume.
	e.state = uint32(StateInitial)
	// Condition variables and mutexs are not S/R'ed so reinitialize
	// acceptCond with e.acceptMu.
	e.acceptCond = sync.NewCond(&e.acceptMu)
	stack.StackFromEnv.RegisterRestoredEndpoint(e)
}

// Resume implements tcpip.ResumableEndpoint.Resume.
func (e *endpoint) Resume(s *stack.Stack) {
	e.keepalive.timer.init(s.Clock(), &e.keepalive.waker)
	if snd := e.snd; snd != nil {
		snd.resendTimer.init(s.Clock(), &snd.resendWaker)
		snd.reorderTimer.init(s.Clock(), &snd.reorderWaker)
		snd.probeTimer.init(s.Clock(), &snd.probeWaker)
	}
	e.stack = s
	e.protocol = protocolFromStack(s)
	e.ops.InitHandler(e, e.stack, GetTCPSendBufferLimits, GetTCPReceiveBufferLimits)
	e.segmentQueue.thaw()
	epState := EndpointState(e.origEndpointState)
	switch epState {
	case StateInitial, StateBound, StateListen, StateConnecting, StateEstablished:
		var ss tcpip.TCPSendBufferSizeRangeOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
			sendBufferSize := e.getSendBufferSize()
			if sendBufferSize < ss.Min || sendBufferSize > ss.Max {
				panic(fmt.Sprintf("endpoint sendBufferSize %d is outside the min and max allowed [%d, %d]", sendBufferSize, ss.Min, ss.Max))
			}
		}

		var rs tcpip.TCPReceiveBufferSizeRangeOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
			if rcvBufSize := e.ops.GetReceiveBufferSize(); rcvBufSize < int64(rs.Min) || rcvBufSize > int64(rs.Max) {
				panic(fmt.Sprintf("endpoint rcvBufSize %d is outside the min and max allowed [%d, %d]", rcvBufSize, rs.Min, rs.Max))
			}
		}
	}

	bind := func() {
		addr, _, err := e.checkV4MappedLocked(tcpip.FullAddress{Addr: e.BindAddr, Port: e.TransportEndpointInfo.ID.LocalPort})
		if err != nil {
			panic("unable to parse BindAddr: " + err.String())
		}
		portRes := ports.Reservation{
			Networks:     e.effectiveNetProtos,
			Transport:    ProtocolNumber,
			Addr:         addr.Addr,
			Port:         addr.Port,
			Flags:        e.boundPortFlags,
			BindToDevice: e.boundBindToDevice,
			Dest:         e.boundDest,
		}
		if ok := e.stack.ReserveTuple(portRes); !ok {
			panic(fmt.Sprintf("unable to re-reserve tuple (%v, %q, %d, %+v, %d, %v)", e.effectiveNetProtos, addr.Addr, addr.Port, e.boundPortFlags, e.boundBindToDevice, e.boundDest))
		}
		e.isPortReserved = true

		// Mark endpoint as bound.
		e.setEndpointState(StateBound)
	}

	switch {
	case epState.connected():
		bind()
		if len(e.connectingAddress) == 0 {
			e.connectingAddress = e.TransportEndpointInfo.ID.RemoteAddress
			// This endpoint is accepted by netstack but not yet by
			// the app. If the endpoint is IPv6 but the remote
			// address is IPv4, we need to connect as IPv6 so that
			// dual-stack mode can be properly activated.
			if e.NetProto == header.IPv6ProtocolNumber && len(e.TransportEndpointInfo.ID.RemoteAddress) != header.IPv6AddressSize {
				e.connectingAddress = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + e.TransportEndpointInfo.ID.RemoteAddress
			}
		}
		// Reset the scoreboard to reinitialize the sack information as
		// we do not restore SACK information.
		e.scoreboard.Reset()
		err := e.connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.TransportEndpointInfo.ID.RemotePort}, false, e.workerRunning)
		if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			panic("endpoint connecting failed: " + err.String())
		}
		e.mu.Lock()
		e.state = e.origEndpointState
		closed := e.closed
		e.mu.Unlock()
		e.notifyProtocolGoroutine(notifyTickleWorker)
		if epState == StateFinWait2 && closed {
			// If the endpoint has been closed then make sure we notify so
			// that the FIN_WAIT2 timer is started after a restore.
			e.notifyProtocolGoroutine(notifyClose)
		}
		connectedLoading.Done()
	case epState == StateListen:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			bind()
			e.acceptMu.Lock()
			backlog := e.acceptQueue.capacity
			e.acceptMu.Unlock()
			if err := e.Listen(backlog); err != nil {
				panic("endpoint listening failed: " + err.String())
			}
			e.LockUser()
			if e.shutdownFlags != 0 {
				e.shutdownLocked(e.shutdownFlags)
			}
			e.UnlockUser()
			listenLoading.Done()
			tcpip.AsyncLoading.Done()
		}()
	case epState.connecting():
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			bind()
			err := e.Connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.TransportEndpointInfo.ID.RemotePort})
			if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
				panic("endpoint connecting failed: " + err.String())
			}
			connectingLoading.Done()
			tcpip.AsyncLoading.Done()
		}()
	case epState == StateBound:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			connectingLoading.Wait()
			bind()
			tcpip.AsyncLoading.Done()
		}()
	case epState == StateClose:
		e.isPortReserved = false
		e.state = uint32(StateClose)
		e.stack.CompleteTransportEndpointCleanup(e)
		tcpip.DeleteDanglingEndpoint(e)
	case epState == StateError:
		e.state = uint32(StateError)
		e.stack.CompleteTransportEndpointCleanup(e)
		tcpip.DeleteDanglingEndpoint(e)
	}
}
