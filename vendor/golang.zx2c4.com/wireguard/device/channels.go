/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"runtime"
	"sync"
)

// An outboundQueue is a channel of QueueOutboundElements awaiting encryption.
// An outboundQueue is ref-counted using its wg field.
// An outboundQueue created with newOutboundQueue has one reference.
// Every additional writer must call wg.Add(1).
// Every completed writer must call wg.Done().
// When no further writers will be added,
// call wg.Done to remove the initial reference.
// When the refcount hits 0, the queue's channel is closed.
type outboundQueue struct {
	c  chan *QueueOutboundElement
	wg sync.WaitGroup
}

func newOutboundQueue() *outboundQueue {
	q := &outboundQueue{
		c: make(chan *QueueOutboundElement, QueueOutboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A inboundQueue is similar to an outboundQueue; see those docs.
type inboundQueue struct {
	c  chan *QueueInboundElement
	wg sync.WaitGroup
}

func newInboundQueue() *inboundQueue {
	q := &inboundQueue{
		c: make(chan *QueueInboundElement, QueueInboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A handshakeQueue is similar to an outboundQueue; see those docs.
type handshakeQueue struct {
	c  chan QueueHandshakeElement
	wg sync.WaitGroup
}

func newHandshakeQueue() *handshakeQueue {
	q := &handshakeQueue{
		c: make(chan QueueHandshakeElement, QueueHandshakeSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

type autodrainingInboundQueue struct {
	c chan *QueueInboundElement
}

// newAutodrainingInboundQueue returns a channel that will be drained when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
func newAutodrainingInboundQueue(device *Device) *autodrainingInboundQueue {
	q := &autodrainingInboundQueue{
		c: make(chan *QueueInboundElement, QueueInboundSize),
	}
	runtime.SetFinalizer(q, device.flushInboundQueue)
	return q
}

func (device *Device) flushInboundQueue(q *autodrainingInboundQueue) {
	for {
		select {
		case elem := <-q.c:
			elem.Lock()
			device.PutMessageBuffer(elem.buffer)
			device.PutInboundElement(elem)
		default:
			return
		}
	}
}

type autodrainingOutboundQueue struct {
	c chan *QueueOutboundElement
}

// newAutodrainingOutboundQueue returns a channel that will be drained when it gets GC'd.
// It is useful in cases in which is it hard to manage the lifetime of the channel.
// The returned channel must not be closed. Senders should signal shutdown using
// some other means, such as sending a sentinel nil values.
// All sends to the channel must be best-effort, because there may be no receivers.
func newAutodrainingOutboundQueue(device *Device) *autodrainingOutboundQueue {
	q := &autodrainingOutboundQueue{
		c: make(chan *QueueOutboundElement, QueueOutboundSize),
	}
	runtime.SetFinalizer(q, device.flushOutboundQueue)
	return q
}

func (device *Device) flushOutboundQueue(q *autodrainingOutboundQueue) {
	for {
		select {
		case elem := <-q.c:
			elem.Lock()
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		default:
			return
		}
	}
}
