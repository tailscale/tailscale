/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
	"sync/atomic"
)

type WaitPool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count uint32
	max   uint32
}

func NewWaitPool(max uint32, new func() interface{}) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *WaitPool) Get() interface{} {
	if p.max != 0 {
		p.lock.Lock()
		for atomic.LoadUint32(&p.count) >= p.max {
			p.cond.Wait()
		}
		atomic.AddUint32(&p.count, 1)
		p.lock.Unlock()
	}
	return p.pool.Get()
}

func (p *WaitPool) Put(x interface{}) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	atomic.AddUint32(&p.count, ^uint32(0))
	p.cond.Signal()
}

func (device *Device) PopulatePools() {
	device.pool.messageBuffers = NewWaitPool(PreallocatedBuffersPerPool, func() interface{} {
		return new([MaxMessageSize]byte)
	})
	device.pool.inboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() interface{} {
		return new(QueueInboundElement)
	})
	device.pool.outboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() interface{} {
		return new(QueueOutboundElement)
	})
}

func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	return device.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	device.pool.messageBuffers.Put(msg)
}

func (device *Device) GetInboundElement() *QueueInboundElement {
	return device.pool.inboundElements.Get().(*QueueInboundElement)
}

func (device *Device) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	device.pool.inboundElements.Put(elem)
}

func (device *Device) GetOutboundElement() *QueueOutboundElement {
	return device.pool.outboundElements.Get().(*QueueOutboundElement)
}

func (device *Device) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	device.pool.outboundElements.Put(elem)
}
