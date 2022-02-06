/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/replay"
)

/* Due to limitations in Go and /x/crypto there is currently
 * no way to ensure that key material is securely ereased in memory.
 *
 * Since this may harm the forward secrecy property,
 * we plan to resolve this issue; whenever Go allows us to do so.
 */

type Keypair struct {
	sendNonce    uint64 // accessed atomically
	send         cipher.AEAD
	receive      cipher.AEAD
	replayFilter replay.Filter
	isInitiator  bool
	created      time.Time
	localIndex   uint32
	remoteIndex  uint32
}

type Keypairs struct {
	sync.RWMutex
	current  *Keypair
	previous *Keypair
	next     *Keypair
}

func (kp *Keypairs) storeNext(next *Keypair) {
	atomic.StorePointer((*unsafe.Pointer)((unsafe.Pointer)(&kp.next)), (unsafe.Pointer)(next))
}

func (kp *Keypairs) loadNext() *Keypair {
	return (*Keypair)(atomic.LoadPointer((*unsafe.Pointer)((unsafe.Pointer)(&kp.next))))
}

func (kp *Keypairs) Current() *Keypair {
	kp.RLock()
	defer kp.RUnlock()
	return kp.current
}

func (device *Device) DeleteKeypair(key *Keypair) {
	if key != nil {
		device.indexTable.Delete(key.localIndex)
	}
}
