/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

type IndexTableEntry struct {
	peer      *Peer
	handshake *Handshake
	keypair   *Keypair
}

type IndexTable struct {
	sync.RWMutex
	table map[uint32]IndexTableEntry
}

func randUint32() (uint32, error) {
	var integer [4]byte
	_, err := rand.Read(integer[:])
	// Arbitrary endianness; both are intrinsified by the Go compiler.
	return binary.LittleEndian.Uint32(integer[:]), err
}

func (table *IndexTable) Init() {
	table.Lock()
	defer table.Unlock()
	table.table = make(map[uint32]IndexTableEntry)
}

func (table *IndexTable) Delete(index uint32) {
	table.Lock()
	defer table.Unlock()
	delete(table.table, index)
}

func (table *IndexTable) SwapIndexForKeypair(index uint32, keypair *Keypair) {
	table.Lock()
	defer table.Unlock()
	entry, ok := table.table[index]
	if !ok {
		return
	}
	table.table[index] = IndexTableEntry{
		peer:      entry.peer,
		keypair:   keypair,
		handshake: nil,
	}
}

func (table *IndexTable) NewIndexForHandshake(peer *Peer, handshake *Handshake) (uint32, error) {
	for {
		// generate random index

		index, err := randUint32()
		if err != nil {
			return index, err
		}

		// check if index used

		table.RLock()
		_, ok := table.table[index]
		table.RUnlock()
		if ok {
			continue
		}

		// check again while locked

		table.Lock()
		_, found := table.table[index]
		if found {
			table.Unlock()
			continue
		}
		table.table[index] = IndexTableEntry{
			peer:      peer,
			handshake: handshake,
			keypair:   nil,
		}
		table.Unlock()
		return index, nil
	}
}

func (table *IndexTable) Lookup(id uint32) IndexTableEntry {
	table.RLock()
	defer table.RUnlock()
	return table.table[id]
}
