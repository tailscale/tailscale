// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs_test

import (
	"encoding/hex"
	"log"
	"sync"

	"tailscale.com/syncs"
)

func ExampleLockFunc() {
	var nodesMu sync.Mutex
	var nodes []string
	syncs.LockFunc(&nodesMu, func() { nodes = append(nodes, "node123") })
}

func ExampleLockValue() {
	var nodesMu sync.Mutex
	var nodes []string
	n := syncs.LockValue(&nodesMu, func() int { return len(nodes) })
	log.Printf("there are %d nodes", n)
}

func ExampleLockValues() {
	var bufferMu sync.Mutex
	var buffer string
	b, err := syncs.LockValues(&bufferMu, func() ([]byte, error) {
		return hex.DecodeString(buffer)
	})
	if err != nil {
		log.Fatalf("Decode error: %v", err)
	}
	log.Printf("decoded %d bytes", len(b))
}
