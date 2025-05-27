// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !loong64

package tsconsensus

import (
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

func boltStore(path string) (raft.StableStore, raft.LogStore, error) {
	store, err := raftboltdb.NewBoltStore(path)
	if err != nil {
		return nil, nil, err
	}
	return store, store, nil
}
