// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build loong64

package tsconsensus

import (
	"errors"

	"github.com/hashicorp/raft"
)

func boltStore(path string) (raft.StableStore, raft.LogStore, error) {
	// "github.com/hashicorp/raft-boltdb/v2" doesn't build on loong64
	// see https://github.com/hashicorp/raft-boltdb/issues/27
	return nil, nil, errors.New("not implemented")
}
