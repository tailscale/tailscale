// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package peers contains helpers for looking up peers on a Tailscale network.
package peers

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
)

// A Peer is another machine connected on a users network.
type Peer struct {
	Hostname string `json:"Hostname"`
	TailAddr net.IP `json:"TailAddr"`
}

// A Queryer can be used to query for peers.
type Queryer interface {
	Query() ([]Peer, error)
}

// NewQueryer creates a new queryer object.
func NewQueryer() Queryer {
	return &queryer{}
}

type queryer struct{}

func parseCmdOutput(output []byte) ([]Peer, error) {
	var buf struct {
		Peers map[string]Peer `json:"Peer"`
	}
	if err := json.Unmarshal(output, &buf); err != nil {
		return nil, fmt.Errorf("peers: failed to parse command output: %v", err)
	}
	peers := make([]Peer, 0, len(buf.Peers))
	for _, p := range buf.Peers {
		peers = append(peers, p)
	}
	return peers, nil
}

func (q *queryer) Query() ([]Peer, error) {
	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		return nil, err
	}
	return parseCmdOutput(out)
}
