// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package derpmap contains information about Tailscale.com's production DERP nodes.
package derpmap

import (
	"fmt"

	"tailscale.com/types/structs"
)

// World is a set of DERP server.
type World struct {
	servers []*Server
	ids     []int
	byID    map[int]*Server
	stun4   []string
	stun6   []string
}

func (w *World) IDs() []int                { return w.ids }
func (w *World) STUN4() []string           { return w.stun4 }
func (w *World) STUN6() []string           { return w.stun6 }
func (w *World) ServerByID(id int) *Server { return w.byID[id] }

// LocationOfID returns the geographic name of a node, if present.
func (w *World) LocationOfID(id int) string {
	if s, ok := w.byID[id]; ok {
		return s.Geo
	}
	return ""
}

func (w *World) NodeIDOfSTUNServer(server string) int {
	// TODO: keep reverse map? Small enough to not matter for now.
	for _, s := range w.servers {
		if s.STUN4 == server || s.STUN6 == server {
			return s.ID
		}
	}
	return 0
}

// Prod returns the production DERP nodes.
func Prod() *World {
	return prod
}

func NewTestWorld(stun ...string) *World {
	w := &World{}
	for i, s := range stun {
		w.add(&Server{
			ID:    i + 1,
			Geo:   fmt.Sprintf("Testopolis-%d", i+1),
			STUN4: s,
		})
	}
	return w
}

func NewTestWorldWith(servers ...*Server) *World {
	w := &World{}
	for _, s := range servers {
		w.add(s)
	}
	return w
}

var prod = new(World) // ... a dazzling place I never knew

func addProd(id int, geo string) {
	prod.add(&Server{
		ID:        id,
		Geo:       geo,
		HostHTTPS: fmt.Sprintf("derp%v.tailscale.com", id),
		STUN4:     fmt.Sprintf("derp%v.tailscale.com:3478", id),
		STUN6:     fmt.Sprintf("derp%v-v6.tailscale.com:3478", id),
	})
}

func (w *World) add(s *Server) {
	if s.ID == 0 {
		panic("ID required")
	}
	if _, dup := w.byID[s.ID]; dup {
		panic("duplicate prod server")
	}
	if w.byID == nil {
		w.byID = make(map[int]*Server)
	}
	w.byID[s.ID] = s
	w.ids = append(w.ids, s.ID)
	w.servers = append(w.servers, s)
	if s.STUN4 != "" {
		w.stun4 = append(w.stun4, s.STUN4)
	}
	if s.STUN6 != "" {
		w.stun6 = append(w.stun6, s.STUN6)
	}
}

func init() {
	addProd(1, "New York")
	addProd(2, "San Francisco")
	addProd(3, "Singapore")
	addProd(4, "Frankfurt")
	addProd(5, "Sydney")
}

// Server is configuration for a DERP server.
type Server struct {
	_ structs.Incomparable

	ID int

	// HostHTTPS is the HTTPS hostname.
	HostHTTPS string

	// STUN4 is the host:port of the IPv4 STUN server on this DERP
	// node. Required.
	STUN4 string

	// STUN6 optionally provides the IPv6 host:port of the STUN
	// server on the DERP node.
	// It should be an IPv6-only address for now. (We currently make lazy
	// assumptions that the server names are unique.)
	STUN6 string

	// Geo is a human-readable geographic region name of this server.
	Geo string
}

func (s *Server) String() string {
	if s == nil {
		return "<nil *derpmap.Server>"
	}
	if s.Geo != "" {
		return fmt.Sprintf("%v (%v)", s.HostHTTPS, s.Geo)
	}
	return s.HostHTTPS
}
