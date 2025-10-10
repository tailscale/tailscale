// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=true -type SliceContainer,InterfaceContainer

// Package clonerex is an example package for the cloner tool.
package clonerex

type SliceContainer struct {
	Slice []*int
}

// Cloneable is an interface with a Clone method.
type Cloneable interface {
	Clone() Cloneable
}

// CloneableImpl is a concrete type that implements Cloneable.
type CloneableImpl struct {
	Value int
}

func (c *CloneableImpl) Clone() Cloneable {
	if c == nil {
		return nil
	}
	return &CloneableImpl{Value: c.Value}
}

// InterfaceContainer has a pointer to an interface field, which tests
// the special handling for interface types in the cloner.
type InterfaceContainer struct {
	Interface Cloneable
}
