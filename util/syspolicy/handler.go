// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"
	"sync/atomic"
	"testing"
)

var (
	handlerUsed atomic.Bool
	handler     Handler = defaultHandler{}
)

// Handler reads system policies from OS-specific storage.
type Handler interface {
	// ReadString reads the policy settings value string given the key.
	ReadString(key string) (string, error)
	// ReadUInt64 reads the policy settings uint64 value given the key.
	ReadUInt64(key string) (uint64, error)
	// ReadBool reads the policy setting's boolean value, given the key.
	ReadBoolean(key string) (bool, error)
}

// ErrNoSuchKey is returned when the specified key does not have a value set.
var ErrNoSuchKey = errors.New("no such key")

// defaultHandler is the catch all syspolicy type for anything that isn't windows or apple.
type defaultHandler struct{}

func (defaultHandler) ReadString(_ string) (string, error) {
	return "", ErrNoSuchKey
}

func (defaultHandler) ReadUInt64(_ string) (uint64, error) {
	return 0, ErrNoSuchKey
}

func (defaultHandler) ReadBoolean(_ string) (bool, error) {
	return false, ErrNoSuchKey
}

// markHandlerInUse is called before handler methods are called.
func markHandlerInUse() {
	handlerUsed.Store(true)
}

// RegisterHandler initializes the policy handler and ensures registration will happen once.
func RegisterHandler(h Handler) {
	// Technically this assignment is not concurrency safe, but in the
	// event that there was any risk of a data race, we will panic due to
	// the CompareAndSwap failing.
	handler = h
	if !handlerUsed.CompareAndSwap(false, true) {
		panic("handler was already used before registration")
	}
}

func SetHandlerForTest(tb testing.TB, h Handler) {
	tb.Helper()
	oldHandler := handler
	handler = h
	tb.Cleanup(func() { handler = oldHandler })
}
