// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
)

// TODO(nickkhyl): delete this file once other repos are updated.

// Handler reads system policies from OS-specific storage.
//
// Deprecated: implementing a [source.Store] should be preferred.
type Handler interface {
	// ReadString reads the policy setting's string value for the given key.
	// It should return ErrNoSuchKey if the key does not have a value set.
	ReadString(key string) (string, error)
	// ReadUInt64 reads the policy setting's uint64 value for the given key.
	// It should return ErrNoSuchKey if the key does not have a value set.
	ReadUInt64(key string) (uint64, error)
	// ReadBool reads the policy setting's boolean value for the given key.
	// It should return ErrNoSuchKey if the key does not have a value set.
	ReadBoolean(key string) (bool, error)
	// ReadStringArray reads the policy setting's string array value for the given key.
	// It should return ErrNoSuchKey if the key does not have a value set.
	ReadStringArray(key string) ([]string, error)
}

// RegisterHandler wraps and registers the specified handler as the device's
// policy [source.Store] for the program's lifetime.
//
// Deprecated: using [RegisterStore] should be preferred.
func RegisterHandler(h Handler) {
	rsop.RegisterStore("DeviceHandler", setting.DeviceScope, WrapHandler(h))
}

// TB is a subset of testing.TB that we use to set up test helpers.
// It's defined here to avoid pulling in the testing package.
type TB = internal.TB

// SetHandlerForTest wraps and sets the specified handler as the device's policy
// [source.Store] for the duration of tb.
//
// Deprecated: using [MustRegisterStoreForTest] should be preferred.
func SetHandlerForTest(tb TB, h Handler) {
	RegisterWellKnownSettingsForTest(tb)
	MustRegisterStoreForTest(tb, "DeviceHandler-TestOnly", setting.DefaultScope(), WrapHandler(h))
}

var _ source.Store = (*handlerStore)(nil)

// handlerStore is a [source.Store] that calls the underlying [Handler].
//
// TODO(nickkhyl): remove it when the corp and android repos are updated.
type handlerStore struct {
	h Handler
}

// WrapHandler returns a [source.Store] that wraps the specified [Handler].
func WrapHandler(h Handler) source.Store {
	return handlerStore{h}
}

// Lock implements [source.Lockable].
func (s handlerStore) Lock() error {
	if lockable, ok := s.h.(source.Lockable); ok {
		return lockable.Lock()
	}
	return nil
}

// Unlock implements [source.Lockable].
func (s handlerStore) Unlock() {
	if lockable, ok := s.h.(source.Lockable); ok {
		lockable.Unlock()
	}
}

// RegisterChangeCallback implements [source.Changeable].
func (s handlerStore) RegisterChangeCallback(callback func()) (unregister func(), err error) {
	if changeable, ok := s.h.(source.Changeable); ok {
		return changeable.RegisterChangeCallback(callback)
	}
	return func() {}, nil
}

// ReadString implements [source.Store].
func (s handlerStore) ReadString(key setting.Key) (string, error) {
	return s.h.ReadString(string(key))
}

// ReadUInt64 implements [source.Store].
func (s handlerStore) ReadUInt64(key setting.Key) (uint64, error) {
	return s.h.ReadUInt64(string(key))
}

// ReadBoolean implements [source.Store].
func (s handlerStore) ReadBoolean(key setting.Key) (bool, error) {
	return s.h.ReadBoolean(string(key))
}

// ReadStringArray implements [source.Store].
func (s handlerStore) ReadStringArray(key setting.Key) ([]string, error) {
	return s.h.ReadStringArray(string(key))
}

// Done implements [source.Expirable].
func (s handlerStore) Done() <-chan struct{} {
	if expirable, ok := s.h.(source.Expirable); ok {
		return expirable.Done()
	}
	return nil
}
