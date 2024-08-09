// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"cmp"
	"errors"
	"fmt"
	"io"

	"tailscale.com/types/lazy"
	"tailscale.com/util/syspolicy/setting"
)

// ErrStoreClosed is an error returned when attempting to use a [Store] after it
// has been closed.
var ErrStoreClosed = errors.New("the policy store has been closed")

// Store provides methods to read system policy settings from OS-specific storage.
// Implementations must be concurrency-safe, and may also implement
// [Lockable], [Changeable], [Expirable] and [io.Closer].
//
// If a [Store] implementation also implements [io.Closer],
// it will be called by the package to release the resources
// when the store is no longer needed.
type Store interface {
	// ReadString returns the value of a [setting.StringValue] with the specified key,
	// an [setting.ErrNotConfigured] if the policy setting is not configured, or
	// an [setting.ErrTypeMismatch] if the policy setting is not of a string type.
	ReadString(key setting.Key) (string, error)
	// ReadUInt64 returns the value of a [setting.IntegerValue] with the specified key,
	// an [setting.ErrNotConfigured] if the policy setting is not configured, or
	// an [setting.ErrTypeMismatch] if the policy setting is not of a string type.
	ReadUInt64(key setting.Key) (uint64, error)
	// ReadBoolean returns the value of a [setting.BooleanValue] with the specified key,
	// an [setting.ErrNotConfigured] if the policy setting is not configured, or
	// an [setting.ErrTypeMismatch] if the policy setting is not of a string type.
	ReadBoolean(key setting.Key) (bool, error)
	// ReadStringArray returns the value of a [setting.StringListValue] with the specified key,
	// an [setting.ErrNotConfigured] if the policy setting is not configured, or
	// an [setting.ErrTypeMismatch] if the policy setting is not of a string list type.
	ReadStringArray(key setting.Key) ([]string, error)
}

// Lockable is an optional interface that [Store] implementations may support.
// Locking a [Store] is not mandatory as [Store] must be concurrency-safe,
// but is recommended to avoid issues where consecutive read calls for related
// policies might return inconsistent results if a policy change occurs between
// the calls.
type Lockable interface {

	// Lock acquires a read lock on the policy store,
	// ensuring the store's state remains unchanged while locked.
	// Multiple readers can hold the lock simultaneously.
	// It should return nil if the store does not support locking,
	// or an error if the store cannot be locked.
	Lock() error
	// Unlock unlocks the policy store.
	// It is a runtime error if the store is not locked on entry to Unlock.
	Unlock()
}

// Changeable is an optional interface that [Store] implementations may support.
type Changeable interface {
	// RegisterChangeCallback adds a function that will be called
	// whenever there's a policy change in the [Store].
	// The returned function can be used to unregister the callback.
	RegisterChangeCallback(callback func()) (unregister func(), err error)
}

// Expirable is an optional interface that [Store] implementations may support.
type Expirable interface {
	// Done returns a channel that is closed when the policy [Store] should no longer be used.
	// It should return nil if the store never expires.
	Done() <-chan struct{}
}

// Source represents a named source of policy settings for a given scope.
type Source struct {
	name   string
	scope  setting.PolicyScope
	store  Store
	origin *setting.Origin

	lazyReader lazy.SyncValue[*Reader]
}

// NewSource returns a new [Source] with the specified name, scope, and store.
func NewSource(name string, scope setting.PolicyScope, store Store) *Source {
	return &Source{name: name, scope: scope, store: store, origin: setting.NewNamedOrigin(name, scope)}
}

// Name reports the name of the policy source.
func (s *Source) Name() string {
	return s.name
}

// Scope reports the management scope of the policy source.
func (s *Source) Scope() setting.PolicyScope {
	return s.scope
}

// Store returns the [Store] that can be used to read policy settings from this source.
func (s *Source) Store() Store {
	return s.store
}

// Reader returns a [Reader] that reads from this source's [Store].
func (s *Source) Reader() (*Reader, error) {
	return s.lazyReader.GetErr(func() (*Reader, error) {
		return newReader(s.store, s.origin)
	})
}

// String implements [fmt.Stringer].
func (s *Source) String() string {
	if s.Name() != "" {
		return fmt.Sprintf("%s (%v)", s.Name(), s.Scope())
	}
	return s.Scope().String()
}

// Compare returns an integer comparing [Source] s and s2
// by their precedence, following the "last-wins" model.
// The result will be:
//
//	-1 if policy settings from s should be processed before policy settings from s2;
//	+1 if policy settings from s should be processed after policy settings from s2, overriding s2;
//	0 if the relative processing order of policy settings in s and s2 is unspecified.
func (s *Source) Compare(s2 *Source) int {
	return cmp.Compare(s2.Scope().Kind(), s.Scope().Kind())
}

// Close closes the [Source] and the underlying [Store].
func (s *Source) Close() error {
	// The [Reader], if any, owns the [Store].
	if reader, _ := s.lazyReader.GetErr(func() (*Reader, error) { return nil, ErrStoreClosed }); reader != nil {
		return reader.Close()
	}
	// Otherwise, it is our responsibility to close it.
	if closer, ok := s.store.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
