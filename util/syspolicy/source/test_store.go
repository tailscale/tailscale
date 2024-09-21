// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"fmt"
	"sync"
	"sync/atomic"

	xmaps "golang.org/x/exp/maps"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/setting"
)

var (
	_ Store      = (*TestStore)(nil)
	_ Lockable   = (*TestStore)(nil)
	_ Changeable = (*TestStore)(nil)
	_ Expirable  = (*TestStore)(nil)
)

// TestValueType is a constraint that allows types supported by [TestStore].
type TestValueType interface {
	bool | uint64 | string | []string
}

// TestSetting is a policy setting in a [TestStore].
type TestSetting[T TestValueType] struct {
	// Key is the setting's unique identifier.
	Key setting.Key
	// Error is the error to be returned by the [TestStore] when reading
	// a policy setting with the specified key.
	Error error
	// Value is the value to be returned by the [TestStore] when reading
	// a policy setting with the specified key.
	// It is only used if the Error is nil.
	Value T
}

// TestSettingOf returns a [TestSetting] representing a policy setting
// configured with the specified key and value.
func TestSettingOf[T TestValueType](key setting.Key, value T) TestSetting[T] {
	return TestSetting[T]{Key: key, Value: value}
}

// TestSettingWithError returns a [TestSetting] representing a policy setting
// with the specified key and error.
func TestSettingWithError[T TestValueType](key setting.Key, err error) TestSetting[T] {
	return TestSetting[T]{Key: key, Error: err}
}

// testReadOperation describes a single policy setting read operation.
type testReadOperation struct {
	// Key is the setting's unique identifier.
	Key setting.Key
	// Type is a value type of a read operation.
	// [setting.BooleanValue], [setting.IntegerValue], [setting.StringValue] or [setting.StringListValue]
	Type setting.Type
}

// TestExpectedReads is the number of read operations with the specified details.
type TestExpectedReads struct {
	// Key is the setting's unique identifier.
	Key setting.Key
	// Type is a value type of a read operation.
	// [setting.BooleanValue], [setting.IntegerValue], [setting.StringValue] or [setting.StringListValue]
	Type setting.Type
	// NumTimes is how many times a setting with the specified key and type should have been read.
	NumTimes int
}

func (r TestExpectedReads) operation() testReadOperation {
	return testReadOperation{r.Key, r.Type}
}

// TestStore is a [Store] that can be used in tests.
type TestStore struct {
	tb internal.TB

	done chan struct{}

	storeLock      sync.RWMutex // its RLock is exposed via [Store.Lock]/[Store.Unlock].
	storeLockCount atomic.Int32

	mu           sync.RWMutex
	suspendCount int                 // change callback are suspended if > 0
	mr, mw       map[setting.Key]any // maps for reading and writing; they're the same unless the store is suspended.
	cbs          set.HandleSet[func()]

	readsMu sync.Mutex
	reads   map[testReadOperation]int // how many times a policy setting was read
}

// NewTestStore returns a new [TestStore].
// The tb will be used to report coding errors detected by the [TestStore].
func NewTestStore(tb internal.TB) *TestStore {
	m := make(map[setting.Key]any)
	return &TestStore{
		tb:   tb,
		done: make(chan struct{}),
		mr:   m,
		mw:   m,
	}
}

// NewTestStoreOf is a shorthand for [NewTestStore] followed by [TestStore.SetBooleans],
// [TestStore.SetUInt64s], [TestStore.SetStrings] or [TestStore.SetStringLists].
func NewTestStoreOf[T TestValueType](tb internal.TB, settings ...TestSetting[T]) *TestStore {
	m := make(map[setting.Key]any)
	store := &TestStore{
		tb:   tb,
		done: make(chan struct{}),
		mr:   m,
		mw:   m,
	}
	switch settings := any(settings).(type) {
	case []TestSetting[bool]:
		store.SetBooleans(settings...)
	case []TestSetting[uint64]:
		store.SetUInt64s(settings...)
	case []TestSetting[string]:
		store.SetStrings(settings...)
	case []TestSetting[[]string]:
		store.SetStringLists(settings...)
	}
	return store
}

// Lock implements [Lockable].
func (s *TestStore) Lock() error {
	s.storeLock.RLock()
	s.storeLockCount.Add(1)
	return nil
}

// Unlock implements [Lockable].
func (s *TestStore) Unlock() {
	if s.storeLockCount.Add(-1) < 0 {
		s.tb.Fatal("negative storeLockCount")
	}
	s.storeLock.RUnlock()
}

// RegisterChangeCallback implements [Changeable].
func (s *TestStore) RegisterChangeCallback(callback func()) (unregister func(), err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	handle := s.cbs.Add(callback)
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.cbs, handle)
	}, nil
}

// ReadString implements [Store].
func (s *TestStore) ReadString(key setting.Key) (string, error) {
	defer s.recordRead(key, setting.StringValue)
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.mr[key]
	if !ok {
		return "", setting.ErrNotConfigured
	}
	if err, ok := v.(error); ok {
		return "", err
	}
	str, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w in ReadString: got %T", setting.ErrTypeMismatch, v)
	}
	return str, nil
}

// ReadUInt64 implements [Store].
func (s *TestStore) ReadUInt64(key setting.Key) (uint64, error) {
	defer s.recordRead(key, setting.IntegerValue)
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.mr[key]
	if !ok {
		return 0, setting.ErrNotConfigured
	}
	if err, ok := v.(error); ok {
		return 0, err
	}
	u64, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("%w in ReadUInt64: got %T", setting.ErrTypeMismatch, v)
	}
	return u64, nil
}

// ReadBoolean implements [Store].
func (s *TestStore) ReadBoolean(key setting.Key) (bool, error) {
	defer s.recordRead(key, setting.BooleanValue)
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.mr[key]
	if !ok {
		return false, setting.ErrNotConfigured
	}
	if err, ok := v.(error); ok {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%w in ReadBoolean: got %T", setting.ErrTypeMismatch, v)
	}
	return b, nil
}

// ReadStringArray implements [Store].
func (s *TestStore) ReadStringArray(key setting.Key) ([]string, error) {
	defer s.recordRead(key, setting.StringListValue)
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.mr[key]
	if !ok {
		return nil, setting.ErrNotConfigured
	}
	if err, ok := v.(error); ok {
		return nil, err
	}
	slice, ok := v.([]string)
	if !ok {
		return nil, fmt.Errorf("%w in ReadStringArray: got %T", setting.ErrTypeMismatch, v)
	}
	return slice, nil
}

func (s *TestStore) recordRead(key setting.Key, typ setting.Type) {
	s.readsMu.Lock()
	op := testReadOperation{key, typ}
	num := s.reads[op]
	num++
	mak.Set(&s.reads, op, num)
	s.readsMu.Unlock()
}

func (s *TestStore) ResetCounters() {
	s.readsMu.Lock()
	clear(s.reads)
	s.readsMu.Unlock()
}

// ReadsMustEqual fails the test if the actual reads differs from the specified reads.
func (s *TestStore) ReadsMustEqual(reads ...TestExpectedReads) {
	s.tb.Helper()
	s.readsMu.Lock()
	defer s.readsMu.Unlock()
	s.readsMustContainLocked(reads...)
	s.readMustNoExtraLocked(reads...)
}

// ReadsMustContain fails the test if the specified reads have not been made,
// or have been made a different number of times. It permits other values to be
// read in addition to the ones being tested.
func (s *TestStore) ReadsMustContain(reads ...TestExpectedReads) {
	s.tb.Helper()
	s.readsMu.Lock()
	defer s.readsMu.Unlock()
	s.readsMustContainLocked(reads...)
}

func (s *TestStore) readsMustContainLocked(reads ...TestExpectedReads) {
	s.tb.Helper()
	for _, r := range reads {
		if numTimes := s.reads[r.operation()]; numTimes != r.NumTimes {
			s.tb.Errorf("%q (%v) reads: got %v, want %v", r.Key, r.Type, numTimes, r.NumTimes)
		}
	}
}

func (s *TestStore) readMustNoExtraLocked(reads ...TestExpectedReads) {
	s.tb.Helper()
	rs := make(set.Set[testReadOperation])
	for i := range reads {
		rs.Add(reads[i].operation())
	}
	for ro, num := range s.reads {
		if !rs.Contains(ro) {
			s.tb.Errorf("%q (%v) reads: got %v, want 0", ro.Key, ro.Type, num)
		}
	}
}

// Suspend suspends the store, batching changes and notifications
// until [TestStore.Resume] is called the same number of times as Suspend.
func (s *TestStore) Suspend() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.suspendCount++; s.suspendCount == 1 {
		s.mw = xmaps.Clone(s.mr)
	}
}

// Resume resumes the store, applying the changes and invoking
// the change callbacks.
func (s *TestStore) Resume() {
	s.storeLock.Lock()
	s.mu.Lock()
	switch s.suspendCount--; {
	case s.suspendCount == 0:
		s.mr = s.mw
		s.mu.Unlock()
		s.storeLock.Unlock()
		s.notifyPolicyChanged()
	case s.suspendCount < 0:
		s.tb.Fatal("negative suspendCount")
	default:
		s.mu.Unlock()
		s.storeLock.Unlock()
	}
}

// SetBooleans sets the specified boolean settings in s.
func (s *TestStore) SetBooleans(settings ...TestSetting[bool]) {
	s.storeLock.Lock()
	for _, setting := range settings {
		if setting.Key == "" {
			s.tb.Fatal("empty keys disallowed")
		}
		s.mu.Lock()
		if setting.Error != nil {
			mak.Set(&s.mw, setting.Key, any(setting.Error))
		} else {
			mak.Set(&s.mw, setting.Key, any(setting.Value))
		}
		s.mu.Unlock()
	}
	s.storeLock.Unlock()
	s.notifyPolicyChanged()
}

// SetUInt64s sets the specified integer settings in s.
func (s *TestStore) SetUInt64s(settings ...TestSetting[uint64]) {
	s.storeLock.Lock()
	for _, setting := range settings {
		if setting.Key == "" {
			s.tb.Fatal("empty keys disallowed")
		}
		s.mu.Lock()
		if setting.Error != nil {
			mak.Set(&s.mw, setting.Key, any(setting.Error))
		} else {
			mak.Set(&s.mw, setting.Key, any(setting.Value))
		}
		s.mu.Unlock()
	}
	s.storeLock.Unlock()
	s.notifyPolicyChanged()
}

// SetStrings sets the specified string settings in s.
func (s *TestStore) SetStrings(settings ...TestSetting[string]) {
	s.storeLock.Lock()
	for _, setting := range settings {
		if setting.Key == "" {
			s.tb.Fatal("empty keys disallowed")
		}
		s.mu.Lock()
		if setting.Error != nil {
			mak.Set(&s.mw, setting.Key, any(setting.Error))
		} else {
			mak.Set(&s.mw, setting.Key, any(setting.Value))
		}
		s.mu.Unlock()
	}
	s.storeLock.Unlock()
	s.notifyPolicyChanged()
}

// SetStrings sets the specified string list settings in s.
func (s *TestStore) SetStringLists(settings ...TestSetting[[]string]) {
	s.storeLock.Lock()
	for _, setting := range settings {
		if setting.Key == "" {
			s.tb.Fatal("empty keys disallowed")
		}
		s.mu.Lock()
		if setting.Error != nil {
			mak.Set(&s.mw, setting.Key, any(setting.Error))
		} else {
			mak.Set(&s.mw, setting.Key, any(setting.Value))
		}
		s.mu.Unlock()
	}
	s.storeLock.Unlock()
	s.notifyPolicyChanged()
}

// Delete deletes the specified settings from s.
func (s *TestStore) Delete(keys ...setting.Key) {
	s.storeLock.Lock()
	for _, key := range keys {
		s.mu.Lock()
		delete(s.mw, key)
		s.mu.Unlock()
	}
	s.storeLock.Unlock()
	s.notifyPolicyChanged()
}

// Clear deletes all settings from s.
func (s *TestStore) Clear() {
	s.storeLock.Lock()
	s.mu.Lock()
	clear(s.mw)
	s.mu.Unlock()
	s.storeLock.Unlock()
	s.notifyPolicyChanged()
}

func (s *TestStore) notifyPolicyChanged() {
	s.mu.RLock()
	if s.suspendCount != 0 {
		s.mu.RUnlock()
		return
	}
	cbs := xmaps.Values(s.cbs)
	s.mu.RUnlock()

	var wg sync.WaitGroup
	wg.Add(len(cbs))
	for _, cb := range cbs {
		go func() {
			defer wg.Done()
			cb()
		}()
	}
	wg.Wait()
}

// Close closes s, notifying its users that it has expired.
func (s *TestStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		close(s.done)
		s.done = nil
	}
}

// Done implements [Expirable].
func (s *TestStore) Done() <-chan struct{} {
	return s.done
}
