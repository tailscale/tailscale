// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"sync"
	"time"

	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy/internal/loggerx"
	"tailscale.com/util/syspolicy/internal/metrics"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/syspolicy/setting"
)

// Reader reads all configured policy settings from a given [Store].
// It registers a change callback with the [Store] and maintains the current version
// of the [setting.Snapshot] by lazily re-reading policy settings from the [Store]
// whenever a new settings snapshot is requested with [Reader.GetSettings].
// It is safe for concurrent use.
type Reader struct {
	store                    Store
	origin                   *setting.Origin
	settings                 []*setting.Definition
	unregisterChangeNotifier func()
	doneCh                   chan struct{} // closed when [Reader] is closed.

	mu         sync.Mutex
	closing    bool
	upToDate   bool
	lastPolicy *setting.Snapshot
	sessions   set.HandleSet[*ReadingSession]
}

// newReader returns a new [Reader] that reads policy settings from a given [Store].
// The returned reader takes ownership of the store. If the store implements [io.Closer],
// the returned reader will close the store when it is closed.
func newReader(store Store, origin *setting.Origin) (*Reader, error) {
	settings, err := setting.Definitions()
	if err != nil {
		return nil, err
	}

	if expirable, ok := store.(Expirable); ok {
		select {
		case <-expirable.Done():
			return nil, ErrStoreClosed
		default:
		}
	}

	reader := &Reader{store: store, origin: origin, settings: settings, doneCh: make(chan struct{})}
	if changeable, ok := store.(Changeable); ok {
		// We should subscribe to policy change notifications first before reading
		// the policy settings from the store. This way we won't miss any notifications.
		if reader.unregisterChangeNotifier, err = changeable.RegisterChangeCallback(reader.onPolicyChange); err != nil {
			// Errors registering policy change callbacks are non-fatal.
			// TODO(nickkhyl): implement a background policy refresh every X minutes?
			loggerx.Errorf("failed to register %v policy change callback: %v", origin, err)
		}
	}

	if _, err := reader.reload(true); err != nil {
		if reader.unregisterChangeNotifier != nil {
			reader.unregisterChangeNotifier()
		}
		return nil, err
	}

	if expirable, ok := store.(Expirable); ok {
		if waitCh := expirable.Done(); waitCh != nil {
			go func() {
				select {
				case <-waitCh:
					reader.Close()
				case <-reader.doneCh:
				}
			}()
		}
	}

	return reader, nil
}

// GetSettings returns the current [*setting.Snapshot],
// re-reading it from from the underlying [Store] only if the policy
// has changed since it was read last. It never fails and returns
// the previous version of the policy settings if a read attempt fails.
func (r *Reader) GetSettings() *setting.Snapshot {
	r.mu.Lock()
	upToDate, lastPolicy := r.upToDate, r.lastPolicy
	r.mu.Unlock()
	if upToDate {
		return lastPolicy
	}

	policy, err := r.reload(false)
	if err != nil {
		// If the policy fails to reload completely, log an error and return the last cached version.
		// However, errors related to individual policy items are always
		// propagated to callers when they fetch those settings.
		loggerx.Errorf("failed to reload %v policy: %v", r.origin, err)
	}
	return policy
}

// ReadSettings reads policy settings from the underlying [Store] even if no
// changes were detected. It returns the new [*setting.Snapshot],nil on
// success or an undefined snapshot (possibly `nil`) along with a non-`nil`
// error in case of failure.
func (r *Reader) ReadSettings() (*setting.Snapshot, error) {
	return r.reload(true)
}

// reload is like [Reader.ReadSettings], but allows specifying whether to re-read
// an unchanged policy, and returns the last [*setting.Snapshot] if the read fails.
func (r *Reader) reload(force bool) (*setting.Snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.upToDate && !force {
		return r.lastPolicy, nil
	}

	if lockable, ok := r.store.(Lockable); ok {
		if err := lockable.Lock(); err != nil {
			return r.lastPolicy, err
		}
		defer lockable.Unlock()
	}

	r.upToDate = true

	metrics.Reset(r.origin)

	var m map[pkey.Key]setting.RawItem
	if lastPolicyCount := r.lastPolicy.Len(); lastPolicyCount > 0 {
		m = make(map[pkey.Key]setting.RawItem, lastPolicyCount)
	}
	for _, s := range r.settings {
		if !r.origin.Scope().IsConfigurableSetting(s) {
			// Skip settings that cannot be configured in the current scope.
			continue
		}

		val, err := readPolicySettingValue(r.store, s)
		if err != nil && (errors.Is(err, setting.ErrNoSuchKey) || errors.Is(err, setting.ErrNotConfigured)) {
			metrics.ReportNotConfigured(r.origin, s)
			continue
		}

		if err == nil {
			metrics.ReportConfigured(r.origin, s, val)
		} else {
			metrics.ReportError(r.origin, s, err)
		}

		// If there's an error reading a single policy, such as a value type mismatch,
		// we'll wrap the error to preserve its text and return it
		// whenever someone attempts to fetch the value.
		// Otherwise, the errorText will be nil.
		errorText := setting.MaybeErrorText(err)
		item := setting.RawItemWith(val, errorText, r.origin)
		mak.Set(&m, s.Key(), item)
	}

	newPolicy := setting.NewSnapshot(m, setting.SummaryWith(r.origin))
	if r.lastPolicy == nil || !newPolicy.EqualItems(r.lastPolicy) {
		r.lastPolicy = newPolicy
	}
	return r.lastPolicy, nil
}

// ReadingSession is like [Reader], but with a channel that's written
// to when there's a policy change, and closed when the session is terminated.
type ReadingSession struct {
	reader          *Reader
	policyChangedCh chan struct{} // 1-buffered channel
	handle          set.Handle    // in the reader.sessions
	closeInternal   func()
}

// OpenSession opens and returns a new session to r, allowing the caller
// to get notified whenever a policy change is reported by the [source.Store],
// or an [ErrStoreClosed] if the reader has already been closed.
func (r *Reader) OpenSession() (*ReadingSession, error) {
	session := &ReadingSession{
		reader:          r,
		policyChangedCh: make(chan struct{}, 1),
	}
	session.closeInternal = sync.OnceFunc(func() { close(session.policyChangedCh) })
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return nil, ErrStoreClosed
	}
	session.handle = r.sessions.Add(session)
	return session, nil
}

// GetSettings is like [Reader.GetSettings].
func (s *ReadingSession) GetSettings() *setting.Snapshot {
	return s.reader.GetSettings()
}

// ReadSettings is like [Reader.ReadSettings].
func (s *ReadingSession) ReadSettings() (*setting.Snapshot, error) {
	return s.reader.ReadSettings()
}

// PolicyChanged returns a channel that's written to when
// there's a policy change, closed when the session is terminated.
func (s *ReadingSession) PolicyChanged() <-chan struct{} {
	return s.policyChangedCh
}

// Close unregisters this session with the [Reader].
func (s *ReadingSession) Close() {
	s.reader.mu.Lock()
	delete(s.reader.sessions, s.handle)
	s.closeInternal()
	s.reader.mu.Unlock()
}

// onPolicyChange handles a policy change notification from the [Store],
// invalidating the current [setting.Snapshot] in r,
// and notifying the active [ReadingSession]s.
func (r *Reader) onPolicyChange() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upToDate = false
	for _, s := range r.sessions {
		select {
		case s.policyChangedCh <- struct{}{}:
			// Notified.
		default:
			// 1-buffered channel is full, meaning that another policy change
			// notification is already en route.
		}
	}
}

// Close closes the store reader and the underlying store.
func (r *Reader) Close() error {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return nil
	}
	r.closing = true
	r.mu.Unlock()

	if r.unregisterChangeNotifier != nil {
		r.unregisterChangeNotifier()
		r.unregisterChangeNotifier = nil
	}

	if closer, ok := r.store.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	r.store = nil

	close(r.doneCh)

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.sessions {
		c.closeInternal()
	}
	r.sessions = nil
	return nil
}

// Done returns a channel that is closed when the reader is closed.
func (r *Reader) Done() <-chan struct{} {
	return r.doneCh
}

// ReadableSource is a [Source] open for reading.
type ReadableSource struct {
	*Source
	*ReadingSession
}

// Close closes the underlying [ReadingSession].
func (s ReadableSource) Close() {
	s.ReadingSession.Close()
}

// ReadableSources is a slice of [ReadableSource].
type ReadableSources []ReadableSource

// Contains reports whether s contains the specified source.
func (s ReadableSources) Contains(source *Source) bool {
	return s.IndexOf(source) != -1
}

// IndexOf returns position of the specified source in s, or -1
// if the source does not exist.
func (s ReadableSources) IndexOf(source *Source) int {
	return slices.IndexFunc(s, func(rs ReadableSource) bool {
		return rs.Source == source
	})
}

// InsertionIndexOf returns the position at which source can be inserted
// to maintain the sorted order of the readableSources.
// The return value is unspecified if s is not sorted on entry to InsertionIndexOf.
func (s ReadableSources) InsertionIndexOf(source *Source) int {
	// Insert new sources after any existing sources with the same precedence,
	// and just before the first source with higher precedence.
	// Just like stable sort, but for insertion.
	// It's okay to use linear search as insertions are rare
	// and we never have more than just a few policy sources.
	higherPrecedence := func(rs ReadableSource) bool { return rs.Compare(source) > 0 }
	if i := slices.IndexFunc(s, higherPrecedence); i != -1 {
		return i
	}
	return len(s)
}

// StableSort sorts [ReadableSource] in s by precedence, so that policy
// settings from sources with higher precedence (e.g., [DeviceScope])
// will be read and merged last, overriding any policy settings with
// the same keys configured in sources with lower precedence
// (e.g., [CurrentUserScope]).
func (s *ReadableSources) StableSort() {
	sort.SliceStable(*s, func(i, j int) bool {
		return (*s)[i].Source.Compare((*s)[j].Source) < 0
	})
}

// DeleteAt closes and deletes the i-th source from s.
func (s *ReadableSources) DeleteAt(i int) {
	(*s)[i].Close()
	*s = slices.Delete(*s, i, i+1)
}

// Close closes and deletes all sources in s.
func (s *ReadableSources) Close() {
	for _, s := range *s {
		s.Close()
	}
	*s = nil
}

func readPolicySettingValue(store Store, s *setting.Definition) (value any, err error) {
	switch key := s.Key(); s.Type() {
	case setting.BooleanValue:
		return store.ReadBoolean(key)
	case setting.IntegerValue:
		return store.ReadUInt64(key)
	case setting.StringValue:
		return store.ReadString(key)
	case setting.StringListValue:
		return store.ReadStringArray(key)
	case setting.PreferenceOptionValue:
		s, err := store.ReadString(key)
		if err == nil {
			var value ptype.PreferenceOption
			if err = value.UnmarshalText([]byte(s)); err == nil {
				return value, nil
			}
		}
		return ptype.ShowChoiceByPolicy, err
	case setting.VisibilityValue:
		s, err := store.ReadString(key)
		if err == nil {
			var value ptype.Visibility
			if err = value.UnmarshalText([]byte(s)); err == nil {
				return value, nil
			}
		}
		return ptype.VisibleByPolicy, err
	case setting.DurationValue:
		s, err := store.ReadString(key)
		if err == nil {
			var value time.Duration
			if value, err = time.ParseDuration(s); err == nil {
				return value, nil
			}
		}
		return nil, err
	default:
		return nil, fmt.Errorf("%w: unsupported setting type: %v", setting.ErrTypeMismatch, s.Type())
	}
}
