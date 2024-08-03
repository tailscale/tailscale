// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package rsop facilitates [source.Store] registration via [RegisterStore]
// and provides access to the resultant policy merged from all registered sources
// via [PolicyFor].
package rsop

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/types/lazy"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/internal/lazyinit"
	"tailscale.com/util/syspolicy/internal/loggerx"
	"tailscale.com/util/syspolicy/setting"

	"tailscale.com/util/syspolicy/source"
)

var errResultantPolicyClosed = errors.New("resultant policy closed")

// The minimum and maximum wait times after detecting a policy change
// before reloading the policy.
// Policy changes occurring within [policyReloadMinDelay] of each other
// will be batched together, resulting in a single policy reload
// no later than [policyReloadMaxDelay] after the first detected change.
// In other words, the resultant policy will be reloaded no more often than once
// every 5 seconds, but at most 15 seconds after an underlying [source.Store]
// has issued a policy change callback.
// See [Policy.watchReload].
const (
	defaultPolicyReloadMinDelay = 5 * time.Second
	defaultPolicyReloadMaxDelay = 15 * time.Second
)

// policyReloadMinDelay and policyReloadMaxDelay are test hooks.
// Their values default to [defaultPolicyReloadMinDelay] and [defaultPolicyReloadMaxDelay].
var (
	policyReloadMinDelay, policyReloadMaxDelay lazy.SyncValue[time.Duration]
)

// Policy provides access to the current resultant [setting.Snapshot] for a given
// scope and allows to reload it from the underlying [source.Store]s. It also allows to
// subscribe and receive a callback whenever the resultant [setting.Snapshot] is
// changed. It is safe for concurrent use.
type Policy struct {
	scope setting.PolicyScope

	reloadCh       chan reloadRequest       // 1-buffered; written to when a policy reload is required
	changeSourceCh chan sourceChangeRequest // written to to add a new or remove an existing source
	closeCh        chan struct{}            // closed to signal that the Policy is being closed
	doneCh         chan struct{}            // closed by closeInternal when watchReload exits

	// resultant is the most recent version of the [setting.Snapshot] containing policy settings
	// merged from all applicable sources.
	resultant atomic.Pointer[setting.Snapshot]

	changeCallbacks policyChangeCallbacks

	mu      sync.RWMutex
	sources source.ReadableSources
	closing bool // Close was called (even if we're still closing)
}

// newPolicy returns a new [Policy] for the specified [setting.PolicyScope]
// that tracks changes and merges policy settings read from the specified sources.
func newPolicy(scope setting.PolicyScope, sources ...*source.Source) (p *Policy, err error) {
	readableSources := source.ReadableSources(make([]source.ReadableSource, len(sources)))
	for i, s := range sources {
		reader, err := s.Reader()
		if err != nil {
			return nil, fmt.Errorf("failed to get a store reader: %v", err)
		}
		session, err := reader.OpenSession()
		if err != nil {
			return nil, fmt.Errorf("failed to open a reading session: %v", err)
		}

		readableSource := source.ReadableSource{
			Source:         s,
			ReadingSession: session,
		}
		readableSources[i] = readableSource
		defer func() {
			if err != nil {
				readableSource.Close()
			}
		}()
	}

	// Sort policy sources by their precedence from lower to higher.
	// For example, {UserPolicy},{ProfilePolicy},{DevicePolicy}.
	readableSources.StableSort()

	p = &Policy{
		scope:          scope,
		sources:        readableSources,
		reloadCh:       make(chan reloadRequest, 1),
		changeSourceCh: make(chan sourceChangeRequest),
		closeCh:        make(chan struct{}),
		doneCh:         make(chan struct{}),
	}
	if err := p.start(); err != nil {
		return nil, err
	}
	return p, nil
}

// IsValid reports whether p is in a valid state and has not been closed.
func (p *Policy) IsValid() bool {
	select {
	case <-p.closeCh:
		return false
	default:
		return true
	}
}

// Scope returns the [setting.PolicyScope] that this resultant policy applies to.
func (p *Policy) Scope() setting.PolicyScope {
	return p.scope
}

// Get returns the most recent resultant [setting.Snapshot].
func (p *Policy) Get() *setting.Snapshot {
	return p.resultant.Load()
}

// RegisterChangeCallback adds a function to be called whenever the resultant
// policy changes. The returned function can be used to unregister the callback.
func (p *Policy) RegisterChangeCallback(callback PolicyChangeCallback) (unregister func()) {
	return p.changeCallbacks.Register(callback)
}

// Reload synchronously re-reads policy settings from the underlying policy
// [source.Store], constructing a new merged [setting.Snapshot] even if the policy remains
// unchanged. In most scenarios, there's no need to re-read the policy manually.
// Instead, it is recommended to register a policy change callback, or to use
// the most recent [setting.Snapshot] returned by the [Policy.Get] method.
func (p *Policy) Reload() (*setting.Snapshot, error) {
	return p.reload(true)
}

// reload is like Reload, but allows to specify whether to re-read policy settings
// from unchanged policy sources.
func (p *Policy) reload(force bool) (*setting.Snapshot, error) {
	respCh := make(chan reloadResponse, 1)
	select {
	case p.reloadCh <- reloadRequest{force: force, respCh: respCh}:
		// continue
	case <-p.closeCh:
		return nil, errResultantPolicyClosed
	}
	select {
	case resp := <-respCh:
		return resp.policy, resp.err
	case <-p.closeCh:
		return nil, errResultantPolicyClosed
	}
}

// Done returns a channel that is closed when the [Policy] is closed.
func (p *Policy) Done() <-chan struct{} {
	return p.doneCh
}

func (p *Policy) start() error {
	if _, err := p.reloadNow(false); err != nil {
		return err
	}
	go p.watchPolicyChanges()
	go p.watchReload()
	return nil
}

// readAndMerge reads and merges policy settings from the underlying sources,
// returning a [setting.Snapshot] with the merged result.
// If the force parameter is true, it re-reads policy settings from each store
// even if no policy change was observed, and returns an error if the read
// operation fails.
func (p *Policy) readAndMerge(force bool) (*setting.Snapshot, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	// Start with an empty policy in the target scope.
	resultant := setting.NewSnapshot(nil, setting.SummaryWith(p.scope))
	// Then merge policy settings from all sources.
	// Policy sources with the highest precedence (e.g., the device policy) are merged last,
	// overriding any conflicting policy settings with lower precedence.
	for _, s := range p.sources {
		var policy *setting.Snapshot
		if force {
			var err error
			if policy, err = s.ReadSettings(); err != nil {
				return nil, err
			}
		} else {
			policy = s.GetSettings()
		}
		resultant = setting.MergeSnapshots(resultant, policy)
	}
	return resultant, nil
}

// reloadAsync requests an asynchronous background policy reload.
// The policy will be reloaded no later than in [policyReloadMaxDelay].
func (p *Policy) reloadAsync() {
	select {
	case p.reloadCh <- reloadRequest{}:
		// Sent.
	default:
		// A reload request is already en route.
	}
}

// reloadNow loads and merges policies from all sources, updating the resultant policy.
// If the force parameter is true, it forcibly reloads policies
// from the underlying policy store, even if no policy changes were detected.
//
// Except for the initial policy reload during the [Policy] creation,
// this method should only be called from the [Policy.watchReload] goroutine.
func (p *Policy) reloadNow(force bool) (*setting.Snapshot, error) {
	new, err := p.readAndMerge(force)
	if err != nil {
		return nil, err
	}
	old := p.resultant.Swap(new)
	// A nil old value indicates the initial policy load rather than a policy change.
	// Additionally, we should not invoke the policy change callbacks unless the
	// policy items have actually changed.
	if old != nil && !old.EqualItems(new) {
		snapshots := Change[*setting.Snapshot]{New: new, Old: old}
		p.changeCallbacks.Invoke(snapshots)
	}
	return new, nil
}

// AddSource adds the specified source to the list of sources used by p,
// and triggers a synchronous policy refresh. It returns an error
// if the source is not a valid source for this resultant policy,
// or if the resultant policy is being closed,
// or if policy refresh fails with an error.
func (p *Policy) AddSource(source *source.Source) error {
	return p.changeSource(source, nil)
}

// RemoveSource removes the specified source from the list of sources used by p,
// and triggers a synchronous policy refresh. It returns an error if the
// resultant policy is being closed, or if policy refresh fails with an error.
func (p *Policy) RemoveSource(source *source.Source) error {
	return p.changeSource(nil, source)
}

// ReplaceSource replaces the old source with the new source atomically,
// and triggers a synchronous policy refresh. It returns an error
// if the source is not a valid source for this resultant policy,
// or if the resultant policy is being closed,
// or if policy refresh fails with an error.
func (p *Policy) ReplaceSource(old, new *source.Source) error {
	return p.changeSource(new, old)
}

func (p *Policy) changeSource(toAdd, toRemove *source.Source) error {
	if toAdd == toRemove {
		return nil
	}
	if toAdd != nil && !p.scope.IsWithinOf(toAdd.Scope()) {
		return errors.New("scope mismatch")
	}
	respCh := make(chan error, 1)
	req := sourceChangeRequest{toAdd, toRemove, respCh}
	select {
	case p.changeSourceCh <- req:
		return <-respCh
	case <-p.closeCh:
		return errResultantPolicyClosed
	}
}

// watchPolicyChanges awaits a policy change notification from any of the sources
// and calls reloadAsync whenever a notification is received.
func (p *Policy) watchPolicyChanges() {
	const (
		closeIdx = iota
		changeSourceIdx
		policyChangedOffset
	)

	// The cases are Close, ChangeSource, PolicyChanged[0],...,PolicyChanged[N-1].
	p.mu.RLock()
	cases := make([]reflect.SelectCase, len(p.sources)+policyChangedOffset)
	// Add the PolicyChanged[N] cases.
	for i, source := range p.sources {
		cases[i+policyChangedOffset] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(source.PolicyChanged())}
	}
	// Add the Close case.
	cases[closeIdx] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(p.closeCh)}
	// Add the ChangeSource case.
	cases[changeSourceIdx] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(p.changeSourceCh)}
	p.mu.RUnlock()

	for {
		switch chosen, recv, ok := reflect.Select(cases); chosen {
		case closeIdx: // Close
			// Exit the watch as the closeCh was closed, indicating that
			// the [Policy] is being closed.
			return
		case changeSourceIdx: // ChangeSource
			// We've received a source change request from one of the AddSource,
			// RemoveSource, or ReplaceSource methods, meaning that we need to:
			//  - Open a reader session if a new source is being added;
			//  - Update the p.sources slice;
			//  - Update the cases slice;
			//  - Trigger a synchronous policy reload;
			//  - Report an error, if any, back to the caller.
			req := recv.Interface().(sourceChangeRequest)
			needClose, err := func() (close bool, err error) {
				p.mu.Lock()
				defer p.mu.Unlock()
				if req.toAdd != nil {
					if !p.sources.Contains(req.toAdd) {
						reader, err := req.toAdd.Reader()
						if err != nil {
							return false, fmt.Errorf("failed to get a store reader: %v", err)
						}
						session, err := reader.OpenSession()
						if err != nil {
							return false, fmt.Errorf("failed to open a reading session: %v", err)
						}

						addAt := p.sources.InsertionIndexOf(req.toAdd)
						toAdd := source.ReadableSource{
							Source:         req.toAdd,
							ReadingSession: session,
						}
						p.sources = slices.Insert(p.sources, addAt, toAdd)
						newCase := reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(toAdd.PolicyChanged())}
						caseIndex := addAt + policyChangedOffset
						cases = slices.Insert(cases, caseIndex, newCase)
					}
				}
				if req.toDelete != nil {
					if deleteAt := p.sources.IndexOf(req.toDelete); deleteAt != -1 {
						p.sources.DeleteAt(deleteAt)
						caseIndex := deleteAt + policyChangedOffset
						cases = slices.Delete(cases, caseIndex, caseIndex+1)
					}
				}
				return len(p.sources) == 0, nil
			}()
			if err == nil {
				if needClose {
					// Close the resultant policy if the last policy source was deleted.
					p.Close()
				} else {
					// Otherwise, reload the policy synchronously.
					_, err = p.reload(false)
				}
			}
			req.respCh <- err
		default: // PolicyChanged[N]
			if !ok {
				// One of the PolicyChanged channels was closed, indicating that
				// the corresponding [source.Source] is no longer valid.
				// We can no longer keep this [Policy] up to date
				// and should close it.
				p.Close()
				return
			}

			// One of the PolicyChanged channels was signaled.
			// We should request an asynchronous policy reload.
			p.reloadAsync()
		}
	}
}

// watchReload processes incoming synchronous and asynchronous policy reload requests.
// Synchronous requests (with a non-nil respCh) are served immediately.
// Asynchronous requests are debounced and throttled: they are executed at least
// [policyReloadMinDelay] after the last request, but no later than [policyReloadMaxDelay]
// after the first request in a batch.
func (p *Policy) watchReload() {
	force := false // whether a forced refresh was requested
	var delayCh, timeoutCh <-chan time.Time
	reload := func(respCh chan<- reloadResponse) {
		delayCh, timeoutCh = nil, nil
		policy, err := p.reloadNow(force)
		if err != nil {
			loggerx.Errorf("%v policy reload failed: %v\n", p.scope, err)
		}
		if respCh != nil {
			respCh <- reloadResponse{policy: policy, err: err}
		}
		force = false
	}

loop:
	for {
		select {
		case req := <-p.reloadCh:
			if req.force {
				force = true
			}
			if req.respCh != nil {
				reload(req.respCh)
				continue
			}
			if delayCh == nil {
				timeoutCh = time.After(policyReloadMaxDelay.Get(func() time.Duration { return defaultPolicyReloadMaxDelay }))
			}
			delayCh = time.After(policyReloadMinDelay.Get(func() time.Duration { return defaultPolicyReloadMinDelay }))
		case <-delayCh:
			reload(nil)
		case <-timeoutCh:
			reload(nil)
		case <-p.closeCh:
			break loop
		}
	}

	p.closeInternal()
}

func (p *Policy) closeInternal() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sources.Close()
	p.changeCallbacks.Close()
	close(p.doneCh)
}

// Close initiates the closing of the resultant policy.
// The actual closing is performed by closeInternal when watchReload exits,
// and the Done() channel is closed when closeInternal finishes.
func (p *Policy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return
	}
	p.closing = true
	close(p.closeCh)
}

// sourceChangeRequest is a request to add and/or remove source from a [Policy].
type sourceChangeRequest struct {
	toAdd, toDelete *source.Source
	respCh          chan<- error
}

// reloadRequest describes a policy reload request.
type reloadRequest struct {
	// force triggers an immediate synchronous policy reload,
	// reloading the policy regardless of whether a policy change was detected.
	force bool
	// respCh is an optional channel. If non-nil, it makes the reload request
	// synchronous and receives the result.
	respCh chan<- reloadResponse
}

type reloadResponse struct {
	policy *setting.Snapshot
	err    error
}

var (
	policyMu          sync.RWMutex
	policySources     []*source.Source
	resultantPolicies []*Policy

	resultantPolicyLRU [setting.MaxSettingScope + 1]syncs.AtomicValue[*Policy] // by [Scope.Kind]
)

// registerSource registers the specified [source.Source] to be used by the package.
// It updates existing [Policy]s returned by [PolicyFor] to use this source if
// they are within the source's [setting.PolicyScope].
func registerSource(source *source.Source) error {
	policyMu.Lock()
	defer policyMu.Unlock()
	if slices.Contains(policySources, source) {
		return nil
	}
	policySources = append(policySources, source)
	return forEachResultantPolicyLocked(func(policy *Policy) error {
		if !policy.Scope().IsWithinOf(source.Scope()) {
			return nil
		}
		return policy.AddSource(source)
	})
}

// replaceSource is like [unregisterSource](old) followed by [registerSource](new),
// but is atomic from the perspective of each [Policy].
func replaceSource(old, new *source.Source) error {
	policyMu.Lock()
	defer policyMu.Unlock()
	oldIndex := slices.Index(policySources, old)
	if oldIndex == -1 {
		return fmt.Errorf("the source is not registered: %v", old)
	}
	policySources[oldIndex] = new
	return forEachResultantPolicyLocked(func(policy *Policy) error {
		if policy.Scope().IsWithinOf(old.Scope()) || policy.Scope().IsWithinOf(new.Scope()) {
			return nil
		}
		return policy.ReplaceSource(old, new)
	})
}

// unregisterSource unregisters the specified [source.Source],
// so that it won't be used by any new or existing [Policy].
func unregisterSource(source *source.Source) error {
	policyMu.Lock()
	defer policyMu.Unlock()
	index := slices.Index(policySources, source)
	if index == -1 {
		return nil
	}
	policySources = slices.Delete(policySources, index, index+1)
	return forEachResultantPolicyLocked(func(policy *Policy) error {
		if !policy.Scope().IsWithinOf(source.Scope()) {
			return nil
		}
		return policy.RemoveSource(source)
	})
}

// forEachResultantPolicyLocked calls fn for every [Policy] in [resultantPolicies].
// It accumulates the returned errors, except for [errResultantPolicyClosed],
// and returns an error that wraps all errors returned by fn.
// The [policyMu] mutex must be held while this function is executed.
func forEachResultantPolicyLocked(fn func(p *Policy) error) error {
	var errs []error
	for _, policy := range resultantPolicies {
		err := fn(policy)
		if err != nil && !errors.Is(err, errResultantPolicyClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// PolicyFor returns the [Policy] for the specified scope,
// creating one from the registered [source.Store]s if it does not exist.
func PolicyFor(scope setting.PolicyScope) (*Policy, error) {
	if err := lazyinit.Do(); err != nil {
		return nil, err
	}
	if policy := resultantPolicyLRU[scope.Kind()].Load(); policy != nil && policy.Scope() == scope && policy.IsValid() {
		return policy, nil
	}
	return policyForSlow(scope)
}

func policyForSlow(scope setting.PolicyScope) (policy *Policy, err error) {
	defer func() {
		if policy != nil {
			resultantPolicyLRU[scope.Kind()].Store(policy)
		}
	}()

	policyMu.RLock()
	if policy, ok := findPolicyByScopeLocked(scope); ok {
		policyMu.RUnlock()
		return policy, nil
	}
	policyMu.RUnlock()

	policyMu.Lock()
	defer policyMu.Unlock()
	if policy, ok := findPolicyByScopeLocked(scope); ok {
		return policy, nil
	}
	sources := slicesx.Filter(nil, policySources, func(source *source.Source) bool {
		return scope.IsWithinOf(source.Scope())
	})
	policy, err = newPolicy(scope, sources...)
	if err != nil {
		return nil, err
	}
	resultantPolicies = append(resultantPolicies, policy)
	go func() {
		<-policy.Done()
		deletePolicy(policy)
	}()
	return policy, nil
}

// findPolicyByScopeLocked returns a policy with the specified scope and true if
// one exists, otherwise it returns nil, false.
// [policyMu] must be held.
func findPolicyByScopeLocked(target setting.PolicyScope) (policy *Policy, ok bool) {
	for _, policy := range resultantPolicies {
		if policy.Scope() == target && policy.IsValid() {
			return policy, true
		}
	}
	return nil, false
}

// deletePolicy deletes the specified resultant policy from the [resultantPolicies] list.
func deletePolicy(policy *Policy) {
	policyMu.Lock()
	if i := slices.Index(resultantPolicies, policy); i != -1 {
		resultantPolicies = slices.Delete(resultantPolicies, i, i+1)
	}
	resultantPolicyLRU[policy.Scope().Kind()].CompareAndSwap(policy, nil)
	policyMu.Unlock()
}

// ErrAlreadyConsumed is the error returned when [StoreRegistration.ReplaceStore]
// or [StoreRegistration.Unregister] is called more than once.
var ErrAlreadyConsumed = errors.New("the store registration is no longer valid")

// StoreRegistration is a [source.Store] registered for use in the specified scope.
// It can be used to unregister the store, or replace it with another one.
type StoreRegistration struct {
	source   *source.Source
	consumed atomic.Uint32
	m        sync.Mutex
}

// RegisterStore registers a new policy [source.Store] with the specified name and [setting.PolicyScope].
func RegisterStore(name string, scope setting.PolicyScope, store source.Store) (*StoreRegistration, error) {
	return newStoreRegistration(name, scope, store)
}

// RegisterStoreForTest is like [RegisterStore], but unregisters the store when
// tb and all its subtests complete.
func RegisterStoreForTest(tb internal.TB, name string, scope setting.PolicyScope, store source.Store) (*StoreRegistration, error) {
	reg, err := RegisterStore(name, scope, store)
	if err == nil {
		tb.Cleanup(func() {
			if err := reg.Unregister(); err != nil && !errors.Is(err, ErrAlreadyConsumed) {
				tb.Fatalf("Unregister failed: %v", err)
			}
		})
	}
	return reg, err // may be nil or non-nil
}

func newStoreRegistration(name string, scope setting.PolicyScope, store source.Store) (*StoreRegistration, error) {
	source := source.NewSource(name, scope, store)
	if err := registerSource(source); err != nil {
		return nil, err
	}
	return &StoreRegistration{source: source}, nil
}

// ReplaceStore replaces the registered store with the new one,
// returning a new [StoreRegistration] or an error.
func (r *StoreRegistration) ReplaceStore(new source.Store) (*StoreRegistration, error) {
	var res *StoreRegistration
	err := r.consume(func() error {
		newSource := source.NewSource(r.source.Name(), r.source.Scope(), new)
		if err := replaceSource(r.source, newSource); err != nil {
			return err
		}
		res = &StoreRegistration{source: newSource}
		return nil
	})
	return res, err
}

// Unregister reverts the registration.
func (r *StoreRegistration) Unregister() error {
	return r.consume(func() error { return unregisterSource(r.source) })
}

// consume invokes fn, consuming r if no error is returned.
// It returns [ErrAlreadyConsumed] on subsequent calls after the first successful call.
func (r *StoreRegistration) consume(fn func() error) (err error) {
	if r.consumed.Load() != 0 {
		return ErrAlreadyConsumed
	}
	return r.consumeSlow(fn)
}

func (r *StoreRegistration) consumeSlow(fn func() error) (err error) {
	r.m.Lock()
	defer r.m.Unlock()
	if r.consumed.Load() != 0 {
		return ErrAlreadyConsumed
	}
	if err = fn(); err == nil {
		r.consumed.Store(1)
	}
	return err // may be nil or non-nil
}
