// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rsop

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/internal/loggerx"
	"tailscale.com/util/syspolicy/setting"

	"tailscale.com/util/syspolicy/source"
)

// ErrPolicyClosed is returned by [Policy.Reload], [Policy.addSource],
// [Policy.removeSource] and [Policy.replaceSource] if the policy has been closed.
var ErrPolicyClosed = errors.New("effective policy closed")

// The minimum and maximum wait times after detecting a policy change
// before reloading the policy. This only affects policy reloads triggered
// by a change in the underlying [source.Store] and does not impact
// synchronous, caller-initiated reloads, such as when [Policy.Reload] is called.
//
// Policy changes occurring within [policyReloadMinDelay] of each other
// will be batched together, resulting in a single policy reload
// no later than [policyReloadMaxDelay] after the first detected change.
// In other words, the effective policy will be reloaded no more often than once
// every 5 seconds, but at most 15 seconds after an underlying [source.Store]
// has issued a policy change callback.
//
// See [Policy.watchReload].
var (
	policyReloadMinDelay = 5 * time.Second
	policyReloadMaxDelay = 15 * time.Second
)

// Policy provides access to the current effective [setting.Snapshot] for a given
// scope and allows to reload it from the underlying [source.Store] list. It also allows to
// subscribe and receive a callback whenever the effective [setting.Snapshot] is changed.
//
// It is safe for concurrent use.
type Policy struct {
	scope setting.PolicyScope

	reloadCh chan reloadRequest // 1-buffered; written to when a policy reload is required
	closeCh  chan struct{}      // closed to signal that the Policy is being closed
	doneCh   chan struct{}      // closed by [Policy.closeInternal]

	// effective is the most recent version of the [setting.Snapshot]
	// containing policy settings merged from all applicable sources.
	effective atomic.Pointer[setting.Snapshot]

	changeCallbacks policyChangeCallbacks

	mu             sync.Mutex
	watcherStarted bool // whether [Policy.watchReload] was started
	sources        source.ReadableSources
	closing        bool // whether [Policy.Close] was called (even if we're still closing)
}

// newPolicy returns a new [Policy] for the specified [setting.PolicyScope]
// that tracks changes and merges policy settings read from the specified sources.
func newPolicy(scope setting.PolicyScope, sources ...*source.Source) (_ *Policy, err error) {
	readableSources := make(source.ReadableSources, 0, len(sources))
	defer func() {
		if err != nil {
			readableSources.Close()
		}
	}()
	for _, s := range sources {
		reader, err := s.Reader()
		if err != nil {
			return nil, fmt.Errorf("failed to get a store reader: %w", err)
		}
		session, err := reader.OpenSession()
		if err != nil {
			return nil, fmt.Errorf("failed to open a reading session: %w", err)
		}
		readableSources = append(readableSources, source.ReadableSource{Source: s, ReadingSession: session})
	}

	// Sort policy sources by their precedence from lower to higher.
	// For example, {UserPolicy},{ProfilePolicy},{DevicePolicy}.
	readableSources.StableSort()

	p := &Policy{
		scope:    scope,
		sources:  readableSources,
		reloadCh: make(chan reloadRequest, 1),
		closeCh:  make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	if _, err := p.reloadNow(false); err != nil {
		p.Close()
		return nil, err
	}
	p.startWatchReloadIfNeeded()
	return p, nil
}

// IsValid reports whether p is in a valid state and has not been closed.
//
// Since p's state can be changed by other goroutines at any time, this should
// only be used as an optimization.
func (p *Policy) IsValid() bool {
	select {
	case <-p.closeCh:
		return false
	default:
		return true
	}
}

// Scope returns the [setting.PolicyScope] that this policy applies to.
func (p *Policy) Scope() setting.PolicyScope {
	return p.scope
}

// Get returns the effective [setting.Snapshot].
func (p *Policy) Get() *setting.Snapshot {
	return p.effective.Load()
}

// RegisterChangeCallback adds a function to be called whenever the effective
// policy changes. The returned function can be used to unregister the callback.
func (p *Policy) RegisterChangeCallback(callback PolicyChangeCallback) (unregister func()) {
	return p.changeCallbacks.Register(callback)
}

// Reload synchronously re-reads policy settings from the underlying list of policy sources,
// constructing a new merged [setting.Snapshot] even if the policy remains unchanged.
// In most scenarios, there's no need to re-read the policy manually.
// Instead, it is recommended to register a policy change callback, or to use
// the most recent [setting.Snapshot] returned by the [Policy.Get] method.
//
// It must not be called with p.mu held.
func (p *Policy) Reload() (*setting.Snapshot, error) {
	return p.reload(true)
}

// reload is like Reload, but allows to specify whether to re-read policy settings
// from unchanged policy sources.
//
// It must not be called with p.mu held.
func (p *Policy) reload(force bool) (*setting.Snapshot, error) {
	if !p.startWatchReloadIfNeeded() {
		return p.Get(), nil
	}

	respCh := make(chan reloadResponse, 1)
	select {
	case p.reloadCh <- reloadRequest{force: force, respCh: respCh}:
		// continue
	case <-p.closeCh:
		return nil, ErrPolicyClosed
	}
	select {
	case resp := <-respCh:
		return resp.policy, resp.err
	case <-p.closeCh:
		return nil, ErrPolicyClosed
	}
}

// reloadAsync requests an asynchronous background policy reload.
// The policy will be reloaded no later than in [policyReloadMaxDelay].
//
// It must not be called with p.mu held.
func (p *Policy) reloadAsync() {
	if !p.startWatchReloadIfNeeded() {
		return
	}
	select {
	case p.reloadCh <- reloadRequest{}:
		// Sent.
	default:
		// A reload request is already en route.
	}
}

// reloadNow loads and merges policies from all sources, updating the effective policy.
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
	old := p.effective.Swap(new)
	// A nil old value indicates the initial policy load rather than a policy change.
	// Additionally, we should not invoke the policy change callbacks unless the
	// policy items have actually changed.
	if old != nil && !old.EqualItems(new) {
		snapshots := Change[*setting.Snapshot]{New: new, Old: old}
		p.changeCallbacks.Invoke(snapshots)
	}
	return new, nil
}

// Done returns a channel that is closed when the [Policy] is closed.
func (p *Policy) Done() <-chan struct{} {
	return p.doneCh
}

// readAndMerge reads and merges policy settings from all applicable sources,
// returning a [setting.Snapshot] with the merged result.
// If the force parameter is true, it re-reads policy settings from each source
// even if no policy change was observed, and returns an error if the read
// operation fails.
func (p *Policy) readAndMerge(force bool) (*setting.Snapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Start with an empty policy in the target scope.
	effective := setting.NewSnapshot(nil, setting.SummaryWith(p.scope))
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
		effective = setting.MergeSnapshots(effective, policy)
	}
	return effective, nil
}

// addSource adds the specified source to the list of sources used by p,
// and triggers a synchronous policy refresh. It returns an error
// if the source is not a valid source for this effective policy,
// or if the effective policy is being closed,
// or if policy refresh fails with an error.
func (p *Policy) addSource(source *source.Source) error {
	return p.applySourcesChange(source, nil)
}

// removeSource removes the specified source from the list of sources used by p,
// and triggers a synchronous policy refresh. It returns an error if the
// effective policy is being closed, or if policy refresh fails with an error.
func (p *Policy) removeSource(source *source.Source) error {
	return p.applySourcesChange(nil, source)
}

// replaceSource replaces the old source with the new source atomically,
// and triggers a synchronous policy refresh. It returns an error
// if the source is not a valid source for this effective policy,
// or if the effective policy is being closed,
// or if policy refresh fails with an error.
func (p *Policy) replaceSource(old, new *source.Source) error {
	return p.applySourcesChange(new, old)
}

func (p *Policy) applySourcesChange(toAdd, toRemove *source.Source) error {
	if toAdd == toRemove {
		return nil
	}
	if toAdd != nil && !toAdd.Scope().Contains(p.scope) {
		return errors.New("scope mismatch")
	}

	changed, err := func() (changed bool, err error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if toAdd != nil && !p.sources.Contains(toAdd) {
			reader, err := toAdd.Reader()
			if err != nil {
				return false, fmt.Errorf("failed to get a store reader: %w", err)
			}
			session, err := reader.OpenSession()
			if err != nil {
				return false, fmt.Errorf("failed to open a reading session: %w", err)
			}

			addAt := p.sources.InsertionIndexOf(toAdd)
			toAdd := source.ReadableSource{
				Source:         toAdd,
				ReadingSession: session,
			}
			p.sources = slices.Insert(p.sources, addAt, toAdd)
			go p.watchPolicyChanges(toAdd)
			changed = true
		}
		if toRemove != nil {
			if deleteAt := p.sources.IndexOf(toRemove); deleteAt != -1 {
				p.sources.DeleteAt(deleteAt)
				changed = true
			}
		}
		return changed, nil
	}()
	if changed {
		_, err = p.reload(false)
	}
	return err // may be nil or non-nil
}

func (p *Policy) watchPolicyChanges(s source.ReadableSource) {
	for {
		select {
		case _, ok := <-s.ReadingSession.PolicyChanged():
			if !ok {
				p.mu.Lock()
				abruptlyClosed := slices.Contains(p.sources, s)
				p.mu.Unlock()
				if abruptlyClosed {
					// The underlying [source.Source] was closed abruptly without
					// being properly removed or replaced by another policy source.
					// We can't keep this [Policy] up to date, so we should close it.
					p.Close()
				}
				return
			}
			// The PolicyChanged channel was signaled.
			// Request an asynchronous policy reload.
			p.reloadAsync()
		case <-p.closeCh:
			// The [Policy] is being closed.
			return
		}
	}
}

// startWatchReloadIfNeeded starts [Policy.watchReload] in a new goroutine
// if the list of policy sources is not empty, it hasn't been started yet,
// and the [Policy] is not being closed.
// It reports whether [Policy.watchReload] has ever been started.
//
// It must not be called with p.mu held.
func (p *Policy) startWatchReloadIfNeeded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sources) != 0 && !p.watcherStarted && !p.closing {
		go p.watchReload()
		for i := range p.sources {
			go p.watchPolicyChanges(p.sources[i])
		}
		p.watcherStarted = true
	}
	return p.watcherStarted
}

// reloadRequest describes a policy reload request.
type reloadRequest struct {
	// force policy reload regardless of whether a policy change was detected.
	force bool
	// respCh is an optional channel. If non-nil, it makes the reload request
	// synchronous and receives the result.
	respCh chan<- reloadResponse
}

// reloadResponse is a result of a synchronous policy reload.
type reloadResponse struct {
	policy *setting.Snapshot
	err    error
}

// watchReload processes incoming synchronous and asynchronous policy reload requests.
//
// Synchronous requests (with a non-nil respCh) are served immediately.
//
// Asynchronous requests are debounced and throttled: they are executed at least
// [policyReloadMinDelay] after the last request, but no later than [policyReloadMaxDelay]
// after the first request in a batch.
func (p *Policy) watchReload() {
	defer p.closeInternal()

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
				timeoutCh = time.After(policyReloadMinDelay)
			}
			delayCh = time.After(policyReloadMaxDelay)
		case <-delayCh:
			reload(nil)
		case <-timeoutCh:
			reload(nil)
		case <-p.closeCh:
			break loop
		}
	}
}

func (p *Policy) closeInternal() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sources.Close()
	p.changeCallbacks.Close()
	close(p.doneCh)
	deletePolicy(p)
}

// Close initiates the closing of the policy.
// The [Policy.Done] channel is closed to signal that the operation has been completed.
func (p *Policy) Close() {
	p.mu.Lock()
	alreadyClosing := p.closing
	watcherStarted := p.watcherStarted
	p.closing = true
	p.mu.Unlock()

	if alreadyClosing {
		return
	}

	close(p.closeCh)
	if !watcherStarted {
		// Normally, closing p.closeCh signals [Policy.watchReload] to exit,
		// and [Policy.closeInternal] performs the actual closing when
		// [Policy.watchReload] returns. However, if the watcher was never
		// started, we need to call [Policy.closeInternal] manually.
		go p.closeInternal()
	}
}

func setForTest[T any](tb internal.TB, target *T, newValue T) {
	oldValue := *target
	tb.Cleanup(func() { *target = oldValue })
	*target = newValue
}
