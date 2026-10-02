package refresh

import (
	"context"
	"sync"
	"time"

	"tailscale.com/types/logger"
)

// RefreshFunc is a function that returns a fresh T, and the time the
// next refresh should occur at. This gives the function control of when
// in the lifecycle of T to attempt refreshing it. Returning an error
// will result in an ignored T. When error is non nil, the returned T
// must not be nil.
type RefreshFunc[T any] func(context.Context) (
	t *T,
	refreshAt time.Time,
	err error,
)

// Refresher keeps a T fresh using a [RefreshFunc].
type Refresher[T any] struct {
	mu sync.RWMutex

	// static
	name               string
	logf               logger.Logf
	afterFailurePeriod time.Duration
	refreshFunc        RefreshFunc[T]

	// dynamic; protected by mu
	current   *T
	refreshAt time.Time
	readyErr  error

	// dynamic; readiness check
	ready     chan struct{}
	readyOnce sync.Once
}

// New returns a new [Refresher]
func New[T any](
	ctx context.Context,
	name string,
	logf logger.Logf,
	afterFailurePeriod time.Duration,
	refreshFunc RefreshFunc[T],
) *Refresher[T] {
	r := &Refresher[T]{
		name:               name,
		logf:               logf,
		afterFailurePeriod: afterFailurePeriod,
		refreshFunc:        refreshFunc,
		refreshAt:          time.Now(),
		ready:              make(chan struct{}),
	}
	go r.start(ctx)
	return r
}

// WaitReady waits for the [Refresher] to have a valid
// value or the context given to [New] to be cancelled.
func (r *Refresher[T]) WaitReady() error {
	<-r.ready

	r.mu.RLock()
	err := r.readyErr
	r.mu.RUnlock()
	return err
}

// GetCurrent returns the current T.
func (r *Refresher[T]) GetCurrent() *T {
	r.mu.RLock()
	t := r.current
	r.mu.RUnlock()
	return t
}

// GetRefreshAt returns when the T will be refreshed next.
func (r *Refresher[T]) GetRefreshAt() time.Time {
	r.mu.RLock()
	t := r.refreshAt
	r.mu.RUnlock()
	return t
}

// signalReady marks the [Refresher] as ready/errored.
func (r *Refresher[T]) signalReady(err error) {
	r.readyOnce.Do(func() {
		r.mu.Lock()
		r.readyErr = err
		r.mu.Unlock()
		close(r.ready)
	})
}

// refresh invokes the [Refresher]'s [RefreshFunc] and
// updates its inner values; on refresh success it marks
// the [Refresher] ready
func (r *Refresher[T]) refresh(ctx context.Context) error {
	fresh, refreshAt, err := r.refreshFunc(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.current = fresh
	r.refreshAt = refreshAt
	r.mu.Unlock()
	r.signalReady(nil)
	return nil
}

// start runs the main [Refresher] process.
func (r *Refresher[T]) start(ctx context.Context) {
	refreshTimer := time.NewTimer(time.Until(r.GetRefreshAt()))
	defer refreshTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			r.signalReady(ctx.Err())
			return
		case <-refreshTimer.C:
			if err := r.refresh(ctx); err != nil {
				r.logf("refresher %q failed to refresh: %v", r.name, err)
				refreshTimer.Reset(r.afterFailurePeriod)
				continue
			}
			nextRefreshIn := time.Until(r.GetRefreshAt())
			refreshTimer.Reset(nextRefreshIn)
		}
	}
}
