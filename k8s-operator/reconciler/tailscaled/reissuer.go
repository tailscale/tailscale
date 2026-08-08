// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailscaled

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"

	"tailscale.com/k8s-operator/tsclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

// Reissuer manages auth key re-issuance for a CRD reconciler that runs one tailscaled replica per Secret. It
// tracks in-flight reissues per replica so duplicate reconciles don't mint duplicate keys, and rate limits
// re-issuance per parent resource so a replica that can never auth doesn't hammer the control plane.
type Reissuer struct {
	mu         sync.Mutex                 // protects following
	reissuing  map[string]set.Set[string] // parent name -> replica names with a reissue in flight
	rateLimits map[string]*rate.Limiter   // parent name -> re-issuance rate limiter
}

// NewReissuer returns a ready-to-use Reissuer.
func NewReissuer() *Reissuer {
	return &Reissuer{
		reissuing:  make(map[string]set.Set[string]),
		rateLimits: make(map[string]*rate.Limiter),
	}
}

// EnsureState sets up the per-parent rate limiter, sized so every replica can have its key re-issued quickly the
// first time via the burst, then an overall limit of one every 30s. It is idempotent and safe to call on every
// reconcile. ShouldReissue also creates a limiter on demand (with a burst of 1) so it never panics if EnsureState
// hasn't run; EnsureState just fixes the burst to the replica count.
func (r *Reissuer) EnsureState(parentName string, replicas int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limiterLocked(parentName, max(replicas, 1))
}

// RemoveState drops all per-parent state (rate limiter and every replica's in-flight marker) when the parent
// resource is deleted. It clears markers for all replicas the parent ever had, not just its current count, so
// replicas removed by an earlier scale-down don't strand entries.
func (r *Reissuer) RemoveState(parentName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rateLimits, parentName)
	delete(r.reissuing, parentName)
}

// limiterLocked returns the rate limiter for parentName, creating one with the given burst if absent. r.mu must be
// held. The burst only applies the first time a limiter is created for a parent; EnsureState seeds it with the
// replica count, but ShouldReissue can also reach this before EnsureState has run and passes a burst of 1.
func (r *Reissuer) limiterLocked(parentName string, burst int) *rate.Limiter {
	lim, ok := r.rateLimits[parentName]
	if !ok {
		lim = rate.NewLimiter(rate.Every(30*time.Second), burst)
		r.rateLimits[parentName] = lim
	}
	return lim
}

// setReissuingLocked records or clears the in-flight reissue marker for a replica. r.mu must be held. The
// per-parent set is created on first use and dropped once its last marker is cleared, so an idle parent holds no
// entry.
func (r *Reissuer) setReissuingLocked(parentName, replicaName string, reissuing bool) {
	if reissuing {
		s := r.reissuing[parentName]
		if s == nil {
			s = make(set.Set[string])
			r.reissuing[parentName] = s
		}
		s.Add(replicaName)
		return
	}
	s := r.reissuing[parentName]
	s.Delete(replicaName)
	if s.Len() == 0 {
		delete(r.reissuing, parentName)
	}
}

// Kind names of the CRDs that use a Reissuer, used only in its log and error messages.
const (
	KindProxyGroup = "ProxyGroup"
	KindRecorder   = "Recorder"
	KindPeerRelay  = "PeerRelay"
)

// ReissueInput describes a single replica's re-issuance check.
type ReissueInput struct {
	// ParentName is the owning CRD's name; it keys the rate limiter and appears in the rate-limit error.
	ParentName string
	// ReplicaName keys the in-flight marker and appears in log lines. Callers use the replica's state Secret name.
	ReplicaName string
	// Kind is the owning CRD kind, used only in log lines.
	Kind string
	// StateSecret is the replica's tailscaled state Secret. It may be nil or empty if the replica hasn't started
	// yet.
	StateSecret *corev1.Secret
	// CfgAuthKey is the auth key currently stored in the replica's config, or nil if none. The caller extracts it
	// from wherever it stores the key (a config Secret, a plain auth Secret, etc.).
	CfgAuthKey *string
}

// ShouldReissue reports whether the replica needs a fresh auth key. It tracks in-flight reissues via an internal
// marker to avoid duplicate API calls across reconciles: once it returns true, subsequent calls return false until
// containerboot clears the reissue request from the state Secret. When a reissue is warranted it deletes the stale
// tailnet device before returning true so the new key registers a clean device.
func (r *Reissuer) ShouldReissue(ctx context.Context, tsClient tsclient.Client, logger *zap.SugaredLogger, in ReissueInput) (shouldReissue bool, err error) {
	var stateData map[string][]byte
	if in.StateSecret != nil {
		stateData = in.StateSecret.Data
	}

	r.mu.Lock()
	reissuing := r.reissuing[in.ParentName].Contains(in.ReplicaName)
	r.mu.Unlock()

	if reissuing {
		_, requestStillPresent := stateData[kubetypes.KeyReissueAuthkey]
		if !requestStillPresent {
			r.mu.Lock()
			r.setReissuingLocked(in.ParentName, in.ReplicaName, false)
			r.mu.Unlock()
			logger.Debugf("auth key reissue completed for %q", in.ReplicaName)
			return false, nil
		}
		logger.Debugf("auth key already in process of re-issuance for %q, waiting", in.ReplicaName)
		return false, nil
	}

	defer func() {
		r.mu.Lock()
		r.setReissuingLocked(in.ParentName, in.ReplicaName, shouldReissue)
		r.mu.Unlock()
	}()

	brokenAuthkey, ok := stateData[kubetypes.KeyReissueAuthkey]
	if !ok {
		return false, nil
	}

	empty := in.CfgAuthKey == nil || *in.CfgAuthKey == ""
	broken := in.CfgAuthKey != nil && *in.CfgAuthKey == string(brokenAuthkey)

	// A new key has been written but the replica hasn't picked it up yet.
	if !empty && !broken {
		return false, nil
	}

	r.mu.Lock()
	lim := r.limiterLocked(in.ParentName, 1)
	r.mu.Unlock()
	if !lim.Allow() {
		logger.Debugf("auth key re-issuance rate limit exceeded, limit: %.2f, burst: %d, tokens: %.2f",
			lim.Limit(), lim.Burst(), lim.Tokens())
		return false, fmt.Errorf("auth key re-issuance rate limit exceeded for %s %q, will retry with backoff", in.Kind, in.ParentName)
	}

	logger.Infof("%s replica %s failing to auth; attempting cleanup and new key", in.Kind, in.ReplicaName)
	if tsID := stateData[kubetypes.KeyDeviceID]; len(tsID) > 0 {
		if err = EnsureDeviceDeleted(ctx, tsClient, logger, tailcfg.StableNodeID(tsID)); err != nil {
			return false, err
		}
	}

	return true, nil
}
