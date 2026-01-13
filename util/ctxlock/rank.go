// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ctxlock

// A Rank defines the locking rules for a [Mutex].
//
// Typically, a distinct [Rank] type is defined for each mutex
// that requires specific locking order.
//
// Example:
//
//	type (
//		fooRank struct{} // fooRank must not be locked after barRank
//		barRank struct{}
//	)
//
//	func (r fooRank) CheckLockAfter(r2 Rank) error {
//		switch r2.(type) {
//		case barRank:
//			return fmt.Errorf("cannot lock %T after %T", r, r2)
//		default:
//			return nil
//		}
//	}
//
//	func (r barRank) CheckLockAfter(r2 Rank) error {
//		return nil // barRank can be locked anytime
//	}
//
//	type Foo struct {
//		mu Mutex[fooRank]
//	}
//
//	type Bar struct {
//		mu Mutex[barRank]
//	}
type Rank interface {
	// CheckLockAfter returns an error if locking the receiver
	// after the given rank would violate lock ordering or reentrancy rules.
	CheckLockAfter(Rank) error
}

// Reentrant is a [Rank] that does not enforce any locking order and allows reentrancy.
//
// It is used by a pre-defined [ReentrantMutex] type.
type Reentrant struct {
	noRank
}

// NonReentrant is a [Rank] that does not enforce any locking order, but disallows reentrancy.
type NonReentrant struct {
	noRank
}

type noRank struct{}

func (noRank) CheckLockAfter(Rank) error { return nil }
