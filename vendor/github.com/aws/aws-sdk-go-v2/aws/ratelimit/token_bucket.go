package ratelimit

import (
	"sync"
)

// TokenBucket provides a concurrency safe utility for adding and removing
// tokens from the available token bucket.
type TokenBucket struct {
	capacity    uint
	maxCapacity uint
	mu          sync.Mutex
}

// NewTokenBucket returns an initialized TokenBucket with the capacity
// specified.
func NewTokenBucket(i uint) *TokenBucket {
	return &TokenBucket{
		capacity:    i,
		maxCapacity: i,
	}
}

// Retrieve attempts to reduce the available tokens by the amount requested. If
// there are tokens available true will be returned along with the number of
// available tokens remaining. If amount requested is larger than the available
// capacity, false will be returned along with the available capacity. If the
// amount is less than the available capacity
func (t *TokenBucket) Retrieve(amount uint) (available uint, retrieved bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if amount > t.capacity {
		return t.capacity, false
	}

	t.capacity -= amount
	return t.capacity, true
}

// Refund returns the amount of tokens back to the available token bucket, up
// to the initial capacity.
func (t *TokenBucket) Refund(amount uint) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.capacity += amount
	if t.capacity > t.maxCapacity {
		t.capacity = t.maxCapacity
	}
}
