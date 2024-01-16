// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rate

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"tailscale.com/tstime/mono"
)

// Value measures the rate at which events occur,
// exponentially weighted towards recent activity.
// It is guaranteed to occupy O(1) memory, operate in O(1) runtime,
// and is safe for concurrent use.
// The zero value is safe for immediate use.
//
// The algorithm is based on and semantically equivalent to
// [exponentially weighted moving averages (EWMAs)],
// but modified to avoid assuming that event samples are gathered
// at fixed and discrete time-step intervals.
//
// In EWMA literature, the average is typically tuned with a λ parameter
// that determines how much weight to give to recent event samples.
// A high λ value reacts quickly to new events favoring recent history,
// while a low λ value reacts more slowly to new events.
// The EWMA is computed as:
//
//	zᵢ = λxᵢ + (1-λ)zᵢ₋₁
//
// where:
//   - λ is the weight parameter, where 0 ≤ λ ≤ 1
//   - xᵢ is the number of events that has since occurred
//   - zᵢ is the newly computed moving average
//   - zᵢ₋₁ is the previous moving average one time-step ago
//
// As mentioned, this implementation does not assume that the average
// is updated periodically on a fixed time-step interval,
// but allows the application to indicate that events occurred
// at any point in time by simply calling Value.Add.
// Thus, for every time Value.Add is called, it takes into consideration
// the amount of time elapsed since the last call to Value.Add as
// opposed to assuming that every call to Value.Add is evenly spaced
// some fixed time-step interval apart.
//
// Since time is critical to this measurement, we tune the metric not
// with the weight parameter λ (a unit-less constant between 0 and 1),
// but rather as a half-life period t½. The half-life period is
// mathematically equivalent but easier for humans to reason about.
// The parameters λ and t½ and directly related in the following way:
//
//	t½ = -(ln(2) · ΔT) / ln(1 - λ)
//
//	λ = 1 - 2^-(ΔT / t½)
//
// where:
//   - t½ is the half-life commonly used with exponential decay
//   - λ is the unit-less weight parameter commonly used with EWMAs
//   - ΔT is the discrete time-step interval used with EWMAs
//
// The internal algorithm does not use the EWMA formula,
// but is rather based on [half-life decay].
// The formula for half-life decay is mathematically related
// to the formula for computing the EWMA.
// The calculation of an EWMA is a geometric progression [[1]] and
// is essentially a discrete version of an exponential function [[2]],
// for which half-life decay is one particular expression.
// Given sufficiently small time-steps, the EWMA and half-life
// algorithms provide equivalent results.
//
// The Value type does not take ΔT as a parameter since it relies
// on a timer with nanosecond resolution. In a way, one could treat
// this algorithm as operating on a ΔT of 1ns. Practically speaking,
// the computation operates on non-discrete time intervals.
//
// [exponentially weighted moving averages (EWMAs)]: https://en.wikipedia.org/wiki/EWMA_chart
// [half-life decay]: https://en.wikipedia.org/wiki/Half-life
// [1]: https://en.wikipedia.org/wiki/Exponential_smoothing#%22Exponential%22_naming
// [2]: https://en.wikipedia.org/wiki/Exponential_decay
type Value struct {
	// HalfLife specifies how quickly the rate reacts to rate changes.
	//
	// Specifically, if there is currently a steady-state rate of
	// 0 events per second, and then immediately the rate jumped to
	// N events per second, then it will take HalfLife seconds until
	// the Value represents a rate of N/2 events per second and
	// 2*HalfLife seconds until the Value represents a rate of 3*N/4
	// events per second, and so forth. The rate represented by Value
	// will asymptotically approach N events per second over time.
	//
	// In order for Value to stably represent a steady-state rate,
	// the HalfLife should be larger than the average period between
	// calls to Value.Add.
	//
	// A zero or negative HalfLife is by default 1 second.
	HalfLife time.Duration

	mu      sync.Mutex
	updated mono.Time
	value   float64 // adjusted count of events
}

// halfLife returns the half-life period in seconds.
func (r *Value) halfLife() float64 {
	if r.HalfLife <= 0 {
		return time.Second.Seconds()
	}
	return time.Duration(r.HalfLife).Seconds()
}

// Add records that n number of events just occurred,
// which must be a finite and non-negative number.
func (r *Value) Add(n float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addNow(mono.Now(), n)
}
func (r *Value) addNow(now mono.Time, n float64) {
	if n < 0 || math.IsInf(n, 0) || math.IsNaN(n) {
		panic(fmt.Sprintf("invalid count %f; must be a finite, non-negative number", n))
	}
	r.value = r.valueNow(now) + n
	r.updated = now
}

// valueNow computes the number of events after some elapsed time.
// The total count of events decay exponentially so that
// the computed rate is biased towards recent history.
func (r *Value) valueNow(now mono.Time) float64 {
	// This uses the half-life formula:
	//	N(t) = N₀ · 2^-(t / t½)
	// where:
	//	N(t) is the amount remaining after time t,
	//	N₀ is the initial quantity, and
	//	t½ is the half-life of the decaying quantity.
	//
	// See https://en.wikipedia.org/wiki/Half-life
	age := now.Sub(r.updated).Seconds()
	return r.value * math.Exp2(-age/r.halfLife())
}

// Rate computes the rate as events per second.
func (r *Value) Rate() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rateNow(mono.Now())
}
func (r *Value) rateNow(now mono.Time) float64 {
	// The stored value carries the units "events"
	// while we want to compute "events / second".
	//
	// In the trivial case where the events never decay,
	// the average rate can be computed by dividing the total events
	// by the total elapsed time since the start of the Value.
	// This works because the weight distribution is uniform such that
	// the weight of an event in the distant past is equal to
	// the weight of a recent event. This is not the case with
	// exponentially decaying weights, which complicates computation.
	//
	// Since our events are decaying, we can divide the number of events
	// by the total possible accumulated value, which we determine
	// by integrating the half-life formula from t=0 until t=∞,
	// assuming that N₀ is 1:
	//	∫ N(t) dt = t½ / ln(2)
	//
	// Recall that the integral of a curve is the area under a curve,
	// which carries the units of the X-axis multiplied by the Y-axis.
	// In our case this would be the units "events · seconds".
	// By normalizing N₀ to 1, the Y-axis becomes a unit-less quantity,
	// resulting in a integral unit of just "seconds".
	// Dividing the events by the integral quantity correctly produces
	// the units of "events / second".
	return r.valueNow(now) / r.normalizedIntegral()
}

// normalizedIntegral computes the quantity t½ / ln(2).
// It carries the units of "seconds".
func (r *Value) normalizedIntegral() float64 {
	return r.halfLife() / math.Ln2
}

type jsonValue struct {
	// TODO: Use v2 "encoding/json" for native time.Duration formatting.
	HalfLife string    `json:"halfLife,omitempty,omitzero"`
	Value    float64   `json:"value,omitempty,omitzero"`
	Updated  mono.Time `json:"updated,omitempty,omitzero"`
}

func (r *Value) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v := jsonValue{Value: r.value, Updated: r.updated}
	if r.HalfLife > 0 {
		v.HalfLife = r.HalfLife.String()
	}
	return json.Marshal(v)
}

func (r *Value) UnmarshalJSON(b []byte) error {
	var v jsonValue
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	halfLife, err := time.ParseDuration(v.HalfLife)
	if err != nil && v.HalfLife != "" {
		return fmt.Errorf("invalid halfLife: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.HalfLife = halfLife
	r.value = v.Value
	r.updated = v.Updated
	return nil
}
