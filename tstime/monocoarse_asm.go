// +build go1.16,!go1.17
// +build linux,amd64 linux,arm64

package tstime

const (
	CLOCK_MONOTONIC        = 1
	CLOCK_MONOTONIC_COARSE = 6
)

// MonotonicCoarse returns the number of monotonic seconds elapsed
// since an unspecified starting point, at low precision.
// It is only meaningful when compared to the
// result of previous MonotonicCoarse calls.
// On some platforms, MonotonicCoarse is much faster than time.Now.
func monoClock(clock int) int64

// Monotonic returns the number of monotonic seconds elapsed
// since an unspecified starting point, at low precision.
// It is only meaningful when compared to the
// result of previous Monotonic calls.
// On some platforms, Monotonic is much faster than time.Now.
func Monotonic() int64 {
	return monoClock(CLOCK_MONOTONIC)
}

// MonotonicCoarse returns the number of monotonic seconds elapsed
// since an unspecified starting point, at low precision.
// It is only meaningful when compared to the
// result of previous MonotonicCoarse calls.
// On some platforms, MonotonicCoarse is much faster than time.Now.
func MonotonicCoarse() int64 {
	return monoClock(CLOCK_MONOTONIC_COARSE)
}
