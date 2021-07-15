// +build go1.16,!go1.17
// +build linux,amd64 linux,arm64

package tstime

// MonotonicCoarse returns the number of monotonic seconds elapsed
// since an unspecified starting point, at low precision.
// It is only meaningful when compared to the
// result of previous MonotonicCoarse calls.
// On some platforms, MonotonicCoarse is much faster than time.Now.
func MonotonicCoarse() int64
