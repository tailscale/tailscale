package tstime

import (
	"testing"
	"time"
)

func TestMonotonicCoarse(t *testing.T) {
	t.Parallel()
	start := MonotonicCoarse()
	for n := 0; n < 30; n++ {
		end := MonotonicCoarse()
		if end == start {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if end-start != 1 {
			t.Errorf("monotonic coarse time jumped: %v seconds", end-start)
		}
		return // success
	}
	t.Errorf("monotonic coarse time did not progress after 3s")
}

func BenchmarkMonotonicCoarse(b *testing.B) {
	for i := 0; i < b.N; i++ {
		MonotonicCoarse()
	}
}
