// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package latencyqueue

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestBasicEnqueueDequeue(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		processed := make([]int, 0)
		var mu sync.Mutex
		q := New[int](context.Background(), 100*time.Millisecond)

		q.Start(func(ctx context.Context, val int) {
			mu.Lock()
			processed = append(processed, val)
			mu.Unlock()
		})
		defer q.Close()

		q.Enqueue([]int{0, 1, 2, 3, 4})

		barrier := q.Barrier()
		<-barrier

		if err := context.Cause(q.Context()); err != nil {
			t.Errorf("expected no error after successful processing, got %v", err)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(processed) != 5 {
			t.Errorf("expected 5 items processed, got %d", len(processed))
		}
		for i := range 5 {
			if processed[i] != i {
				t.Errorf("expected processed[%d] = %d, got %d", i, i, processed[i])
			}
		}
	})
}

func TestLagThresholdExceeded(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 50*time.Millisecond)

		q.Start(func(ctx context.Context, val int) {
			time.Sleep(30 * time.Millisecond)
		})
		defer q.Close()

		batch := make([]int, 10)
		for i := range batch {
			batch[i] = i
		}
		q.Enqueue(batch)

		<-q.Done()

		if err := context.Cause(q.Context()); err != ErrLagged {
			t.Errorf("expected ErrLagged, got %v", err)
		}
	})
}

func TestFastProcessingNoLag(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 100*time.Millisecond)

		processed := atomic.Int32{}
		q.Start(func(ctx context.Context, val int) {
			processed.Add(1)
		})
		defer q.Close()

		batch := make([]int, 100)
		for i := range batch {
			batch[i] = i
		}
		q.Enqueue(batch)

		barrier := q.Barrier()
		<-barrier

		if err := context.Cause(q.Context()); err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		if processed.Load() != 100 {
			t.Errorf("expected 100 items processed, got %d", processed.Load())
		}
	})
}

func TestMultipleBarriers(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 100*time.Millisecond)

		processed := atomic.Int32{}
		q.Start(func(ctx context.Context, val int) {
			processed.Add(1)
			time.Sleep(5 * time.Millisecond)
		})
		defer q.Close()

		barrier1 := q.Barrier()
		<-barrier1
		count1 := processed.Load()
		if count1 > 0 {
			t.Errorf("barrier1: nothing enqueued before it, but got %d processed", count1)
		}

		q.Enqueue([]int{0, 1, 2, 3, 4})
		barrier2 := q.Barrier()
		<-barrier2
		count2 := processed.Load()
		if count2 < 5 {
			t.Errorf("barrier2: expected at least 5 processed, got %d", count2)
		}

		q.Enqueue([]int{5, 6, 7, 8, 9})
		barrier3 := q.Barrier()
		<-barrier3
		count3 := processed.Load()
		if count3 != 10 {
			t.Errorf("barrier3: expected exactly 10 processed (all items), got %d", count3)
		}
	})
}

func TestCloseStopsProcessing(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 100*time.Millisecond)

		processed := atomic.Int32{}
		q.Start(func(ctx context.Context, val int) {
			processed.Add(1)
			time.Sleep(10 * time.Millisecond)
		})

		batch := make([]int, 1000)
		for i := range batch {
			batch[i] = i
		}
		q.Enqueue(batch)

		time.Sleep(20 * time.Millisecond)
		q.Close()

		processedCount := processed.Load()
		if processedCount >= 1000 {
			t.Error("expected some items to be dropped after close")
		}

		if q.Enqueue([]int{9999}) {
			t.Error("enqueue after close should return false")
		}

		if err := context.Cause(q.Context()); err != ErrClosed {
			t.Errorf("expected ErrClosed, got %v", err)
		}
	})
}

func TestBatchesShareEnqueueTime(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 50*time.Millisecond)

		q.Start(func(ctx context.Context, val int) {
			time.Sleep(10 * time.Millisecond)
		})
		defer q.Close()

		batch := make([]int, 10)
		for i := range batch {
			batch[i] = i
		}
		q.Enqueue(batch)

		<-q.Done()

		if err := context.Cause(q.Context()); err != ErrLagged {
			t.Errorf("expected ErrLagged - batch items share enqueue time, got %v", err)
		}
	})
}

func TestAbortStopsProcessing(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 200*time.Millisecond)

		processed := atomic.Int32{}
		q.Start(func(ctx context.Context, val int) {
			processed.Add(1)
			if val == 3 {
				q.Abort()
			}
			time.Sleep(10 * time.Millisecond)
		})

		q.Enqueue([]int{1, 2, 3, 4, 5})

		<-q.Done()

		if err := context.Cause(q.Context()); err != ErrAborted {
			t.Errorf("expected ErrAborted, got %v", err)
		}

		count := processed.Load()
		if count > 3 {
			t.Errorf("expected at most 3 items processed after abort, got %d", count)
		}
		if count == 0 {
			t.Error("expected at least one item to be processed")
		}
	})
}

func TestConcurrentEnqueuers(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 5*time.Second)

		var processed []int
		var mu sync.Mutex
		q.Start(func(ctx context.Context, val int) {
			mu.Lock()
			processed = append(processed, val)
			mu.Unlock()
		})
		defer q.Close()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			q.Enqueue([]int{100, 101, 102})
		}()

		go func() {
			defer wg.Done()
			q.Enqueue([]int{200, 201, 202})
		}()

		wg.Wait()
		barrier := q.Barrier()
		<-barrier

		mu.Lock()
		defer mu.Unlock()

		if len(processed) != 6 {
			t.Errorf("expected 6 items, got %d", len(processed))
		}

		has100 := false
		has200 := false
		idx100, idx200 := -1, -1

		for i, v := range processed {
			if v == 100 {
				has100 = true
				idx100 = i
			}
			if v == 200 {
				has200 = true
				idx200 = i
			}
		}

		if !has100 || !has200 {
			t.Fatal("both batches should be processed")
		}

		if idx100+2 < len(processed) {
			if processed[idx100] != 100 || processed[idx100+1] != 101 || processed[idx100+2] != 102 {
				t.Errorf("batch [100,101,102] not in order at position %d", idx100)
			}
		}

		if idx200+2 < len(processed) {
			if processed[idx200] != 200 || processed[idx200+1] != 201 || processed[idx200+2] != 202 {
				t.Errorf("batch [200,201,202] not in order at position %d", idx200)
			}
		}
	})
}

func TestProcessorReceivesContextCancellation(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 50*time.Millisecond)

		processorStarted := make(chan struct{})
		contextCancelledDuringProcessing := atomic.Bool{}

		q.Start(func(ctx context.Context, val int) {
			close(processorStarted)
			for i := 0; i < 10; i++ {
				select {
				case <-ctx.Done():
					contextCancelledDuringProcessing.Store(true)
					return
				default:
					time.Sleep(20 * time.Millisecond)
				}
			}
		})
		defer q.Close()

		q.Enqueue([]int{1, 2, 3})

		<-processorStarted
		<-q.Done()

		if err := context.Cause(q.Context()); err != ErrLagged {
			t.Errorf("expected ErrLagged, got %v", err)
		}

		if !contextCancelledDuringProcessing.Load() {
			t.Error("expected processor to observe context cancellation during processing")
		}
	})
}

func TestProcessorReceivesAbortCancellation(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 500*time.Millisecond)

		processorStarted := make(chan struct{})
		contextCancelledDuringProcessing := atomic.Bool{}

		q.Start(func(ctx context.Context, val int) {
			if val == 1 {
				close(processorStarted)
			}
			for i := 0; i < 10; i++ {
				select {
				case <-ctx.Done():
					contextCancelledDuringProcessing.Store(true)
					return
				default:
					time.Sleep(10 * time.Millisecond)
				}
			}
		})

		q.Enqueue([]int{1, 2, 3, 4, 5})

		<-processorStarted
		q.Abort()
		<-q.Done()

		if err := context.Cause(q.Context()); err != ErrAborted {
			t.Errorf("expected ErrAborted, got %v", err)
		}

		if !contextCancelledDuringProcessing.Load() {
			t.Error("expected processor to observe context cancellation during processing")
		}
	})
}

func TestEnqueueFailsAfterLag(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 30*time.Millisecond)

		q.Start(func(ctx context.Context, val int) {
			time.Sleep(20 * time.Millisecond)
		})
		defer q.Close()

		q.Enqueue([]int{1, 2, 3})

		<-q.Done()

		if q.Enqueue([]int{999}) {
			t.Error("enqueue after lag should return false")
		}

		if err := context.Cause(q.Context()); err != ErrLagged {
			t.Errorf("expected ErrLagged, got %v", err)
		}
	})
}

func TestContextCause(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		setup     func(*Queue[int])
		expectErr error
	}{
		{
			name: "close",
			setup: func(q *Queue[int]) {
				q.Start(func(ctx context.Context, val int) {})
				q.Close()
			},
			expectErr: ErrClosed,
		},
		{
			name: "abort",
			setup: func(q *Queue[int]) {
				q.Start(func(ctx context.Context, val int) {})
				q.Abort()
				<-q.Done()
			},
			expectErr: ErrAborted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				q := New[int](context.Background(), 100*time.Millisecond)
				tt.setup(q)

				if err := context.Cause(q.Context()); err != tt.expectErr {
					t.Errorf("expected %v, got %v", tt.expectErr, err)
				}
			})
		})
	}
}

func TestBarrierWithContextDistinction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setup       func(*Queue[int]) <-chan struct{}
		expectErr   error
		description string
	}{
		{
			name: "normal completion",
			setup: func(q *Queue[int]) <-chan struct{} {
				q.Start(func(ctx context.Context, val int) {})
				q.Enqueue([]int{1, 2, 3})
				return q.Barrier()
			},
			expectErr:   nil,
			description: "barrier completes normally when items are processed",
		},
		{
			name: "close",
			setup: func(q *Queue[int]) <-chan struct{} {
				q.Start(func(ctx context.Context, val int) {
					time.Sleep(100 * time.Millisecond)
				})
				q.Enqueue([]int{1, 2, 3, 4, 5})
				b := q.Barrier()
				time.Sleep(10 * time.Millisecond)
				q.Close()
				return b
			},
			expectErr:   ErrClosed,
			description: "barrier released when queue is closed",
		},
		{
			name: "abort",
			setup: func(q *Queue[int]) <-chan struct{} {
				q.Start(func(ctx context.Context, val int) {
					time.Sleep(100 * time.Millisecond)
				})
				q.Enqueue([]int{1, 2, 3, 4, 5})
				b := q.Barrier()
				time.Sleep(10 * time.Millisecond)
				q.Abort()
				return b
			},
			expectErr:   ErrAborted,
			description: "barrier released when queue is aborted",
		},
		{
			name: "lag",
			setup: func(q *Queue[int]) <-chan struct{} {
				q.Start(func(ctx context.Context, val int) {
					time.Sleep(30 * time.Millisecond)
				})
				q.Enqueue([]int{1, 2, 3, 4, 5})
				return q.Barrier()
			},
			expectErr:   ErrLagged,
			description: "barrier released when lag threshold is exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var q *Queue[int]
				if tt.name == "lag" {
					q = New[int](context.Background(), 50*time.Millisecond)
				} else {
					q = New[int](context.Background(), 5*time.Second)
				}
				defer q.Close()

				barrier := tt.setup(q)
				<-barrier

				if err := context.Cause(q.Context()); err != tt.expectErr {
					t.Errorf("%s: expected %v, got %v", tt.description, tt.expectErr, err)
				}
			})
		})
	}
}

func TestFirstStopWins(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 100*time.Millisecond)

		q.Start(func(ctx context.Context, val int) {})

		q.Abort()
		q.Close()

		<-q.Done()

		if err := context.Cause(q.Context()); err != ErrAborted {
			t.Errorf("expected ErrAborted (first error wins), got %v", err)
		}
	})
}

func TestMultipleCloseCallsSafe(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 100*time.Millisecond)

		q.Start(func(ctx context.Context, val int) {})

		q.Close()
		q.Close()

		if err := context.Cause(q.Context()); err != ErrClosed {
			t.Errorf("expected ErrClosed, got %v", err)
		}
	})
}

func TestMultipleAbortCallsSafe(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 100*time.Millisecond)

		q.Start(func(ctx context.Context, val int) {})

		q.Abort()
		q.Abort()
		q.Abort()

		<-q.Done()

		if err := context.Cause(q.Context()); err != ErrAborted {
			t.Errorf("expected ErrAborted, got %v", err)
		}
	})
}

func TestCounters(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 500*time.Millisecond)

		processed := make(chan struct{}, 10)
		q.Start(func(ctx context.Context, val int) {
			time.Sleep(5 * time.Millisecond)
			processed <- struct{}{}
		})
		defer q.Close()

		q.Enqueue([]int{1, 2, 3})

		counters := q.Counters()
		if counters.Enqueued != 3 {
			t.Errorf("expected 3 enqueued, got %d", counters.Enqueued)
		}

		q.Enqueue([]int{4, 5})

		counters = q.Counters()
		if counters.Enqueued != 5 {
			t.Errorf("expected 5 enqueued total, got %d", counters.Enqueued)
		}

		<-processed
		<-processed

		counters = q.Counters()
		if counters.Processed < 2 {
			t.Errorf("expected at least 2 processed, got %d", counters.Processed)
		}
		if counters.Processed > counters.Enqueued {
			t.Errorf("processed (%d) cannot exceed enqueued (%d)", counters.Processed, counters.Enqueued)
		}

		barrier := q.Barrier()
		<-barrier

		counters = q.Counters()
		if counters.Enqueued != 5 {
			t.Errorf("expected 5 enqueued total, got %d", counters.Enqueued)
		}
		if counters.Processed != 5 {
			t.Errorf("expected 5 processed, got %d", counters.Processed)
		}
	})
}

func TestPanicRecovery(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 500*time.Millisecond)

		q.Start(func(ctx context.Context, val int) {
			if val == 2 {
				panic("test panic")
			}
		})

		q.Enqueue([]int{1, 2, 3})

		<-q.Done()

		err := context.Cause(q.Context())
		if err == nil {
			t.Fatal("expected panic error, got nil")
		}

		panicErr, ok := err.(*ErrPanic)
		if !ok {
			t.Fatalf("expected *ErrPanic, got %T: %v", err, err)
		}

		if panicErr.Panic != "test panic" {
			t.Errorf("expected panic value 'test panic', got %v", panicErr.Panic)
		}
	})
}

func TestContextPropagation(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		parentCtx, parentCancel := context.WithCancel(context.Background())
		defer parentCancel()

		q := New[int](parentCtx, 500*time.Millisecond)

		var receivedCtx context.Context
		var mu sync.Mutex
		q.Start(func(ctx context.Context, val int) {
			mu.Lock()
			receivedCtx = ctx
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		})
		defer q.Close()

		q.Enqueue([]int{1})
		time.Sleep(5 * time.Millisecond)

		mu.Lock()
		ctx := receivedCtx
		mu.Unlock()

		if ctx == nil {
			t.Fatal("expected context to be passed to processor")
		}

		parentCancel()
		<-q.Done()

		if err := q.Context().Err(); err != context.Canceled {
			t.Errorf("expected context.Canceled when parent cancelled, got %v", err)
		}
	})
}

func TestZeroMaxLag(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := New[int](context.Background(), 0)

		processed := atomic.Int32{}
		q.Start(func(ctx context.Context, val int) {
			processed.Add(1)
			time.Sleep(10 * time.Millisecond)
		})
		defer q.Close()

		q.Enqueue([]int{1, 2, 3})
		barrier := q.Barrier()
		<-barrier

		if processed.Load() != 3 {
			t.Errorf("expected 3 items processed with zero maxLag, got %d", processed.Load())
		}

		if err := context.Cause(q.Context()); err != nil {
			t.Errorf("expected no error with zero maxLag, got %v", err)
		}
	})
}
