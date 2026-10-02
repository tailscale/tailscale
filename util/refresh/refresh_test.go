// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package refresh

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestRefresher(t *testing.T) {
	errTest := errors.New("refresh failed")

	type result struct {
		val       string
		refreshIn time.Duration
		err       error
	}
	tests := []struct {
		name    string
		results []result
		want    string
	}{
		{
			name:    "immediate success",
			results: []result{{val: "a", refreshIn: time.Hour}},
			want:    "a",
		},
		{
			name: "retry after failure",
			results: []result{
				{err: errTest},
				{val: "b", refreshIn: time.Hour},
			},
			want: "b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				var n int
				r := New(ctx, tt.name, t.Logf, time.Second,
					func(context.Context) (*string, time.Time, error) {
						res := tt.results[min(n, len(tt.results)-1)]
						n++
						v := res.val
						if res.err != nil {
							return &v, time.Time{}, res.err
						}
						return &v, time.Now().Add(res.refreshIn), nil
					})

				if err := r.WaitReady(); err != nil {
					t.Fatalf("WaitReady() = %v, want nil", err)
				}
				if got := r.GetCurrent(); got == nil || *got != tt.want {
					t.Fatalf("GetCurrent() = %v, want %q", got, tt.want)
				}
			})
		})
	}
}

func TestRefresherPeriodic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		vals := []string{"x", "y", "z"}
		var n int
		r := New(ctx, "test", t.Logf, time.Second,
			func(context.Context) (*string, time.Time, error) {
				v := vals[min(n, len(vals)-1)]
				n++
				return &v, time.Now().Add(time.Minute), nil
			})

		if err := r.WaitReady(); err != nil {
			t.Fatalf("WaitReady() = %v, want nil", err)
		}
		for _, want := range []string{"x", "y", "z"} {
			synctest.Wait()
			if got := *r.GetCurrent(); got != want {
				t.Fatalf("GetCurrent() = %q, want %q", got, want)
			}
			time.Sleep(time.Minute)
		}
	})
}

func TestRefresherGetRefreshAt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		r := New(ctx, "test", t.Logf, time.Second,
			func(context.Context) (*string, time.Time, error) {
				v := "a"
				return &v, time.Now().Add(time.Hour), nil
			})

		if err := r.WaitReady(); err != nil {
			t.Fatalf("WaitReady() = %v, want nil", err)
		}
		if got, want := r.GetRefreshAt(), time.Now().Add(time.Hour); !got.Equal(want) {
			t.Errorf("GetRefreshAt() = %v, want %v", got, want)
		}
	})
}

func TestRefresherContextCancelled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		r := New(ctx, "test", t.Logf, time.Second,
			func(ctx context.Context) (*string, time.Time, error) {
				<-ctx.Done()
				v := ""
				return &v, time.Time{}, ctx.Err()
			})
		cancel()

		if err := r.WaitReady(); !errors.Is(err, context.Canceled) {
			t.Errorf("WaitReady() = %v, want context.Canceled", err)
		}
		if cur := r.GetCurrent(); cur != nil {
			t.Errorf("GetCurrent() = %v, want nil", cur)
		}
	})
}
