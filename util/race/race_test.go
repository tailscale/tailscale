// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package race

import (
	"context"
	"errors"
	"testing"
	"time"

	"tailscale.com/tstest"
)

func TestRaceSuccess1(t *testing.T) {
	tstest.ResourceCheck(t)

	const want = "success"
	rh := New[string](
		10*time.Second,
		func(context.Context) (string, error) {
			return want, nil
		}, func(context.Context) (string, error) {
			t.Fatal("should not be called")
			return "", nil
		})
	res, err := rh.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res != want {
		t.Errorf("got res=%q, want %q", res, want)
	}
}

func TestRaceRetry(t *testing.T) {
	tstest.ResourceCheck(t)

	const want = "fallback"
	rh := New[string](
		10*time.Second,
		func(context.Context) (string, error) {
			return "", errors.New("some error")
		}, func(context.Context) (string, error) {
			return want, nil
		})
	res, err := rh.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res != want {
		t.Errorf("got res=%q, want %q", res, want)
	}
}

func TestRaceTimeout(t *testing.T) {
	tstest.ResourceCheck(t)

	const want = "fallback"
	rh := New[string](
		100*time.Millisecond,
		func(ctx context.Context) (string, error) {
			// Block forever
			<-ctx.Done()
			return "", ctx.Err()
		}, func(context.Context) (string, error) {
			return want, nil
		})
	res, err := rh.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res != want {
		t.Errorf("got res=%q, want %q", res, want)
	}
}

func TestRaceError(t *testing.T) {
	tstest.ResourceCheck(t)

	err1 := errors.New("error 1")
	err2 := errors.New("error 2")

	rh := New[string](
		100*time.Millisecond,
		func(ctx context.Context) (string, error) {
			return "", err1
		}, func(context.Context) (string, error) {
			return "", err2
		})

	_, err := rh.Start(context.Background())
	if !errors.Is(err, err1) {
		t.Errorf("wanted err to contain err1; got %v", err)
	}
	if !errors.Is(err, err2) {
		t.Errorf("wanted err to contain err2; got %v", err)
	}
}
