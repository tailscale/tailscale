// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"context"
	"testing"
	"time"

	"fyne.io/systray"
)

func TestOnClickRemovedItem(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	item := &systray.MenuItem{ClickedCh: make(chan struct{})}
	called := make(chan struct{}, 1)
	onClick(ctx, item, func(context.Context) {
		select {
		case called <- struct{}{}:
		default:
		}
	})
	// An ordinary click still invokes the handler.
	select {
	case item.ClickedCh <- struct{}{}:
	case <-time.After(time.Second):
		t.Fatal("click handler did not start")
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("click handler did not run")
	}
	// fyne.io/systray closes ClickedCh when an item is removed. Removal
	// must not synthesize additional clicks, even before context cancellation.
	close(item.ClickedCh)
	select {
	case <-called:
		t.Fatal("removing the menu item invoked its click handler")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestOnClickCanceledItem(t *testing.T) {
	called := make(chan struct{}, 64)
	for range 64 {
		ctx, cancel := context.WithCancel(context.Background())
		item := &systray.MenuItem{ClickedCh: make(chan struct{}, 1)}
		item.ClickedCh <- struct{}{}
		cancel()
		onClick(ctx, item, func(context.Context) { called <- struct{}{} })
	}
	select {
	case <-called:
		t.Fatal("a canceled menu item invoked its queued click handler")
	case <-time.After(100 * time.Millisecond):
	}
}
