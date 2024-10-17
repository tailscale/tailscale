// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

package main

import (
	"bytes"
	"context"
	"image/color"
	"image/png"
	"sync"
	"time"

	"fyne.io/systray"
	"github.com/fogleman/gg"
)

// tsLogo represents the state of the 3x3 dot grid in the Tailscale logo.
// A 0 represents a gray dot, any other value is a white dot.
type tsLogo [9]byte

var (
	// disconnected is all gray dots
	disconnected = tsLogo{
		0, 0, 0,
		0, 0, 0,
		0, 0, 0,
	}

	// connected is the normal Tailscale logo
	connected = tsLogo{
		0, 0, 0,
		1, 1, 1,
		0, 1, 0,
	}

	// loading is a special tsLogo value that is not meant to be rendered directly,
	// but indicates that the loading animation should be shown.
	loading = tsLogo{'l', 'o', 'a', 'd', 'i', 'n', 'g'}

	// loadingIcons are shown in sequence as an animated loading icon.
	loadingLogos = []tsLogo{
		{
			0, 1, 1,
			1, 0, 1,
			0, 0, 1,
		},
		{
			0, 1, 1,
			0, 0, 1,
			0, 1, 0,
		},
		{
			0, 1, 1,
			0, 0, 0,
			0, 0, 1,
		},
		{
			0, 0, 1,
			0, 1, 0,
			0, 0, 0,
		},
		{
			0, 1, 0,
			0, 0, 0,
			0, 0, 0,
		},
		{
			0, 0, 0,
			0, 0, 1,
			0, 0, 0,
		},
		{
			0, 0, 0,
			0, 0, 0,
			0, 0, 0,
		},
		{
			0, 0, 1,
			0, 0, 0,
			0, 0, 0,
		},
		{
			0, 0, 0,
			0, 0, 0,
			1, 0, 0,
		},
		{
			0, 0, 0,
			0, 0, 0,
			1, 1, 0,
		},
		{
			0, 0, 0,
			1, 0, 0,
			1, 1, 0,
		},
		{
			0, 0, 0,
			1, 1, 0,
			0, 1, 0,
		},
		{
			0, 0, 0,
			1, 1, 0,
			0, 1, 1,
		},
		{
			0, 0, 0,
			1, 1, 1,
			0, 0, 1,
		},
		{
			0, 1, 0,
			0, 1, 1,
			1, 0, 1,
		},
	}
)

var (
	black = color.NRGBA{0, 0, 0, 255}
	white = color.NRGBA{255, 255, 255, 255}
	gray  = color.NRGBA{255, 255, 255, 102}
)

// render returns a PNG image of the logo.
func (logo tsLogo) render() *bytes.Buffer {
	const radius = 25
	const borderUnits = 1
	dim := radius * (8 + borderUnits*2)

	dc := gg.NewContext(dim, dim)
	dc.DrawRectangle(0, 0, float64(dim), float64(dim))
	dc.SetColor(black)
	dc.Fill()

	for y := 0; y < 3; y++ {
		for x := 0; x < 3; x++ {
			px := (borderUnits + 1 + 3*x) * radius
			py := (borderUnits + 1 + 3*y) * radius
			col := white
			if logo[y*3+x] == 0 {
				col = gray
			}
			dc.DrawCircle(float64(px), float64(py), radius)
			dc.SetColor(col)
			dc.Fill()
		}
	}

	b := bytes.NewBuffer(nil)
	png.Encode(b, dc.Image())
	return b
}

// setAppIcon renders logo and sets it as the systray icon.
func setAppIcon(icon tsLogo) {
	if icon == loading {
		startLoadingAnimation()
	} else {
		stopLoadingAnimation()
		systray.SetIcon(icon.render().Bytes())
	}
}

var (
	loadingMu sync.Mutex // protects loadingCancel

	// loadingCancel stops the loading animation in the systray icon.
	// This is nil if the animation is not currently active.
	loadingCancel func()
)

// startLoadingAnimation starts the animated loading icon in the system tray.
// The animation continues until [stopLoadingAnimation] is called.
// If the loading animation is already active, this func does nothing.
func startLoadingAnimation() {
	loadingMu.Lock()
	defer loadingMu.Unlock()

	if loadingCancel != nil {
		// loading icon already displayed
		return
	}

	ctx := context.Background()
	ctx, loadingCancel = context.WithCancel(ctx)

	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		var i int
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				systray.SetIcon(loadingLogos[i].render().Bytes())
				i++
				if i >= len(loadingLogos) {
					i = 0
				}
			}
		}
	}()
}

// stopLoadingAnimation stops the animated loading icon in the system tray.
// If the loading animation is not currently active, this func does nothing.
func stopLoadingAnimation() {
	loadingMu.Lock()
	defer loadingMu.Unlock()

	if loadingCancel != nil {
		loadingCancel()
		loadingCancel = nil
	}
}
