// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

package systray

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"runtime"
	"sync"
	"time"

	"fyne.io/systray"
	ico "github.com/Kodeworks/golang-image-ico"
	"github.com/fogleman/gg"
)

// tsLogo represents the Tailscale logo displayed as the systray icon.
type tsLogo struct {
	// dots represents the state of the 3x3 dot grid in the logo.
	// A 0 represents a gray dot, any other value is a white dot.
	dots [9]byte

	// dotMask returns an image mask to be used when rendering the logo dots.
	dotMask func(dc *gg.Context, borderUnits int, radius int) *image.Alpha

	// overlay is called after the dots are rendered to draw an additional overlay.
	overlay func(dc *gg.Context, borderUnits int, radius int)
}

var (
	// disconnected is all gray dots
	disconnected = tsLogo{dots: [9]byte{
		0, 0, 0,
		0, 0, 0,
		0, 0, 0,
	}}

	// connected is the normal Tailscale logo
	connected = tsLogo{dots: [9]byte{
		0, 0, 0,
		1, 1, 1,
		0, 1, 0,
	}}

	// loading is a special tsLogo value that is not meant to be rendered directly,
	// but indicates that the loading animation should be shown.
	loading = tsLogo{dots: [9]byte{'l', 'o', 'a', 'd', 'i', 'n', 'g'}}

	// loadingIcons are shown in sequence as an animated loading icon.
	loadingLogos = []tsLogo{
		{dots: [9]byte{
			0, 1, 1,
			1, 0, 1,
			0, 0, 1,
		}},
		{dots: [9]byte{
			0, 1, 1,
			0, 0, 1,
			0, 1, 0,
		}},
		{dots: [9]byte{
			0, 1, 1,
			0, 0, 0,
			0, 0, 1,
		}},
		{dots: [9]byte{
			0, 0, 1,
			0, 1, 0,
			0, 0, 0,
		}},
		{dots: [9]byte{
			0, 1, 0,
			0, 0, 0,
			0, 0, 0,
		}},
		{dots: [9]byte{
			0, 0, 0,
			0, 0, 1,
			0, 0, 0,
		}},
		{dots: [9]byte{
			0, 0, 0,
			0, 0, 0,
			0, 0, 0,
		}},
		{dots: [9]byte{
			0, 0, 1,
			0, 0, 0,
			0, 0, 0,
		}},
		{dots: [9]byte{
			0, 0, 0,
			0, 0, 0,
			1, 0, 0,
		}},
		{dots: [9]byte{
			0, 0, 0,
			0, 0, 0,
			1, 1, 0,
		}},
		{dots: [9]byte{
			0, 0, 0,
			1, 0, 0,
			1, 1, 0,
		}},
		{dots: [9]byte{
			0, 0, 0,
			1, 1, 0,
			0, 1, 0,
		}},
		{dots: [9]byte{
			0, 0, 0,
			1, 1, 0,
			0, 1, 1,
		}},
		{dots: [9]byte{
			0, 0, 0,
			1, 1, 1,
			0, 0, 1,
		}},
		{dots: [9]byte{
			0, 1, 0,
			0, 1, 1,
			1, 0, 1,
		}},
	}

	// exitNodeOnline is the Tailscale logo with an additional arrow overlay in the corner.
	exitNodeOnline = tsLogo{
		dots: [9]byte{
			0, 0, 0,
			1, 1, 1,
			0, 1, 0,
		},
		// draw an arrow mask in the bottom right corner with a reasonably thick line width.
		dotMask: func(dc *gg.Context, borderUnits int, radius int) *image.Alpha {
			bu, r := float64(borderUnits), float64(radius)

			x1 := r * (bu + 3.5)
			y := r * (bu + 7)
			x2 := x1 + (r * 5)

			mc := gg.NewContext(dc.Width(), dc.Height())
			mc.DrawLine(x1, y, x2, y)                 // arrow center line
			mc.DrawLine(x2-(1.5*r), y-(1.5*r), x2, y) // top of arrow tip
			mc.DrawLine(x2-(1.5*r), y+(1.5*r), x2, y) // bottom of arrow tip
			mc.SetLineWidth(r * 3)
			mc.Stroke()
			return mc.AsMask()
		},
		// draw an arrow in the bottom right corner over the masked area.
		overlay: func(dc *gg.Context, borderUnits int, radius int) {
			bu, r := float64(borderUnits), float64(radius)

			x1 := r * (bu + 3.5)
			y := r * (bu + 7)
			x2 := x1 + (r * 5)

			dc.DrawLine(x1, y, x2, y)                 // arrow center line
			dc.DrawLine(x2-(1.5*r), y-(1.5*r), x2, y) // top of arrow tip
			dc.DrawLine(x2-(1.5*r), y+(1.5*r), x2, y) // bottom of arrow tip
			dc.SetColor(fg)
			dc.SetLineWidth(r)
			dc.Stroke()
		},
	}

	// exitNodeOffline is the Tailscale logo with a red "x" in the corner.
	exitNodeOffline = tsLogo{
		dots: [9]byte{
			0, 0, 0,
			1, 1, 1,
			0, 1, 0,
		},
		// Draw a square that hides the four dots in the bottom right corner,
		dotMask: func(dc *gg.Context, borderUnits int, radius int) *image.Alpha {
			bu, r := float64(borderUnits), float64(radius)
			x := r * (bu + 3)

			mc := gg.NewContext(dc.Width(), dc.Height())
			mc.DrawRectangle(x, x, r*6, r*6)
			mc.Fill()
			return mc.AsMask()
		},
		// draw a red "x" over the bottom right corner.
		overlay: func(dc *gg.Context, borderUnits int, radius int) {
			bu, r := float64(borderUnits), float64(radius)

			x1 := r * (bu + 4)
			x2 := x1 + (r * 3.5)
			dc.DrawLine(x1, x1, x2, x2) // top-left to bottom-right stroke
			dc.DrawLine(x1, x2, x2, x1) // bottom-left to top-right stroke
			dc.SetColor(red)
			dc.SetLineWidth(r)
			dc.Stroke()
		},
	}
)

var (
	bg   = color.NRGBA{0, 0, 0, 255}
	fg   = color.NRGBA{255, 255, 255, 255}
	gray = color.NRGBA{255, 255, 255, 102}
	red  = color.NRGBA{229, 111, 74, 255}
)

// render returns a PNG image of the logo.
func (logo tsLogo) render() *bytes.Buffer {
	const borderUnits = 1
	return logo.renderWithBorder(borderUnits)
}

// renderWithBorder returns a PNG image of the logo with the specified border width.
// One border unit is equal to the radius of a tailscale logo dot.
func (logo tsLogo) renderWithBorder(borderUnits int) *bytes.Buffer {
	const radius = 25
	dim := radius * (8 + borderUnits*2)

	dc := gg.NewContext(dim, dim)
	dc.DrawRectangle(0, 0, float64(dim), float64(dim))
	dc.SetColor(bg)
	dc.Fill()

	if logo.dotMask != nil {
		mask := logo.dotMask(dc, borderUnits, radius)
		dc.SetMask(mask)
		dc.InvertMask()
	}

	for y := 0; y < 3; y++ {
		for x := 0; x < 3; x++ {
			px := (borderUnits + 1 + 3*x) * radius
			py := (borderUnits + 1 + 3*y) * radius
			col := fg
			if logo.dots[y*3+x] == 0 {
				col = gray
			}
			dc.DrawCircle(float64(px), float64(py), radius)
			dc.SetColor(col)
			dc.Fill()
		}
	}

	if logo.overlay != nil {
		dc.ResetClip()
		logo.overlay(dc, borderUnits, radius)
	}

	b := bytes.NewBuffer(nil)

	// Encode as ICO format on Windows, PNG on all other platforms.
	if runtime.GOOS == "windows" {
		_ = ico.Encode(b, dc.Image())
	} else {
		_ = png.Encode(b, dc.Image())
	}
	return b
}

// setAppIcon renders logo and sets it as the systray icon.
func setAppIcon(icon tsLogo) {
	if icon.dots == loading.dots {
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
