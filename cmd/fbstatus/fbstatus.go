// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// fbstatus is a Linux framebuffer status display for the Tailscale
// appliance. It draws the Tailscale logo, the tailscaled backend state,
// the device's tailnet IP addresses, and (when the device needs to be
// logged in) a QR code containing the login URL so a user can enroll
// the appliance into a tailnet by pointing their phone camera at the
// screen.
//
// fbstatus accesses the framebuffer via the Linux UAPI in
// include/uapi/linux/fb.h: FBIOGET_VSCREENINFO and FBIOGET_FSCREENINFO
// ioctls plus an mmap of /dev/fb0. Only 32-bit truecolor framebuffers
// (the Raspberry Pi default) are supported.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/skip2/go-qrcode"
	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
	"golang.org/x/sys/unix"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/util/cloudenv"
)

//go:embed tailscale.png
var tailscalePNG []byte

// Linux framebuffer ioctl numbers, from include/uapi/linux/fb.h.
const (
	fbioGetVScreenInfo = 0x4600
	fbioGetFScreenInfo = 0x4602
)

// Linux VT ioctl numbers and KD_* modes, from include/uapi/linux/kd.h
// and include/uapi/linux/vt.h.
const (
	kdSetMode    = 0x4B3A
	kdGraphics   = 1
	kdText       = 0
	vtActivate   = 0x5606
	vtWaitActive = 0x5607
)

// Byte offsets into the raw fb_var_screeninfo struct returned by
// FBIOGET_VSCREENINFO. All fields we read are little-endian uint32.
const (
	vsOffXres         = 0
	vsOffYres         = 4
	vsOffBitsPerPixel = 24
	vsOffRedOffset    = 32 // start of struct fb_bitfield red
	vsOffGreenOffset  = 44 // start of struct fb_bitfield green
	vsOffBlueOffset   = 56 // start of struct fb_bitfield blue
)

// Byte offsets into the raw fb_fix_screeninfo struct returned by
// FBIOGET_FSCREENINFO. Layout assumes a 64-bit kernel (the gokrazy
// appliance targets — arm64/amd64 — are both 64-bit). smem_start and
// mmio_start are "unsigned long", which is 8 bytes on 64-bit.
const (
	fsOffSmemLen    = 24
	fsOffLineLength = 48
)

var flagFB = flag.String("fb", "/dev/fb0", "framebuffer device to draw to")

// noFramebufferReason reports whether this host lacks a usable Linux
// framebuffer, along with a short human-readable explanation. If the
// framebuffer device is missing, or we're running on a cloud (currently
// only AWS) whose instances don't expose one, we return true.
func noFramebufferReason(fbPath string) (string, bool) {
	if cloudenv.Get() == cloudenv.AWS {
		return "running on AWS (no framebuffer)", true
	}
	if _, err := os.Stat(fbPath); err != nil {
		return fmt.Sprintf("no framebuffer at %s: %v", fbPath, err), true
	}
	return "", false
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Bail out early on cloud VMs that don't ship a framebuffer. We
	// still kick off breakglass once DHCP succeeds (otherwise the
	// appliance is unreachable — breakglass declares DontStartOnBoot
	// and only runs when fbstatus pokes the supervisor), then exit
	// 125 so the gokrazy supervisor stops respawning us. See
	// https://gokrazy.org/development/process-interface/.
	if reason, ok := noFramebufferReason(*flagFB); ok {
		log.Printf("%s; starting breakglass after DHCP then exiting 125", reason)
		startBreakglassAfterDHCP(&uiState{})
		log.Printf("breakglass started; exiting 125 so gokrazy won't respawn fbstatus")
		os.Exit(125)
	}

	if restore, err := claimVTGraphics(); err != nil {
		log.Printf("could not put VT into graphics mode (fbcon may overdraw): %v", err)
	} else {
		defer restore()
	}

	fb, err := openFramebuffer(*flagFB)
	if err != nil {
		return fmt.Errorf("open framebuffer: %w", err)
	}
	defer fb.Close()
	log.Printf("framebuffer %s: %dx%d, %d bpp, line=%d, RGB offsets %d/%d/%d",
		*flagFB, fb.width, fb.height, fb.bpp, fb.lineLength,
		fb.redShift, fb.greenShift, fb.blueShift)

	logo, err := png.Decode(bytes.NewReader(tailscalePNG))
	if err != nil {
		return fmt.Errorf("decoding embedded logo: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var lc local.Client
	st := &uiState{fb: fb, logo: logo}
	st.updateLAN()
	st.render()

	go st.pollLAN(ctx)
	go startBreakglassAfterDHCP(st)
	go watchKeyboardForConsole(ctx, st)

	for ctx.Err() == nil {
		if err := watchBusOnce(ctx, &lc, st); err != nil && ctx.Err() == nil {
			log.Printf("ipn watch: %v; retrying in 2s", err)
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
	return nil
}

func watchBusOnce(ctx context.Context, lc *local.Client, st *uiState) error {
	w, err := lc.WatchIPNBus(ctx,
		ipn.NotifyInitialState|ipn.NotifyInitialPrefs|ipn.NotifyInitialStatus)
	if err != nil {
		return err
	}
	defer w.Close()

	loginRequested := false

	for ctx.Err() == nil {
		n, err := w.Next()
		if err != nil {
			return err
		}
		if n.State != nil {
			st.state = *n.State
			// On a fresh appliance, tailscaled enters NeedsLogin but
			// does not generate a login URL until someone asks. Trigger
			// an interactive login so the control server sends us a URL
			// (and thus a QR code appears on the display).
			if *n.State == ipn.NeedsLogin && !loginRequested {
				loginRequested = true
				go func() {
					if err := lc.StartLoginInteractive(ctx); err != nil {
						log.Printf("StartLoginInteractive: %v", err)
					}
				}()
			}
		}
		if n.BrowseToURL != nil {
			st.loginURL = *n.BrowseToURL
		}
		if n.InitialStatus != nil {
			st.ips = append(st.ips[:0], n.InitialStatus.TailscaleIPs...)
		}
		if n.SelfChange != nil {
			st.ips = st.ips[:0]
			for _, p := range n.SelfChange.Addresses {
				st.ips = append(st.ips, p.Addr())
			}
		}
		st.render()
	}
	return ctx.Err()
}

// updateLAN scans network interfaces for a non-loopback interface with a
// hardware address, updating st.lanIP and st.lanMAC. Shows the MAC even
// if DHCP hasn't assigned an IP yet.
func (st *uiState) updateLAN() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var bestMAC string
	var bestIP string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		if bestMAC == "" {
			bestMAC = iface.HardwareAddr.String()
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// Prefer the first UP interface with a MAC.
		if bestMAC != iface.HardwareAddr.String() && bestIP == "" {
			bestMAC = iface.HardwareAddr.String()
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				bestMAC = iface.HardwareAddr.String()
				bestIP = ipnet.IP.String()
			}
		}
	}
	st.lanMAC = bestMAC
	st.lanIP = bestIP
}

// startBreakglassAfterDHCP waits until a LAN IP is assigned (meaning DHCP
// succeeded), then restarts breakglass. This ensures breakglass sees the
// real LAN address in PrivateInterfaceAddrs and binds to it, rather than
// only binding to 127.0.0.1.
func startBreakglassAfterDHCP(st *uiState) {
	for {
		st.updateLAN()
		if st.lanIP != "" {
			break
		}
		time.Sleep(time.Second)
	}
	startBreakglass()
}

// startBreakglass asks the gokrazy init HTTP API (over its unix socket) to
// restart the breakglass service so it actually runs. By default breakglass
// calls DontStartOnBoot and exits on the first launch attempt; this poke
// tells the supervisor to try again (without GOKRAZY_FIRST_START=1).
func startBreakglass() {
	const sock = "/run/gokrazy-http.sock"
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	form := url.Values{
		"path":      {"/user/breakglass"},
		"xsrftoken": {"1"},
	}
	req, err := http.NewRequest("POST", "http://gokrazy/restart", strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("startBreakglass: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "gokrazy_xsrf", Value: "1"})
	resp, err := hc.Do(req)
	if err != nil {
		log.Printf("startBreakglass: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode == http.StatusSeeOther {
		log.Printf("startBreakglass: restarted (status %s)", resp.Status)
	} else {
		log.Printf("startBreakglass: unexpected status %s", resp.Status)
	}
}

// watchKeyboardForConsole monitors keyboard input devices for VT-switching
// accelerators.
//   - Ctrl-Alt-F2 (or plain Esc — easier to type in NoVNC where the
//     Ctrl-Alt-Fn sequence doesn't always propagate) switches to VT2, a
//     text-mode busybox shell. When that shell exits, we switch back
//     automatically.
//   - Ctrl-Alt-F1 switches back to VT1 (fbstatus graphics mode).
//
// This mirrors standard Linux VT switching conventions plus a NoVNC-
// friendly shortcut.
func watchKeyboardForConsole(ctx context.Context, st *uiState) {
	kbdPath := findKeyboard()
	if kbdPath == "" {
		log.Printf("no keyboard found for VT switching")
		return
	}
	kbd, err := os.Open(kbdPath)
	if err != nil {
		log.Printf("open keyboard %s: %v", kbdPath, err)
		return
	}
	defer kbd.Close()

	ttyFile, err := os.OpenFile("/dev/tty0", os.O_RDWR, 0)
	if err != nil {
		log.Printf("open /dev/tty0 for VT switch: %v", err)
		return
	}
	defer ttyFile.Close()
	ttyFd := int(ttyFile.Fd())

	log.Printf("watching %s for Ctrl-Alt-F1/F2 and Esc (VT switching)", kbdPath)

	// Linux input_event has the same layout on both arm64 and amd64
	// (24 bytes: two uint64 timestamps + uint16 type + uint16 code +
	// int32 value), so this parser handles both the Pi and Proxmox VM.
	const evSize = 24
	const evKey = 1  // EV_KEY
	const keyEsc = 1 // KEY_ESC
	const keyF1 = 59 // KEY_F1
	const keyF2 = 60 // KEY_F2
	const keyLeftCtrl = 29
	const keyLeftAlt = 56
	const keyRightCtrl = 97
	const keyRightAlt = 100
	const keyPress = 1

	buf := make([]byte, evSize)
	var ctrlHeld, altHeld bool

	switchToFbstatus := func() {
		st.paused.Store(false)
		syscall.Syscall(syscall.SYS_IOCTL, uintptr(ttyFd), vtActivate, 1)
		syscall.Syscall(syscall.SYS_IOCTL, uintptr(ttyFd), vtWaitActive, 1)
		ioctlSetInt(ttyFile, kdSetMode, kdGraphics)
		st.render()
	}
	switchToShell := func(reason string) {
		st.paused.Store(true)
		ioctlSetInt(ttyFile, kdSetMode, kdText)
		syscall.Syscall(syscall.SYS_IOCTL, uintptr(ttyFd), vtActivate, 2)
		syscall.Syscall(syscall.SYS_IOCTL, uintptr(ttyFd), vtWaitActive, 2)
		go ensureShellOnVT2(switchToFbstatus)
		log.Printf("%s: switched to text console", reason)
	}

	for ctx.Err() == nil {
		n, err := kbd.Read(buf)
		if err != nil || n < evSize {
			continue
		}
		evType := binary.LittleEndian.Uint16(buf[16:18])
		evCode := binary.LittleEndian.Uint16(buf[18:20])
		evValue := int32(binary.LittleEndian.Uint32(buf[20:24]))

		if evType != evKey {
			continue
		}

		pressed := evValue == keyPress
		released := evValue == 0

		switch evCode {
		case keyLeftCtrl, keyRightCtrl:
			if pressed {
				ctrlHeld = true
			} else if released {
				ctrlHeld = false
			}
		case keyLeftAlt, keyRightAlt:
			if pressed {
				altHeld = true
			} else if released {
				altHeld = false
			}
		case keyEsc:
			if pressed && !ctrlHeld && !altHeld {
				// Bare Esc: NoVNC-friendly shortcut to the shell.
				switchToShell("Esc")
			}
		case keyF1:
			if pressed && ctrlHeld && altHeld {
				switchToFbstatus()
				log.Printf("Ctrl-Alt-F1: switched to fbstatus")
			}
		case keyF2:
			if pressed && ctrlHeld && altHeld {
				switchToShell("Ctrl-Alt-F2")
			}
		}
	}
}

// ensureShellOnVT2 spawns a busybox ash shell on /dev/tty2 if one isn't
// already running. The shell gets the VT2 tty as its controlling terminal
// so keyboard input on VT2 goes to it. When the shell exits, onExit is
// called (typically to switch back to VT1 / fbstatus graphics mode).
var shellOnVT2Running atomic.Bool

func ensureShellOnVT2(onExit func()) {
	if !shellOnVT2Running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer shellOnVT2Running.Store(false)
		defer func() {
			if onExit != nil {
				onExit()
			}
		}()
		shell := "/tmp/serial-busybox/ash"
		if _, err := os.Stat(shell); err != nil {
			log.Printf("no shell at %s for VT2", shell)
			return
		}
		tty, err := os.OpenFile("/dev/tty2", os.O_RDWR, 0)
		if err != nil {
			log.Printf("open /dev/tty2: %v", err)
			return
		}
		defer tty.Close()
		cmd := exec.Command(shell)
		cmd.Stdin = tty
		cmd.Stdout = tty
		cmd.Stderr = tty
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid:  true,
			Setctty: true,
			Ctty:    0, // index into cmd's file descriptors (stdin = tty)
		}
		cmd.Env = append(os.Environ(), "TERM=linux", "HOME=/tmp", "PATH=/tmp/serial-busybox:/user:/gokrazy")
		log.Printf("starting shell on VT2")
		if err := cmd.Run(); err != nil {
			log.Printf("shell on VT2 exited: %v", err)
		}
	}()
}

// findKeyboard looks for a keyboard among /dev/input/event* devices by
// checking that the device's key capability bitmap has KEY_ESC set. The
// alternative "any non-zero key bitmap" check picks up the ACPI power
// button (which advertises KEY_POWER but no Esc) and misses the real
// keyboard on amd64 Proxmox VMs, where the AT keyboard is event1 but
// event0 is Power Button.
func findKeyboard() string {
	matches, _ := filepath.Glob("/dev/input/event*")
	for _, path := range matches {
		name := filepath.Base(path)
		capData, err := os.ReadFile("/sys/class/input/" + name + "/device/capabilities/key")
		if err != nil {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(string(capData)))
		if len(fields) == 0 {
			continue
		}
		// The kernel prints capability bitmaps as space-separated 64-bit
		// hex chunks, most-significant chunk first. The last chunk holds
		// bits 0..63. KEY_ESC = 1, so its bit-mask is 1<<1 == 0x2.
		low, err := strconv.ParseUint(fields[len(fields)-1], 16, 64)
		if err != nil {
			continue
		}
		const keyEscBit = 1 << 1
		if low&keyEscBit != 0 {
			return path
		}
	}
	return ""
}

// pollLAN periodically refreshes LAN info and re-renders.
func (st *uiState) pollLAN(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			st.updateLAN()
			st.render()
		}
	}
}

// uiState is the most-recently-known view of the appliance state that
// gets rendered to the framebuffer on each notify.
type uiState struct {
	fb   *framebuffer
	logo image.Image

	state    ipn.State
	loginURL string
	ips      []netip.Addr

	lanIP  string // LAN IPv4 address (from DHCP)
	lanMAC string // MAC address of the primary interface

	paused atomic.Bool // when true, render() is a no-op (VT switched away)
}

var (
	bgColor   = color.RGBA{0x10, 0x12, 0x20, 0xff} // near-black slate
	fgColor   = color.RGBA{0xff, 0xff, 0xff, 0xff}
	dimColor  = color.RGBA{0xa0, 0xa6, 0xb8, 0xff}
	stateOK   = color.RGBA{0x4a, 0xc8, 0x82, 0xff} // green for Running
	stateWait = color.RGBA{0xf0, 0xc8, 0x60, 0xff} // amber for NeedsLogin/Starting
)

// render composes the current state into an in-memory image and blits
// it to the framebuffer.
func (st *uiState) render() {
	if st.paused.Load() {
		return
	}
	w, h := st.fb.width, st.fb.height
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: bgColor}, image.Point{}, draw.Src)

	shortSide := min(w, h)

	// Logo, scaled to ~25% of the shorter dimension, centered
	// horizontally near the top.
	logoSize := shortSide / 4
	logoRect := image.Rect(0, 0, logoSize, logoSize).Add(image.Point{
		X: (w - logoSize) / 2,
		Y: shortSide / 16,
	})
	xdraw.ApproxBiLinear.Scale(img, logoRect, st.logo, st.logo.Bounds(), xdraw.Over, nil)

	lineH := basicfont.Face7x13.Metrics().Height.Ceil()
	textTop := logoRect.Max.Y + shortSide/24

	// Hide the state line when the QR code is visible (the "Scan to
	// enroll" label is clear enough context).
	showState := !(st.state == ipn.NeedsLogin && st.loginURL != "")
	if showState {
		stateColor := dimColor
		switch st.state {
		case ipn.Running:
			stateColor = stateOK
		case ipn.NeedsLogin, ipn.Starting, ipn.NoState:
			stateColor = stateWait
		}
		drawCenteredScaled(img, fmt.Sprintf("State: %s", stateLabel(st.state)),
			stateColor, w/2, textTop, 3)
	}

	y := textTop + 3*lineH + shortSide/40

	if len(st.ips) > 0 {
		drawCenteredScaled(img, "Tailscale IPs:", dimColor, w/2, y, 2)
		y += 2 * lineH
		for _, a := range st.ips {
			drawCenteredScaled(img, a.String(), fgColor, w/2, y, 2)
			y += 2*lineH + 4
		}
	}

	// QR code with the login URL when enrollment is needed.
	if st.state == ipn.NeedsLogin && st.loginURL != "" {
		qrSize := shortSide / 2
		q, err := qrcode.New(st.loginURL, qrcode.Medium)
		if err != nil {
			log.Printf("qr encode %q: %v", st.loginURL, err)
		} else {
			q.DisableBorder = false
			qrImg := q.Image(qrSize)
			qrRect := qrImg.Bounds().Add(image.Point{
				X: (w - qrSize) / 2,
				Y: h - qrSize - shortSide/16,
			})
			draw.Draw(img, qrRect, qrImg, qrImg.Bounds().Min, draw.Src)
			drawCenteredScaled(img, "Scan to enroll this device",
				fgColor, w/2, qrRect.Min.Y-lineH*2-8, 2)
		}
	}

	// LAN status pinned to the bottom-left corner.
	{
		lanY := h - lineH - 4
		var lanText string
		if st.lanIP != "" {
			lanText = "LAN IP: " + st.lanIP
		} else if st.lanMAC != "" {
			lanText = "Waiting for DHCP (" + st.lanMAC + ")"
		}
		if lanText != "" {
			face := basicfont.Face7x13
			textW := font.MeasureString(face, lanText).Ceil()
			small := image.NewRGBA(image.Rect(0, 0, textW, lineH))
			d := font.Drawer{
				Dst:  small,
				Src:  &image.Uniform{C: dimColor},
				Face: face,
				Dot:  fixed.P(0, face.Metrics().Ascent.Ceil()),
			}
			d.DrawString(lanText)
			dstRect := image.Rect(4, lanY, 4+textW, lanY+lineH)
			draw.Draw(img, dstRect, small, image.Point{}, draw.Over)
		}
	}

	st.fb.blit(img)
}

// drawCenteredScaled draws s with basicfont.Face7x13 at the given
// integer pixel scale, centered horizontally on x at top y, in col.
func drawCenteredScaled(dst *image.RGBA, s string, col color.Color, x, y, scale int) {
	if s == "" {
		return
	}
	face := basicfont.Face7x13
	width := font.MeasureString(face, s).Ceil()
	height := face.Metrics().Height.Ceil()

	small := image.NewRGBA(image.Rect(0, 0, width, height))
	d := font.Drawer{
		Dst:  small,
		Src:  &image.Uniform{C: col},
		Face: face,
		Dot:  fixed.P(0, face.Metrics().Ascent.Ceil()),
	}
	d.DrawString(s)

	scaledW, scaledH := width*scale, height*scale
	dstRect := image.Rect(0, 0, scaledW, scaledH).Add(image.Point{
		X: x - scaledW/2,
		Y: y,
	})
	xdraw.NearestNeighbor.Scale(dst, dstRect, small, small.Bounds(), xdraw.Over, nil)
}

func stateLabel(s ipn.State) string {
	switch s {
	case ipn.NoState, ipn.Starting:
		return "starting"
	case ipn.NeedsLogin:
		return "needs login"
	case ipn.NeedsMachineAuth:
		return "needs machine auth"
	case ipn.Stopped:
		return "stopped"
	case ipn.Running:
		return "running"
	}
	return strings.ToLower(s.String())
}

// framebuffer is an mmap'd Linux framebuffer device.
type framebuffer struct {
	f          *os.File
	mem        []byte
	width      int
	height     int
	bpp        int
	lineLength int

	// Bit offsets into a 32-bit pixel for each channel, from the
	// fb_bitfield values returned by FBIOGET_VSCREENINFO.
	redShift   uint32
	greenShift uint32
	blueShift  uint32
}

// openFramebuffer opens path, queries dimensions and pixel format via
// the FBIOGET_* ioctls, and mmaps the framebuffer memory.
//
// Only 32-bits-per-pixel framebuffers are supported. Raspberry Pi 3/4/5
// default to that.
func openFramebuffer(path string) (*framebuffer, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var (
		vbuf [160]byte // fb_var_screeninfo
		fbuf [80]byte  // fb_fix_screeninfo
	)
	if err := ioctlGet(f, fbioGetVScreenInfo, vbuf[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("FBIOGET_VSCREENINFO: %w", err)
	}
	if err := ioctlGet(f, fbioGetFScreenInfo, fbuf[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("FBIOGET_FSCREENINFO: %w", err)
	}

	fb := &framebuffer{
		f:          f,
		width:      int(binary.LittleEndian.Uint32(vbuf[vsOffXres:])),
		height:     int(binary.LittleEndian.Uint32(vbuf[vsOffYres:])),
		bpp:        int(binary.LittleEndian.Uint32(vbuf[vsOffBitsPerPixel:])),
		lineLength: int(binary.LittleEndian.Uint32(fbuf[fsOffLineLength:])),
		redShift:   binary.LittleEndian.Uint32(vbuf[vsOffRedOffset:]),
		greenShift: binary.LittleEndian.Uint32(vbuf[vsOffGreenOffset:]),
		blueShift:  binary.LittleEndian.Uint32(vbuf[vsOffBlueOffset:]),
	}
	if fb.bpp != 32 {
		f.Close()
		return nil, fmt.Errorf("unsupported framebuffer bpp %d (only 32 is supported)", fb.bpp)
	}

	memLen := int(binary.LittleEndian.Uint32(fbuf[fsOffSmemLen:]))
	mem, err := unix.Mmap(int(f.Fd()), 0, memLen,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("mmap %s: %w", path, err)
	}
	fb.mem = mem
	return fb, nil
}

func (fb *framebuffer) Close() error {
	if fb.mem != nil {
		unix.Munmap(fb.mem)
		fb.mem = nil
	}
	return fb.f.Close()
}

// blit copies img into the mapped framebuffer, packing each
// image.RGBA pixel into the framebuffer's per-channel bit layout.
func (fb *framebuffer) blit(img *image.RGBA) {
	srcStride := img.Stride
	for y := 0; y < fb.height; y++ {
		srcRow := img.Pix[y*srcStride : y*srcStride+fb.width*4]
		dstRow := fb.mem[y*fb.lineLength:]
		for x := 0; x < fb.width; x++ {
			r := uint32(srcRow[x*4+0])
			g := uint32(srcRow[x*4+1])
			b := uint32(srcRow[x*4+2])
			px := r<<fb.redShift | g<<fb.greenShift | b<<fb.blueShift
			binary.LittleEndian.PutUint32(dstRow[x*4:], px)
		}
	}
}

// claimVTGraphics puts the active virtual terminal into KD_GRAPHICS so
// the kernel's framebuffer console (fbcon) stops drawing on /dev/fb0
// while fbstatus owns it. It returns a function that restores KD_TEXT.
//
// The Linux kernel applies VT mode to whatever VT is current; the open
// path /dev/tty0 always refers to the foreground VT, which on a
// headless gokrazy appliance is the only VT.
func claimVTGraphics() (restore func(), err error) {
	f, err := os.OpenFile("/dev/tty0", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err := ioctlSetInt(f, kdSetMode, kdGraphics); err != nil {
		f.Close()
		return nil, fmt.Errorf("KDSETMODE KD_GRAPHICS: %w", err)
	}
	return func() {
		if err := ioctlSetInt(f, kdSetMode, kdText); err != nil {
			log.Printf("KDSETMODE KD_TEXT on shutdown: %v", err)
		}
		f.Close()
	}, nil
}

// ioctlSetInt runs an ioctl with a single integer arg, like KDSETMODE.
func ioctlSetInt(f *os.File, req uintptr, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

// ioctlGet runs an ioctl that fills a struct of len(buf) bytes in buf.
// Used for the FBIOGET_* ioctls; on success buf holds the kernel's
// fb_*_screeninfo struct.
func ioctlGet(f *os.File, req uintptr, buf []byte) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), req,
		uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return errno
	}
	return nil
}
