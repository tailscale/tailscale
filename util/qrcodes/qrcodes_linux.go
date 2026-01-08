// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_qrcodes

package qrcodes

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/mattn/go-isatty"
	"golang.org/x/sys/unix"
)

func detectFormat(w io.Writer, inverse bool) (format Format, _ error) {
	var zero Format

	// Almost every terminal supports UTF-8, but the Linux
	// console may have partial or no support, which is
	// especially painful inside VMs. See tailscale/tailscale#12935.
	format = FormatSmall

	// Is the locale (LC_CTYPE) set to UTF-8?
	locale, err := locale()
	if err != nil {
		return FormatASCII, fmt.Errorf("QR: %w", err)
	}
	const utf8 = ".UTF-8"
	if !strings.HasSuffix(locale["LC_CTYPE"], utf8) &&
		!strings.HasSuffix(locale["LANG"], utf8) {
		return FormatASCII, nil
	}

	// Are we printing to a terminal?
	f, ok := w.(*os.File)
	if !ok {
		return format, nil
	}
	if !isatty.IsTerminal(f.Fd()) {
		return format, nil
	}
	fd := f.Fd()

	// On a Linux console, check that the current keyboard
	// is in Unicode mode. See unicode_start(1).
	const K_UNICODE = 0x03
	kbMode, err := ioctlGetKBMode(fd)
	if err != nil {
		if errors.Is(err, syscall.ENOTTY) {
			return format, nil
		}
		return zero, err
	}
	if kbMode != K_UNICODE {
		return FormatASCII, nil
	}

	// On a raw Linux console, detect whether the block
	// characters are available in the current font by
	// consulting the Unicode-to-font mapping.
	unimap, err := ioctlGetUniMap(fd)
	if err != nil {
		return zero, err
	}
	if _, ok := unimap['█']; ok {
		format = FormatLarge
	}
	if _, ok := unimap['▀']; ok && inverse {
		format = FormatSmall
	}
	if _, ok := unimap['▄']; ok && !inverse {
		format = FormatSmall
	}

	return format, nil
}

func locale() (map[string]string, error) {
	locale := map[string]string{
		"LANG":     os.Getenv("LANG"),
		"LC_CTYPE": os.Getenv("LC_CTYPE"),
	}

	cmd := exec.Command("locale")
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return locale, nil
		}
		return nil, fmt.Errorf("locale error: %w", err)
	}

	for line := range strings.SplitSeq(string(out), "\n") {
		if line == "" {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		v, err := strconv.Unquote(v)
		if err != nil {
			continue
		}
		locale[k] = v
	}
	return locale, nil
}

func ioctlGetKBMode(fd uintptr) (int, error) {
	const KDGKBMODE = 0x4b44
	mode, err := unix.IoctlGetInt(int(fd), KDGKBMODE)
	if err != nil {
		return 0, fmt.Errorf("keyboard mode error: %w", err)
	}
	return mode, nil
}

func ioctlGetUniMap(fd uintptr) (map[rune]int, error) {
	const GIO_UNIMAP = 0x4B66 // get unicode-to-font mapping from kernel
	var ud struct {
		Count   uint16
		Entries uintptr // pointer to unipair array
	}
	type unipair struct {
		Unicode uint16 // Unicode value
		FontPos uint16 // Font position in the console font
	}

	// First, get the number of entries:
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, GIO_UNIMAP, uintptr(unsafe.Pointer(&ud)))
	if errno != 0 && !errors.Is(errno, syscall.ENOMEM) {
		return nil, fmt.Errorf("unicode mapping error: %w", errno)
	}

	// Then allocate enough space and get the entries themselves:
	if ud.Count == 0 {
		return nil, nil
	}
	entries := make([]unipair, ud.Count)
	ud.Entries = uintptr(unsafe.Pointer(&entries[0]))
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, GIO_UNIMAP, uintptr(unsafe.Pointer(&ud)))
	if errno != 0 {
		return nil, fmt.Errorf("unicode mapping error: %w", errno)
	}

	unimap := make(map[rune]int)
	for _, e := range entries {
		unimap[rune(e.Unicode)] = int(e.FontPos)
	}
	return unimap, nil
}
