// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package conpty implements support for Windows pseudo-consoles.
package conpty

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/dblohm7/wingoes"
	"golang.org/x/sys/windows"
	"tailscale.com/util/winutil"
)

var (
	// ErrUnsupported is returned by NewPseudoConsole if the current Windows
	// build does not support this package's API.
	ErrUnsupported = errors.New("conpty unsupported on this version of Windows")
)

// PseudoConsole encapsulates a Windows pseudo-console. Use NewPseudoConsole
// to create a new instance.
type PseudoConsole struct {
	outputRead io.ReadCloser
	inputWrite io.WriteCloser
	console    windows.Handle
}

// NewPseudoConsole creates a new PseudoConsole using size for its initial
// width and height. It requires Windows 10 1809 or newer, and will return
// ErrUnsupported if that requirement is not met.
func NewPseudoConsole(size windows.Coord) (pty *PseudoConsole, err error) {
	if !wingoes.IsWin10BuildOrGreater(wingoes.Win10Build1809) {
		return nil, ErrUnsupported
	}
	if size.X <= 0 || size.Y <= 0 {
		return nil, fmt.Errorf("%w: size must contain positive values", os.ErrInvalid)
	}

	var inputRead, inputWrite windows.Handle
	if err := windows.CreatePipe(&inputRead, &inputWrite, nil, 0); err != nil {
		return nil, err
	}
	defer func() {
		windows.CloseHandle(inputRead)
		if err != nil {
			windows.CloseHandle(inputWrite)
		}
	}()

	var outputRead, outputWrite windows.Handle
	if err := windows.CreatePipe(&outputRead, &outputWrite, nil, 0); err != nil {
		return nil, err
	}
	defer func() {
		windows.CloseHandle(outputWrite)
		if err != nil {
			windows.CloseHandle(outputRead)
		}
	}()

	var console windows.Handle
	if err := windows.CreatePseudoConsole(size, inputRead, outputWrite, 0, &console); err != nil {
		return nil, err
	}

	pty = &PseudoConsole{
		outputRead: os.NewFile(uintptr(outputRead), "ptyOutputRead"),
		inputWrite: os.NewFile(uintptr(inputWrite), "ptyInputWrite"),
		console:    console,
	}
	return pty, nil
}

// Resize sets the width and height of pty to size.
func (pty *PseudoConsole) Resize(size windows.Coord) error {
	if pty.console == 0 {
		return fmt.Errorf("PseudoConsole is closed")
	}
	if size.X <= 0 || size.Y <= 0 {
		return fmt.Errorf("%w: size must contain positive values", os.ErrInvalid)
	}

	return windows.ResizePseudoConsole(pty.console, size)
}

// Close shuts down the pty. The caller must continue reading from the
// ReadCloser returned by Output until either EOF is reached or Close returns;
// failure to adequately drain the ReadCloser may result in Close deadlocking.
func (pty *PseudoConsole) Close() error {
	if pty.console != 0 {
		windows.ClosePseudoConsole(pty.console)
		pty.console = 0
	}

	// now we can stop these
	if pty.outputRead != nil {
		pty.outputRead.Close()
		pty.outputRead = nil
	}
	if pty.inputWrite != nil {
		pty.inputWrite.Close()
		pty.inputWrite = nil
	}
	return nil
}

// ConfigureStartupInfo associates pty with the process to be started using sib.
func (pty *PseudoConsole) ConfigureStartupInfo(sib *winutil.StartupInfoBuilder) error {
	if sib == nil {
		return os.ErrInvalid
	}
	// We need to explicitly set null std handles.
	// Failure to do so causes interference between the pty and the console
	// handles that are implicitly inherited from the parent.
	// This isn't explicitly documented anywhere. Windows Terminal does this too.
	if err := sib.SetStdHandles(0, 0, 0); err != nil {
		return err
	}
	return sib.SetPseudoConsole(pty.console)
}

// OutputPipe returns the ReadCloser for reading pty's output.
func (pty *PseudoConsole) OutputPipe() io.ReadCloser {
	return pty.outputRead
}

// InputPipe returns the WriteCloser for writing pty's output.
func (pty *PseudoConsole) InputPipe() io.WriteCloser {
	return pty.inputWrite
}
