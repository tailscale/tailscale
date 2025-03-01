// Copyright (c) Plan 9 Foundation, Russ Cox, Google LLC, Tailscale Inc, etc.
// SPDX-License-Identifier: BSD-3-Clause

// This file is a fork of github.com/9fans/go (Go module 9fans.net/go)'s
// file ./plan9/srv9p/example/netshell/main.go turned from a package main
// to a non-main package.

//go:build plan9

// Package netshell implements /dev/cons and /dev/consctl using
// stdin and stdout as a source of bytes and runs a login shell
// in a new namespace with /dev/cons opened to it.
//
// For example, the one-line “insecure shell daemon”:
//
//	aux/listen1 'tcp!*!22222' netshell
//
// This differs from running rc directly in that it provides
// terminal echo, a /dev/cons file, and mostly standard Plan 9 line editing
// (^C, ^D, ^U, ^W, backspace, and delete).
// Unlike standard Plan 9, ^C sends an interrupt and delete is backspace.
package netshell

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unicode/utf8"

	"9fans.net/go/plan9"
	"9fans.net/go/plan9/srv9p"
)

const Env = "_NETSHELL_CHILD_"

var Verbose = os.Getenv("NETSHELL_VERBOSE") == "1"

func init() {
	if os.Getenv(Env) != "" {
		runtime.LockOSThread() // to keep runChild on main thread
	}
}

func Main() {
	log.SetFlags(0)
	log.SetPrefix("netshell: ")

	if os.Getenv(Env) != "" {
		runChild()
		return
	}

	c := newConsole(os.Stdin, os.Stdout)

	tree := srv9p.NewTree("netshell", "netshell", plan9.DMDIR|0555, nil)
	cons, _ := tree.Root.Create("cons", "netshell", 0666, nil)
	consctl, _ := tree.Root.Create("consctl", "netshell", 0222, nil)

	srv := &srv9p.Server{
		Tree: tree,
		Read: func(ctx context.Context, fid *srv9p.Fid, data []byte, offset int64) (int, error) {
			switch fid.File() {
			default:
				return 0, fmt.Errorf("unknown file")
			case cons:
				return c.consRead(ctx, data)
			}
		},
		Write: func(ctx context.Context, fid *srv9p.Fid, data []byte, offset int64) (int, error) {
			switch fid.File() {
			default:
				return 0, fmt.Errorf("unknown file")
			case cons:
				return c.consWrite(ctx, data)
			case consctl:
				return c.consctlWrite(data)
			}
		},
		Clunk: func(fid *srv9p.Fid) {
			if fid.File() == consctl {
				c.consctlClose()
			}
		},
	}
	if Verbose {
		srv.Trace = os.Stderr
	}

	p1, p2, err := os.Pipe()
	if err != nil {
		log.Fatal(err)
	}
	go srv.Serve(p1, p1)

	// Child process runs with the 9P service on stdin (pipes are bidirectional),
	// leaving stdout and stderr directly connected to the parent's stdout/stderr
	// for printing any last gasp errors.
	// The child mounts the 9P session and then runs a shell or other command.
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command("/bin/auth/newns", exe)
	cmd.Env = append(os.Environ(), Env+"=1")
	cmd.Stdin = p2
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Rfork: syscall.RFNOTEG | syscall.RFNAMEG}
	err = cmd.Start()
	p2.Close()
	if err != nil {
		log.Fatal(err)
	}
	cmd.Wait()
}

func runChild() {
	// Note: locked on main thread, so RFNOTEG and RFNAMEG will not migrate elsewhere.
	syscall.RawSyscall(syscall.SYS_RFORK, syscall.RFNOTEG|syscall.RFNAMEG, 0, 0)

	// Mount console device from parent process onto /dev and open.
	if err := syscall.Mount(0, -1, "/dev", syscall.MBEFORE, ""); err != nil {
		log.Fatalf("mount /dev: %v", err)
	}
	cons, err := syscall.Open("/dev/cons", syscall.O_RDWR)
	if err != nil {
		log.Fatal(err)
	}

	// Tell parent to open our note group file for sending interrupts.
	consctl, err := syscall.Open("/dev/consctl", syscall.O_WRONLY)
	if err == nil {
		syscall.Write(consctl, []byte(fmt.Sprintf("notepg %d", os.Getpid())))
		syscall.Close(consctl)
	} else if err != nil {
		log.Print(err)
	}

	// Put /dev/cons on stdin, stdout, stderr and exec command.
	syscall.Dup(cons, 0)
	syscall.Dup(cons, 1)
	syscall.Dup(cons, 2)
	if cons > 2 {
		syscall.Close(cons)
	}
	args := flag.Args()
	if len(args) == 0 {
		args = []string{"/bin/rc", "-l"}
	}
	err = syscall.Exec(args[0], args, append(os.Environ(), "service=netshell"))
	log.Fatal(err)
}

// A rendez is a simple sleep/wakeup primitive (like a condition variable)
// based on a channel. Using a channel lets us sleep on the rendez until
// either it becomes ready or a context is canceled.
type rendez chan bool

func newRendez() rendez {
	return make(rendez, 1)
}

// Sleep sleeps until either something calls r.Wakeup or the context is canceled.
func (r rendez) Sleep(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-r:
	}
}

// Wakeup wakes up one call to r.Sleep or returns immediately if
// there are no calls sleeping.
func (r rendez) Wakeup() {
	select {
	default:
	case r <- true:
	}
}

const (
	maxLine = 4096 // max line buffer
	maxBuf  = 8192 // max read/write buffer
)

// A console implements a simple terminal-like device reading from
// r and writing to w.
type console struct {
	r io.Reader // reader connected to network
	w io.Writer // writer connected to network

	mu         sync.Mutex
	notefd     int
	raw        bool
	line       []byte // line buffer
	read       []byte // from network
	readErr    error
	readEmpty  rendez
	readFull   rendez
	write      []byte // to network
	writeErr   error
	writeEmpty rendez
	writeFull  rendez
}

// newConsole creates a new console reading from r and writing to w.
func newConsole(r io.Reader, w io.Writer) *console {
	c := &console{
		r:          r,
		w:          w,
		notefd:     -1,
		readEmpty:  newRendez(),
		readFull:   newRendez(),
		writeEmpty: newRendez(),
		writeFull:  newRendez(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	go c.readNet(ctx)
	go c.writeNet(ctx)
	_ = cancel
	return c
}

// consctlClose handles a close of /dev/consctl; it turns raw mode off.
func (c *console) consctlClose() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.raw = false
}

// consctlWrite handles writes to /dev/consctl.
func (c *console) consctlWrite(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := strings.TrimSpace(string(data))
	switch s {
	case "rawon": // turn raw mode on
		c.raw = true
		c.read = append(c.read, c.line...)
		c.line = nil
		return len(data), nil

	case "rawoff": // turn raw mode off
		c.raw = false
		return len(data), nil
	}

	if s, ok := strings.CutPrefix(s, "notepg"); ok { // notepg n means send interrupt notes to /proc/n/notepg
		if _, err := strconv.ParseUint(s, 10, 64); err != nil {
			return 0, fmt.Errorf("bad notepg")
		}
		fd, err := syscall.Open("/proc/"+s+"/notepg", syscall.O_WRONLY)
		if err != nil {
			return 0, err
		}
		c.notefd = fd
		return len(data), nil
	}

	return 0, fmt.Errorf("unknown control message")
}

// readNet reads bytes from the network connection
// and adds them to the read buffer for use by /dev/cons.
func (c *console) readNet(ctx context.Context) {
	buf := make([]byte, 4096)
	for context.Cause(ctx) == nil {
		n, err := c.r.Read(buf)
		if n > 0 {
			c.consType(ctx, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

const (
	Backspace = 'H' - '@'
	Delete    = 0x7F
	CtrlC     = 'C' - '@'
	CtrlD     = 'D' - '@'
	CtrlU     = 'U' - '@'
	CtrlW     = 'W' - '@'
)

// consType processes typed characters, adding them to the console.
func (c *console) consType(ctx context.Context, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.raw {
		c.addRead(ctx, data)
		return
	}
	for _, ch := range data {
		if len(c.line) >= maxLine { // too much, just send it
			c.addRead(ctx, c.line)
			c.line = c.line[:0]
		}

		switch ch {
		default:
			c.consWriteLocked(ctx, []byte{ch})
			c.line = append(c.line, ch)

		case '\r', '\n':
			ch = '\n'
			c.consWriteLocked(ctx, []byte{ch})
			c.line = append(c.line, ch)
			c.addRead(ctx, c.line)
			c.line = c.line[:0]

		case CtrlC:
			if c.notefd >= 0 {
				syscall.Write(c.notefd, []byte("interrupt"))
			}
			c.consWriteLocked(ctx, []byte(fmt.Sprintf("^C")))

		case CtrlD:
			c.consWriteLocked(ctx, []byte("^D"))
			c.line = append(c.line, CtrlD)
			c.addRead(ctx, c.line)
			c.line = c.line[:0]

		case Backspace, Delete:
			if len(c.line) > 0 {
				_, size := utf8.DecodeLastRune(c.line)
				c.line = c.line[:len(c.line)-size]
				c.consWriteLocked(ctx, []byte{ch})
			}

		case CtrlW:
			deleted := false
			for len(c.line) > 0 {
				r, size := utf8.DecodeLastRune(c.line)
				alnum := unicode.IsLetter(r) || unicode.IsDigit(r)
				if alnum {
					deleted = true
				} else if deleted {
					break
				}
				c.line = c.line[:len(c.line)-size]
				c.consWriteLocked(ctx, []byte{Backspace})
			}

		case CtrlU:
			if len(c.line) > 0 {
				c.consWriteLocked(ctx, []byte("^U\n"))
				c.line = c.line[:0]
			}

		}
	}
}

// addRead adds data to the read buffer.
func (c *console) addRead(ctx context.Context, data []byte) (int, error) {
	b := data
	for len(b) > 0 {
		if err := context.Cause(ctx); err != nil {
			return len(data) - len(b), err
		}
		n := min(maxBuf-len(c.read), len(b))
		if n <= 0 {
			c.mu.Unlock()
			c.readFull.Sleep(ctx)
			c.mu.Lock()
			continue
		}
		c.read = append(c.read, b[:n]...)
		b = b[n:]
		c.readEmpty.Wakeup()
	}
	return len(data), nil
}

// consRead uses the read buffer to satisfy a 9P read of /dev/cons.
func (c *console) consRead(ctx context.Context, data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		if err := context.Cause(ctx); err != nil {
			return 0, err
		}
		if len(c.read) == 0 {
			c.mu.Unlock()
			c.readEmpty.Sleep(ctx)
			c.mu.Lock()
			continue
		}
		if c.raw {
			n := copy(data, c.read)
			c.read = c.read[:copy(c.read, c.read[n:])]
			c.readFull.Wakeup()
			return n, nil
		}

		// Identify next line.
		n := min(len(data), len(c.read))
		if i := bytes.IndexByte(c.read[:n], '\n'); i >= 0 {
			n = i + 1
		}
		if i := bytes.IndexByte(c.read[:n], CtrlD); i >= 0 {
			n = i + 1
		}
		copy(data, c.read[:n])
		c.read = c.read[:copy(c.read, c.read[n:])]
		c.readFull.Wakeup()
		if n > 0 && data[n-1] == CtrlD {
			n--
		}
		return n, nil
	}
}

// consWrite handles a write to /dev/cons by adding data to the write buffer.
func (c *console) consWrite(ctx context.Context, data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.consWriteLocked(ctx, data)
}

func (c *console) consWriteLocked(ctx context.Context, data []byte) (int, error) {
	b := data
	for len(b) > 0 {
		if err := context.Cause(ctx); err != nil {
			return len(data) - len(b), err
		}
		n := min(maxBuf-len(c.write), len(b))
		if n <= 0 {
			c.mu.Unlock()
			c.writeFull.Sleep(ctx)
			c.mu.Lock()
			continue
		}
		c.write = append(c.write, b[:n]...)
		b = b[n:]
		c.writeEmpty.Wakeup()
	}
	return len(data), nil
}

// writeNet writes bytes from the write buffer to the network connection.
func (c *console) writeNet(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var withCR []byte

	for context.Cause(ctx) == nil {
		if len(c.write) == 0 {
			c.mu.Unlock()
			c.writeEmpty.Sleep(ctx)
			c.mu.Lock()
			continue
		}

		b := c.write
		c.mu.Unlock()

		withCR = withCR[:0]
		for _, b := range b {
			if b == '\n' {
				withCR = append(withCR, '\r', '\n')
			} else {
				withCR = append(withCR, b)
			}
		}

		_, err := c.w.Write(withCR)
		c.mu.Lock()
		if err != nil {
			c.writeErr = err
			return
		}
		c.write = c.write[:copy(c.write, c.write[len(b):])]
		c.writeFull.Wakeup()
	}
}
