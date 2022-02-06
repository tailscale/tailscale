//go:build !windows && !js

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

// Package rwcancel implements cancelable read/write operations on
// a file descriptor.
package rwcancel

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type RWCancel struct {
	fd            int
	closingReader *os.File
	closingWriter *os.File
}

func NewRWCancel(fd int) (*RWCancel, error) {
	err := unix.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}
	rwcancel := RWCancel{fd: fd}

	rwcancel.closingReader, rwcancel.closingWriter, err = os.Pipe()
	if err != nil {
		return nil, err
	}

	return &rwcancel, nil
}

func RetryAfterError(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
}

func (rw *RWCancel) ReadyRead() bool {
	closeFd := int32(rw.closingReader.Fd())

	pollFds := []unix.PollFd{{Fd: int32(rw.fd), Events: unix.POLLIN}, {Fd: closeFd, Events: unix.POLLIN}}
	var err error
	for {
		_, err = unix.Poll(pollFds, -1)
		if err == nil || !RetryAfterError(err) {
			break
		}
	}
	if err != nil {
		return false
	}
	if pollFds[1].Revents != 0 {
		return false
	}
	return pollFds[0].Revents != 0
}

func (rw *RWCancel) ReadyWrite() bool {
	closeFd := int32(rw.closingReader.Fd())
	pollFds := []unix.PollFd{{Fd: int32(rw.fd), Events: unix.POLLOUT}, {Fd: closeFd, Events: unix.POLLOUT}}
	var err error
	for {
		_, err = unix.Poll(pollFds, -1)
		if err == nil || !RetryAfterError(err) {
			break
		}
	}
	if err != nil {
		return false
	}

	if pollFds[1].Revents != 0 {
		return false
	}
	return pollFds[0].Revents != 0
}

func (rw *RWCancel) Read(p []byte) (n int, err error) {
	for {
		n, err := unix.Read(rw.fd, p)
		if err == nil || !RetryAfterError(err) {
			return n, err
		}
		if !rw.ReadyRead() {
			return 0, os.ErrClosed
		}
	}
}

func (rw *RWCancel) Write(p []byte) (n int, err error) {
	for {
		n, err := unix.Write(rw.fd, p)
		if err == nil || !RetryAfterError(err) {
			return n, err
		}
		if !rw.ReadyWrite() {
			return 0, os.ErrClosed
		}
	}
}

func (rw *RWCancel) Cancel() (err error) {
	_, err = rw.closingWriter.Write([]byte{0})
	return
}

func (rw *RWCancel) Close() {
	rw.closingReader.Close()
	rw.closingWriter.Close()
}
