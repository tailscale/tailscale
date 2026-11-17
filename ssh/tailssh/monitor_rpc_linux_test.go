// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Regression assertion for rejected SCM_RIGHTS ancillary data: any subset
// installed by the kernel must be closed, even when MSG_CTRUNC is set.
func TestMonitorRPCAncillaryTruncationDoesNotLeak(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	var original []int
	defer func() { closeFds(original) }()
	for range 4 {
		fd, e := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if e != nil {
			t.Fatal(e)
		}
		original = append(original, fd)
	}
	if err := unix.Sendmsg(pair[0], []byte("x"), unix.UnixRights(original...), nil, 0); err != nil {
		t.Fatal(err)
	}
	b, oob := make([]byte, 8), make([]byte, unix.CmsgSpace(4))
	_, on, flags, _, err := unix.Recvmsg(pair[1], b, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.MSG_CTRUNC == 0 {
		t.Fatalf("expected MSG_CTRUNC, flags=%x", flags)
	}
	_, recvErr := recvFdSets(oob[:on], flags)
	if recvErr == nil {
		t.Fatal("recvFdSets accepted truncated rights")
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:on])
	if err != nil {
		t.Fatal(err)
	}
	var delivered []int
	for _, cm := range cmsgs {
		fds, e := unix.ParseUnixRights(&cm)
		if e != nil {
			t.Fatal(e)
		}
		delivered = append(delivered, fds...)
	}
	if len(delivered) == 0 {
		t.Fatal("kernel delivered no rights, test cannot assert fd cleanup")
	}
	for _, fd := range delivered {
		if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e == nil {
			unix.Close(fd) // Clean up only if recvFdSets failed to close it.
			t.Errorf("recvFdSets leaked delivered fd %d after MSG_CTRUNC", fd)
		} else if e != unix.EBADF {
			t.Fatalf("fd %d status=%v", fd, e)
		}
	}
	t.Logf("MSG_CTRUNC delivered %d rights; recvFdSets error=%v", len(delivered), recvErr)
}

func TestMonitorRPCUnexpectedControlMessageClosesRights(t *testing.T) {
	for _, tc := range []struct {
		name            string
		unexpectedFirst bool
	}{
		{"unexpected_after_rights", false},
		{"unexpected_before_rights", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			defer unix.Close(pair[1])
			sent := devNullFd(t)
			if err := unix.Sendmsg(pair[0], []byte("x"), unix.UnixRights(sent), nil, 0); err != nil {
				t.Fatal(err)
			}
			b, oob := make([]byte, 8), make([]byte, unix.CmsgSpace(4))
			_, on, flags, _, err := unix.Recvmsg(pair[1], b, oob, unix.MSG_CMSG_CLOEXEC)
			if err != nil {
				t.Fatal(err)
			}
			cmsgs, err := unix.ParseSocketControlMessage(oob[:on])
			if err != nil || len(cmsgs) != 1 {
				t.Fatalf("received cmsgs=%v, err=%v", cmsgs, err)
			}
			delivered, err := unix.ParseUnixRights(&cmsgs[0])
			if err != nil || len(delivered) != 1 {
				t.Fatalf("delivered rights=%v, err=%v", delivered, err)
			}
			unexpected := unix.UnixCredentials(&unix.Ucred{})
			var control []byte
			if tc.unexpectedFirst {
				control = append(unexpected, oob[:on]...)
			} else {
				control = append(append([]byte(nil), oob[:on]...), unexpected...)
			}
			if _, err := recvFdSets(control, flags); err == nil {
				t.Fatal("unexpected control message accepted")
			}
			if _, err := unix.FcntlInt(uintptr(delivered[0]), unix.F_GETFD, 0); err != unix.EBADF {
				if err == nil {
					unix.Close(delivered[0])
				}
				t.Errorf("received right %d left open after unexpected control message: %v", delivered[0], err)
			}
		})
	}
}
