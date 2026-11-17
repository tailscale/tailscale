// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// rpcTestPair returns a client/server codec pair over a real AF_UNIX
// SOCK_STREAM socketpair, torn down with the test.
func rpcTestPair(t *testing.T) (client, server *rpcConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	var conns [2]*net.UnixConn
	for i, fd := range fds {
		c, err := wrapUnixConn(fd) // consumes the raw socketpair fd
		if err != nil {
			t.Fatalf("wrap socketpair end %d: %v", i, err)
		}
		conns[i] = c
	}
	t.Cleanup(func() {
		conns[0].Close()
		conns[1].Close()
	})
	return newRPCConn(conns[0]), newRPCConn(conns[1])
}

func devNullFd(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func assertCLOEXEC(t *testing.T, fd int) {
	t.Helper()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD(%d): %v", fd, err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Errorf("fd %d is not close-on-exec", fd)
	}
}

func TestMonitorRPCPingRoundTrip(t *testing.T) {
	client, server := rpcTestPair(t)

	if err := client.writeFrame(rpcPingReq(42)); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	f, fds, err := server.readFrame()
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if f.ID != 42 || f.Op != opPing || len(fds) != 0 {
		t.Fatalf("server got %+v, fds=%v", f, fds)
	}
	if err := server.writeFrame(rpcOKReply(42, opPing)); err != nil {
		t.Fatalf("write ok: %v", err)
	}
	if f, fds, err := client.readFrame(); err != nil || f.ID != 42 || f.Op != opPing || !f.OK || len(fds) != 0 {
		t.Fatalf("client got %+v, fds=%v, err=%v", f, fds, err)
	}
}

// fdPair returns a connected socketpair. One end is wrapped as the peer.
// The other is a raw int ready to be passed through the codec.
func fdPair(t *testing.T) (peer *net.UnixConn, passed int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer, err = wrapUnixConn(fds[0]) // consumes fds[0]
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	return peer, fds[1]
}

func TestMonitorRPCFdRoundTrip(t *testing.T) {
	client, server := rpcTestPair(t)
	peer, passed := fdPair(t)

	if err := client.writeFrame(rpcDialReq(7, "unix", "/run/user/1000/test.sock"), passed); err != nil {
		t.Fatal(err)
	}
	unix.Close(passed) // per sendFds, the sender may close after the write

	f, fds, err := server.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != 7 || f.Op != opDial || f.Net != "unix" || f.Addr != "/run/user/1000/test.sock" {
		t.Fatalf("frame = %+v", f)
	}
	if len(fds) != 1 {
		t.Fatalf("got %d fds, want 1", len(fds))
	}
	assertCLOEXEC(t, fds[0])

	// Liveness: bytes written by the peer come back through the passed fd.
	if _, err := peer.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	got, err := wrapUnixConn(fds[0]) // consumes fds[0]
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	got.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 32)
	n, err := got.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "still alive" {
		t.Fatalf("read %q", buf[:n])
	}

	if err := server.writeFrame(rpcOKReply(7, opDial)); err != nil {
		t.Fatal(err)
	}
	if f, fds, err := client.readFrame(); err != nil || !f.OK || f.ID != 7 || len(fds) != 0 {
		t.Fatalf("reply = %+v, fds=%v, err=%v", f, fds, err)
	}
}

func TestMonitorRPCMultiFd(t *testing.T) {
	client, server := rpcTestPair(t)

	// Three fds pass, matching the exec stdio shape.
	fds := []int{devNullFd(t), devNullFd(t), devNullFd(t)}
	req := rpcExecReq(9, []string{"/bin/sh"}, nil, "", false, false, 3)
	if err := client.writeFrame(req, fds...); err != nil {
		t.Fatal(err)
	}
	f, got, err := server.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Op != opExec || f.ID != 9 || f.Fds != 3 || len(got) != 3 {
		t.Fatalf("frame = %+v, fds = %v", f, got)
	}
	for _, fd := range got {
		assertCLOEXEC(t, fd)
		unix.Close(fd)
	}

	// Four fds pass only with the envfd declaration, stdio plus the
	// --env-fd pipe. The declaration and the delivered count must
	// match.
	envReq := rpcExecReq(10, []string{"/bin/sh"}, nil, "", false, true, 4)
	if err := client.writeFrame(envReq, devNullFd(t), devNullFd(t), devNullFd(t), devNullFd(t)); err != nil {
		t.Fatal(err)
	}
	if f, got, err := server.readFrame(); err != nil || !f.EnvFd || len(got) != 4 {
		t.Fatalf("envfd frame = %+v, fds = %v, err = %v", f, got, err)
	} else {
		for _, fd := range got {
			assertCLOEXEC(t, fd)
			unix.Close(fd)
		}
	}

	// Four fds without the envfd declaration (declared 3) are rejected.
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rights := unix.UnixRights(
		devNullFd(t), devNullFd(t), devNullFd(t), devNullFd(t),
	)
	if _, _, err := client.c.WriteMsgUnix(append(line, '\n'), rights, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.readFrame(); err == nil {
		t.Fatal("4 fds without the envfd declaration accepted")
	}

	// A fifth fd in one frame is rejected by the receiver.
	line, err = json.Marshal(envReq)
	if err != nil {
		t.Fatal(err)
	}
	rights = unix.UnixRights(
		devNullFd(t), devNullFd(t), devNullFd(t), devNullFd(t), devNullFd(t),
	)
	if _, _, err := client.c.WriteMsgUnix(append(line, '\n'), rights, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.readFrame(); err == nil {
		t.Fatal("5-fd frame accepted")
	}
}

// TestMonitorRPCHeraldBatchFailsClosed drives one read whose payload
// carries two herald bytes with one descriptor set. The batch fails as
// a whole and every delivered fd is closed exactly once by the failure
// path: attribution validates the whole batch before queueing any set,
// so a set already queued for a frame can never be closed twice by the
// batch failure and the deferred queue cleanup.
func TestMonitorRPCHeraldBatchFailsClosed(t *testing.T) {
	client, server := rpcTestPair(t)
	a, b := devNullFd(t), devNullFd(t)

	// One message: two herald bytes, one merged descriptor set, and a
	// second herald inside the partial line. Platforms that deliver
	// per-message sets report the herald-inside-a-frame failure; Linux
	// merges a message's fds into one set and reports the herald count
	// mismatch. Either way the batch fails closed.
	payload := append([]byte{rpcFdHerald}, 'a', 'b', 'c', rpcFdHerald, 'd', 'e', 'f', '\n')
	var before map[int]bool
	if runtime.GOOS == "linux" {
		before = openFdSet(t)
	}
	if _, _, err := client.c.WriteMsgUnix(payload, unix.UnixRights(a, b), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.readFrame(); err == nil {
		t.Fatal("readFrame accepted a batch with two herald bytes and one set")
	}
	// The sender keeps its own copies (sendFds never closes what it
	// sends), so the delivered descriptors are only observable from the
	// receiving side: every fd the failed read brought in must be gone.
	if before != nil {
		for fd := range openFdSet(t) {
			if !before[fd] {
				t.Fatalf("fd %d delivered by the failed batch is still open; the batch must fail closed", fd)
			}
		}
	}
}

// openFdSet returns the set of open descriptor numbers of this process.
func openFdSet(t *testing.T) map[int]bool {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("/proc/self/fd unavailable: %v", err)
	}
	out := make(map[int]bool, len(ents))
	for _, ent := range ents {
		n, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		out[n] = true
	}
	return out
}

// TestMonitorRPCHeraldFrames pins the herald attribution rules on
// synthetic reads, including the shape that fails after an earlier
// herald of the same read would already have been queued. heraldFrames
// returns frame indices only when the whole batch validates, which is
// what keeps queueing single-close.
func TestMonitorRPCHeraldFrames(t *testing.T) {
	H := []byte{rpcFdHerald}
	t.Run("pairs_heralds_with_the_frames_they_precede", func(t *testing.T) {
		rbuf := append(append([]byte{}, H...), []byte("frame0\n")...)
		rbuf = append(rbuf, H...)
		rbuf = append(rbuf, []byte("frame1\n")...)
		frames, err := heraldFrames(rbuf, [][]int{{1}, {2}}, func(int) bool { return false })
		if err != nil {
			t.Fatalf("heraldFrames: %v", err)
		}
		if !slices.Equal(frames, []int{0, 1}) {
			t.Fatalf("frames = %v, want [0 1]", frames)
		}
	})
	t.Run("herald_byte_inside_a_frame_line", func(t *testing.T) {
		rbuf := append([]byte("abc"), H...)
		rbuf = append(rbuf, []byte("def\n")...)
		_, err := heraldFrames(rbuf, [][]int{{1}}, func(int) bool { return false })
		if err == nil || !strings.Contains(err.Error(), "herald byte inside a frame line") {
			t.Fatalf("err = %v, want herald-inside-a-frame failure", err)
		}
	})
	t.Run("herald_for_an_already_queued_frame", func(t *testing.T) {
		rbuf := append([]byte{}, H...)
		rbuf = append(rbuf, []byte("frame0\n")...)
		_, err := heraldFrames(rbuf, [][]int{{1}}, func(k int) bool { return k == 0 })
		if err == nil || !strings.Contains(err.Error(), "two fd sets attributed to one frame") {
			t.Fatalf("err = %v, want duplicate-attribution failure", err)
		}
	})
	t.Run("fds_without_a_herald_byte", func(t *testing.T) {
		_, err := heraldFrames([]byte("frame0\n"), [][]int{{1}}, func(int) bool { return false })
		if err == nil || !strings.Contains(err.Error(), "fds without a herald byte") {
			t.Fatalf("err = %v, want missing-herald failure", err)
		}
	})
	t.Run("herald_byte_without_fds", func(t *testing.T) {
		_, err := heraldFrames(append([]byte{}, H...), nil, func(int) bool { return false })
		if err == nil || !strings.Contains(err.Error(), "herald byte without fds") {
			t.Fatalf("err = %v, want fdless-herald failure", err)
		}
	})
}

// Low-level pin of the framing rules. SCM_RIGHTS is delivered with the
// first byte of the message that carried it and never with later chunks
// of a split line.
func TestMonitorRPCFdsArriveWithHerald(t *testing.T) {
	client, server := rpcTestPair(t)
	fd := devNullFd(t)

	// The herald byte is the payload of the message that carries the
	// descriptors, ahead of the frame line it belongs to.
	if _, err := sendFds(client.c, []byte{rpcFdHerald}, []int{fd}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	oob := make([]byte, rpcMaxHeraldRead*unix.CmsgSpace(rpcMaxFds*4))
	n, oobn, flags, _, err := server.c.ReadMsgUnix(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 || oobn == 0 {
		t.Fatalf("herald read: n=%d oobn=%d", n, oobn)
	}
	if buf[0] != rpcFdHerald {
		t.Fatalf("first byte = %d; want the NUL herald", buf[0])
	}
	sets, err := recvFdSets(oob[:oobn], flags)
	if err != nil || len(sets) != 1 || len(sets[0]) != 1 {
		t.Fatalf("herald fds: %v, %v", sets, err)
	}
	unix.Close(sets[0][0])
}

// An undersized OOB buffer makes the kernel truncate the cmsg with
// MSG_CTRUNC and close the descriptors that did not fit. This test
// pins the truncation error path in recvFdSets.
func TestMonitorRPCUndersizedOOBTruncates(t *testing.T) {
	client, server := rpcTestPair(t)
	four := []int{devNullFd(t), devNullFd(t), devNullFd(t), devNullFd(t)}
	// sendFds itself refuses more than rpcMaxFds descriptors. Bypass it
	// to feed the receiver an oversized cmsg.
	var before map[int]bool
	if runtime.GOOS == "linux" {
		before = openFdSet(t)
	}
	if _, _, err := client.c.WriteMsgUnix([]byte("{\"op\":\"exec\"}\n"), unix.UnixRights(four...), nil); err != nil {
		t.Fatal(err)
	}
	// Buffer with room for only one descriptor.
	tooSmall := make([]byte, unix.CmsgSpace(1*4))
	n, oobn, flags, _, err := server.c.ReadMsgUnix(make([]byte, 64), tooSmall)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no payload received")
	}
	if _, err := recvFdSets(tooSmall[:oobn], flags); err == nil {
		t.Fatal("undersized OOB buffer accepted a truncated cmsg")
	}
	if before != nil {
		for fd := range openFdSet(t) {
			if !before[fd] {
				t.Errorf("fd %d delivered by truncated cmsg remains open", fd)
			}
		}
	}
}

// A legal >64 KiB frame with an fd is split by a shrunken send buffer,
// forcing the short-write resend path and multi-read reassembly. The
// herald byte carries the fd ahead of the line, so the fd must survive
// the line's own splitting.
func TestMonitorRPCSplitLineFD(t *testing.T) {
	client, server := rpcTestPair(t)
	peer, passed := fdPair(t)

	rc, err := client.c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 1024); err != nil {
			t.Error(err)
		}
	}); err != nil {
		t.Fatal(err)
	}

	big := strings.Repeat("x", 100<<10)
	req := rpcExecReq(11, []string{big}, nil, "", false, false, 1)
	done := make(chan error, 1)
	go func() {
		done <- client.writeFrame(req, passed)
	}()
	f, fds, err := server.readFrame()
	if err != nil {
		t.Fatalf("reassembled read: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("split write: %v", err)
	}
	unix.Close(passed)

	if f.ID != 11 || f.Op != opExec || f.Fds != 1 || len(f.Argv) != 1 || f.Argv[0] != big {
		t.Fatalf("frame id=%d op=%s argvLen=%d fds=%d", f.ID, f.Op, len(f.Argv), f.Fds)
	}
	if len(fds) != 1 {
		t.Fatalf("fd lost during reassembly: %v", fds)
	}
	assertCLOEXEC(t, fds[0])

	if _, err := peer.Write([]byte("via split")); err != nil {
		t.Fatal(err)
	}
	got, err := wrapUnixConn(fds[0])
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	got.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 32)
	if _, err := io.ReadFull(got, buf[:len("via split")]); err != nil {
		t.Fatal(err)
	}
	if string(buf[:len("via split")]) != "via split" {
		t.Fatalf("read %q", buf)
	}
}

func TestMonitorRPCLineCapAndNUL(t *testing.T) {
	client, server := rpcTestPair(t)

	// Sender side: oversized frames are refused.
	if err := client.writeFrame(rpcDialReq(1, "unix", strings.Repeat("x", rpcMaxLine))); err == nil {
		t.Fatal("oversized write accepted")
	}

	// Receiver side: an oversized line written raw is refused.
	over := append([]byte(`{"id":2,"op":"ping"}`), bytes.Repeat([]byte{0x78}, rpcMaxLine)...)
	over = append(over, '\n')
	go func() {
		_, _ = client.c.Write(over)
	}()
	if _, _, err := server.readFrame(); err == nil {
		t.Fatal("oversized read accepted")
	}

	// NUL bytes in a frame are refused.
	if _, err := client.c.Write([]byte("{\"op\":\"ping\"}\x00\n")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.readFrame(); err == nil {
		t.Fatal("NUL frame accepted")
	}
}

// mockSender records every sendFds call and can short-write the first one.
type mockSender struct {
	writes     []mockWrite
	shortFirst int
	shorted    bool
}

type mockWrite struct {
	data string
	nfds int
}

func (m *mockSender) sendFds(b []byte, fds []int) (int, error) {
	m.writes = append(m.writes, mockWrite{data: string(b), nfds: len(fds)})
	if m.shortFirst > 0 && m.shortFirst < len(b) && !m.shorted {
		m.shorted = true
		return m.shortFirst, nil
	}
	return len(b), nil
}

func TestWriteLineShortWrite(t *testing.T) {
	client, _ := rpcTestPair(t)
	if _, err := sendFds(client.c, nil, []int{devNullFd(t)}); err == nil {
		t.Fatal("sendFds with empty payload and fds accepted")
	}

	line := []byte("{\"id\":1,\"op\":\"dial\",\"ok\":true}\n")

	// The herald byte carries the fds ahead of the line, so a short
	// write of the line resends only the remainder as plain data.
	m := &mockSender{shortFirst: 5}
	if err := writeLine(m, line, []int{9}); err != nil {
		t.Fatal(err)
	}
	if len(m.writes) != 3 ||
		m.writes[0] != (mockWrite{data: string([]byte{rpcFdHerald}), nfds: 1}) ||
		m.writes[1] != (mockWrite{data: string(line), nfds: 0}) ||
		m.writes[2] != (mockWrite{data: string(line[5:]), nfds: 0}) {
		t.Fatalf("writes = %+v", m.writes)
	}

	// A complete first write sends nothing more.
	m = &mockSender{}
	if err := writeLine(m, line, nil); err != nil {
		t.Fatal(err)
	}
	if len(m.writes) != 1 || m.writes[0].nfds != 0 {
		t.Fatalf("writes = %+v", m.writes)
	}
}

// Fifty parallel request/reply pairs multiplexed over one conn pair, with
// every fifth reply carrying an fd, plus an unsolicited exit notification.
func TestMonitorRPCMultiplex(t *testing.T) {
	client, server := rpcTestPair(t)
	const n = 50

	type reply struct {
		f   rpcFrame
		fds []int
	}
	replies := make([]chan reply, n)
	for i := range replies {
		replies[i] = make(chan reply, 1)
	}
	exited := make(chan rpcFrame, 1)

	srcFd := devNullFd(t)
	go func() {
		for i := 0; i < n; i++ {
			f, fds, err := server.readFrame()
			if err != nil {
				t.Errorf("server read %d: %v", i, err)
				return
			}
			closeFds(fds)
			var err2 error
			if f.Op == opDial {
				err2 = server.writeFrame(rpcOKReply(f.ID, f.Op), srcFd)
			} else {
				err2 = server.writeFrame(rpcOKReply(f.ID, f.Op))
			}
			if err2 != nil {
				t.Errorf("server write %d: %v", i, err2)
				return
			}
		}
		if err := server.writeFrame(rpcExitNotify(monitorProcess{PID: 4321, ID: 1}, 0)); err != nil {
			t.Errorf("server exit write: %v", err)
		}
	}()

	go func() {
		for i := 0; i <= n; i++ {
			f, fds, err := client.readFrame()
			if err != nil {
				t.Errorf("client read %d: %v", i, err)
				return
			}
			if f.Op == opExit {
				exited <- f
			} else {
				replies[int(f.ID)-1] <- reply{f, fds}
			}
		}
	}()

	// Parallel requesters. Writes are serialized by one mutex because a
	// codec direction is single-goroutine by contract. writeFrame sets
	// and clears the conn's write deadline.
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mu.Lock()
			var err error
			if i%5 == 0 {
				err = client.writeFrame(rpcDialReq(int64(i+1), "unix", "/tmp/monitor-rpc-test.sock"))
			} else {
				err = client.writeFrame(rpcPingReq(int64(i + 1)))
			}
			mu.Unlock()
			if err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			r := <-replies[i]
			want, wantOp := 0, opPing
			if i%5 == 0 {
				want, wantOp = 1, opDial
			}
			if r.f.ID != int64(i+1) || r.f.Op != wantOp || !r.f.OK || len(r.fds) != want {
				t.Errorf("reply %d = %+v, fds=%d", i, r.f, len(r.fds))
			}
			for _, fd := range r.fds {
				assertCLOEXEC(t, fd)
			}
			closeFds(r.fds)
		}(i)
	}
	wg.Wait()

	select {
	case f := <-exited:
		if f.Op != opExit || f.ID != 0 || f.Pid != 4321 || f.Code != 0 {
			t.Fatalf("exit notification = %+v", f)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("exit notification not received")
	}
}

// TestSpawnRPCChildEnvIsExplicit pins the env contract of the shared
// spawn helper: a child spawned with no env must not inherit the
// spawner's environment, and an explicit env is used exactly as given.
// In production the user-identity forwarding children go through this
// helper, and the daemon's environment must not reach them.
func TestSpawnRPCChildEnvIsExplicit(t *testing.T) {
	// A variable only the spawner's environment carries. A child that
	// inherited it would be leaking the daemon's environment.
	t.Setenv("TS_SSH_RPC_ENV_PROBE", "leaked")
	t.Run("nil_env_excludes_the_spawners_environment", func(t *testing.T) {
		out := spawnRPCChildEnv(t, nil)
		if strings.Contains(out, "TS_SSH_RPC_ENV_PROBE=") {
			t.Fatalf("child inherited the spawner's environment: %q", out)
		}
	})
	t.Run("explicit_env_is_used_as_given", func(t *testing.T) {
		out := spawnRPCChildEnv(t, []string{"FOO=bar"})
		if !strings.Contains(out, "FOO=bar\n") {
			t.Fatalf("child environment %q is missing the explicit FOO=bar", out)
		}
	})
}

// spawnRPCChildEnv spawns a child through spawnRPCChild with the given
// env and returns what the child wrote to its fd 3, the RPC socket.
func spawnRPCChildEnv(t *testing.T, env []string) string {
	t.Helper()
	cmd, parentConn, err := spawnRPCChild("env-test", "/bin/sh",
		[]string{"-c", "printenv >&3; echo DONE >&3"}, env, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	if err != nil {
		t.Fatalf("child wait: %v", err)
	}
	parentConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := parentConn.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("read child env: %v", err)
			}
			break
		}
	}
	out := sb.String()
	if !strings.HasSuffix(out, "DONE\n") {
		t.Fatalf("child output %q does not end with the DONE marker", out)
	}
	return out
}

func TestWrapUnixConn(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := wrapUnixConn(fds[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The original raw int has been consumed and closed exactly once.
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err == nil {
		t.Fatal("original fd still open after wrapUnixConn")
	}

	// The wrapped conn is live and independent of the original fd's fate.
	other, err := wrapUnixConn(fds[1])
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hi" {
		t.Fatalf("read %q", buf)
	}

	// Non-socket fds are refused and consumed.
	devnull, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapUnixConn(devnull); err == nil {
		t.Fatal("non-socket fd accepted")
	}
}

// TestMonitorRPCReadTimeoutPreservesLine pins the read-timeout contract.
// A timeout with a partial line buffered returns os.ErrDeadlineExceeded
// and keeps the line and its descriptors. A retried readFrame after the
// rest of the frame arrives decodes it.
func TestMonitorRPCReadTimeoutPreservesLine(t *testing.T) {
	client, server := rpcTestPair(t)
	peer, passed := fdPair(t)
	defer peer.Close()

	req := rpcExecReq(21, []string{"sleep 1"}, nil, "", false, false, 1)
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	// Send the herald byte with the descriptor, then only part of the
	// line. The read times out mid-line with the state preserved.
	if _, err := sendFds(client.c, []byte{rpcFdHerald}, []int{passed}); err != nil {
		t.Fatal(err)
	}
	unix.Close(passed)
	if _, err := client.c.Write(line[:8]); err != nil {
		t.Fatal(err)
	}

	if err := server.c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.readFrame(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("mid-line readFrame err = %v; want ErrDeadlineExceeded", err)
	}
	if err := server.c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.c.Write(append(line[8:], '\n')); err != nil {
		t.Fatal(err)
	}
	f, fds, err := server.readFrame()
	if err != nil {
		t.Fatalf("retried readFrame: %v", err)
	}
	if f.ID != 21 || f.Op != opExec || f.Fds != 1 || len(fds) != 1 {
		t.Fatalf("frame id=%d op=%s fds=%d/%d", f.ID, f.Op, f.Fds, len(fds))
	}
	unix.Close(fds[0])
}

// TestMonitorRPCFrameShapes round-trips the request and reply
// constructors the later commits' wiring uses, pinning their wire
// fields.
func TestMonitorRPCFrameShapes(t *testing.T) {
	client, server := rpcTestPair(t)

	reqs := []rpcFrame{
		rpcListenReq(7, "unix", "/tmp/x.sock", true, false),
		rpcListenReq(8, "tcp", "127.0.0.1:0", false, true),
		rpcSignalReq(9, monitorProcess{PID: 4321, ID: 8}, "SIGKILL"),
	}
	go func() {
		for _, f := range reqs {
			if err := client.writeFrame(f); err != nil {
				t.Errorf("write %s: %v", f.Op, err)
				return
			}
		}
		if err := client.writeFrame(rpcErrReply(10, opDial, errors.New("refused"))); err != nil {
			t.Errorf("write err reply: %v", err)
		}
	}()
	want := append(reqs, rpcErrReply(10, opDial, errors.New("refused")))
	for _, want := range want {
		got, _, err := server.readFrame()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("frame = %+v; want %+v", got, want)
		}
	}
}
