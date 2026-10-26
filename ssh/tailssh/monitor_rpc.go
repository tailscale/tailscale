// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// Monitor RPC wire codec.
//
// tailscaled and the per-connection ssh-monitor speak newline-delimited
// JSON over an AF_UNIX SOCK_STREAM socketpair, passing file descriptors
// as SCM_RIGHTS ancillary data bound to the first byte of the frame
// that owns them:
//
//	{"id":N,"op":"dial","net":"unix","addr":"/run/user/1000/x.sock"}   request
//	{"id":N,"op":"dial","ok":true}                                reply carrying data and lifetime fds
//	{"op":"exit","pid":123,"childID":1,"code":0}                                   unsolicited notification
//
// The caller assigns request IDs and replies echo them. The codec
// decodes and encodes frames and descriptors. ID bookkeeping, read
// deadlines and op dispatch belong to the RPC loops built on it.
//
// Descriptors ride a one-byte herald message, a NUL byte carrying the
// SCM_RIGHTS data, sent before the frame line they belong to. Frame
// lines are JSON and never contain a NUL byte, so the receiver locates
// each herald in the byte stream and attributes its descriptors to the
// line that follows it, regardless of how the kernel shapes reads. See
// recvFdSets, sendFds and rpcMaxLine for the descriptor and line-size
// rules.
//
// A dial or listen reply's descriptor is held open by its sender until
// the receiver acknowledges it with an fdack frame naming the reply's
// request ID. On Darwin, a socket whose only reference is an in-flight
// SCM_RIGHTS message can be reclaimed by the kernel's Unix-socket garbage
// collector. In that case, recvmsg still returns a valid descriptor, but
// the socket's receive buffer has been flushed and its data discarded.
// Keeping the sender's copy open until receipt is acknowledged prevents this.

package tailssh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Monitor RPC operations.
const (
	opDial   = "dial"   // request {net:"unix"|"tcp", addr}. reply {ok} + socket (and lifetime pipe writer for unix)
	opListen = "listen" // request {net:"unix"|"tcp", addr, unlink?, agent?}. reply {ok, path} + listener fd
	opExec   = "exec"   // request {argv, env, dir?, ctty?, envfd?, fds:0-4} + SCM_RIGHTS fds. reply {ok, pid, childID}
	opSignal = "signal" // request {pid, childID, sig}. reply {ok}
	opPing   = "ping"   // request {}. reply {ok}
	opExit   = "exit"   // unsolicited notification {pid, childID, code}. no request ID
	opFdAck  = "fdack"  // request {id of the reply whose descriptors were received}. no fds, no reply
)

const (
	// rpcMaxLine is the line cap. Larger frames are errors in both
	// directions. The largest legal frame is an exec with a sizeable
	// environment. The cap keeps a frame from wedging a socketpair.
	rpcMaxLine = 256 << 10

	// rpcMaxFds is the maximum number of SCM_RIGHTS descriptors any one
	// frame may carry. Exec passes child stdin, stdout and stderr plus
	// the env-fd pipe declared by rpcFrame.EnvFd.
	rpcMaxFds = 4

	// rpcFdHerald is the one-byte payload of the message that carries a
	// frame's descriptors. It is a NUL byte, which never appears inside
	// a JSON frame line, so the receiver can locate it in the byte
	// stream and attribute the descriptors to the line that follows it.
	rpcFdHerald = 0

	// rpcMaxHeraldRead is the number of herald cmsgs one read can
	// carry. A stream read can span several messages, each carrying at
	// most one SCM_RIGHTS cmsg, so the OOB buffer is sized for this
	// many. Exceeding it truncates the ancillary data and the read
	// fails.
	rpcMaxHeraldRead = 64

	// rpcWriteTimeout bounds each writeFrame call.
	rpcWriteTimeout = 30 * time.Second
)

// rpcFrame is one wire frame. It is a request, a reply to a request, or
// an unsolicited notification. Exactly one struct decodes all three
// shapes because they share the wire format. Only the fields listed for
// each op are meaningful. See the op constants above for the per-op
// field sets.
type rpcFrame struct {
	// ID is the request ID, assigned by the requester and echoed in the
	// reply. The zero ID, absent on the wire, marks an unsolicited
	// notification.
	ID int64 `json:"id,omitzero"`
	// Op is the operation, one of the op* constants.
	Op string `json:"op"`

	// dial and listen requests.
	Net    string `json:"net,omitempty"`  // dial and listen: "unix" or "tcp"
	Addr   string `json:"addr,omitempty"` // target address to dial or bind
	Unlink bool   `json:"unlink,omitzero"`
	Agent  bool   `json:"agent,omitzero"` // listen: create the agent-forwarding socket

	// exec request. Stdio descriptors arrive as SCM_RIGHTS with the
	// frame. Fds declares how many so the receiver can detect a
	// mismatch between announced and delivered descriptors.
	Argv []string `json:"argv,omitempty"`
	Env  []string `json:"env,omitempty"`
	Dir  string   `json:"dir,omitempty"`
	Ctty bool     `json:"ctty,omitzero"`
	Fds  int      `json:"fds,omitzero"`
	// EnvFd, when set on an exec request, declares a fourth descriptor
	// after stdin, stdout, and stderr: the --env-fd payload pipe for
	// the forwarded client env pairs.
	EnvFd bool `json:"envfd,omitzero"`

	// Incubator requests identity-flag normalization for an incubator argv.
	// The RPC caller is trusted to supply the executable and other arguments;
	// this flag is not a privilege boundary against tailscaled.
	Incubator bool `json:"incubator,omitzero"`

	// signal request, exit notification, and exec reply.
	Pid     int    `json:"pid,omitzero"`
	ChildID int64  `json:"childID,omitzero"` // exec request ID; required for signals
	Sig     string `json:"sig,omitempty"`
	Code    int    `json:"code,omitzero"` // exit notification only

	// Reply fields.
	OK   bool   `json:"ok,omitzero"`
	Err  string `json:"err,omitempty"`
	Path string `json:"path,omitempty"` // listen reply: the bound socket's path
}

func rpcPingReq(id int64) rpcFrame {
	return rpcFrame{ID: id, Op: opPing}
}

func rpcDialReq(id int64, network, addr string) rpcFrame {
	return rpcFrame{ID: id, Op: opDial, Net: network, Addr: addr}
}

func rpcListenReq(id int64, network, addr string, unlink, agent bool) rpcFrame {
	return rpcFrame{ID: id, Op: opListen, Net: network, Addr: addr, Unlink: unlink, Agent: agent}
}

func rpcExecReq(id int64, argv, env []string, dir string, ctty, envFd bool, nfds int) rpcFrame {
	return rpcFrame{ID: id, Op: opExec, Argv: argv, Env: env, Dir: dir, Ctty: ctty, EnvFd: envFd, Fds: nfds}
}

func rpcSignalReq(id int64, child monitorProcess, sig string) rpcFrame {
	return rpcFrame{ID: id, Op: opSignal, Pid: child.PID, ChildID: child.ID, Sig: sig}
}

// rpcExecReply returns the PID and generation of the spawned child.
// Signals and exit notifications carry the same pair.
func rpcExecReply(id int64, pid int) rpcFrame {
	return rpcFrame{ID: id, Op: opExec, OK: true, Pid: pid, ChildID: id}
}

func rpcOKReply(id int64, op string) rpcFrame {
	return rpcFrame{ID: id, Op: op, OK: true}
}

func rpcErrReply(id int64, op string, err error) rpcFrame {
	return rpcFrame{ID: id, Op: op, Err: fmt.Sprint(err)}
}

// rpcExitNotify is the unsolicited child-exit notification frame.
func rpcExitNotify(child monitorProcess, code int) rpcFrame {
	return rpcFrame{Op: opExit, Pid: child.PID, ChildID: child.ID, Code: code}
}

// rpcFdAckReq acknowledges receipt of the descriptors a reply with the
// given request ID carried. The sender keeps its copies open until this
// acknowledgment arrives; see the socket-lifetime requirement above.
func rpcFdAckReq(replyID int64) rpcFrame {
	return rpcFrame{ID: replyID, Op: opFdAck}
}

// maxFdsForOp reports the maximum number of SCM_RIGHTS descriptors a
// frame of op may carry in either direction. Exec carries child stdio.
// Unix dial replies carry a data socket and lifetime pipe writer; TCP dial
// and listen replies carry one socket.
func maxFdsForOp(op string) int {
	switch op {
	case opExec:
		return rpcMaxFds
	case opDial:
		return 2
	case opListen:
		return 1
	default:
		return 0
	}
}

// checkFds validates the number of descriptors received with a frame of
// this shape against the protocol's per-op limits.
func (f rpcFrame) checkFds(n int) error {
	if max := maxFdsForOp(f.Op); n > max {
		return fmt.Errorf("monitor rpc: op %q carried %d fds; protocol allows at most %d", f.Op, n, max)
	}
	if f.Op == opExec && f.Fds > 0 && f.Fds != n {
		return fmt.Errorf("monitor rpc: exec declared %d fds but %d arrived", f.Fds, n)
	}
	if f.Op == opExec && f.EnvFd && n != 4 {
		return fmt.Errorf("monitor rpc: envfd exec carried %d fds, want exactly 4 (stdio + env fd)", n)
	}
	return nil
}

// closeFds closes each descriptor, ignoring errors. It is used only on
// error and teardown paths where the set is being abandoned.
func closeFds(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}

// heraldFrames pairs the herald bytes in rbuf with the descriptor sets
// read alongside them and returns, in set order, the index of the frame
// each set belongs to: the frame counted from the lines already parsed
// in this connection's buffer. Every herald is validated before any
// result is returned, so a caller may queue sets only after the whole
// batch passes; see readFrame for the close-on-failure contract.
func heraldFrames(rbuf []byte, sets [][]int, queued func(k int) bool) ([]int, error) {
	var hers []int
	for i, b := range rbuf {
		if b == rpcFdHerald {
			hers = append(hers, i)
		}
	}
	if len(hers) != len(sets) {
		if len(sets) > 0 {
			return nil, errors.New("monitor rpc: fds without a herald byte")
		}
		return nil, errors.New("monitor rpc: herald byte without fds")
	}
	frames := make([]int, len(sets))
	assigned := make(map[int]bool)
	for i, h := range hers {
		if h > 0 && rbuf[h-1] != '\n' {
			return nil, errors.New("monitor rpc: herald byte inside a frame line")
		}
		k := bytes.Count(rbuf[:h], []byte{'\n'})
		if queued(k) || assigned[k] {
			return nil, errors.New("monitor rpc: two fd sets attributed to one frame")
		}
		assigned[k] = true
		frames[i] = k
	}
	return frames, nil
}

// recvFdSets parses the SCM_RIGHTS descriptors from the ancillary data of
// one ReadMsgUnix call, using the oob slice and flags that call
// returned, and marks every received descriptor close-on-exec before
// returning. The caller owns the returned descriptors.
func recvFdSets(oob []byte, flags int) ([][]int, error) {
	var sets [][]int
	var all []int
	fail := func(err error) ([][]int, error) {
		closeFds(all)
		return nil, err
	}
	var unexpected error
	// Parse one cmsg at a time so rights already parsed are still owned
	// (and can be closed) if a later control message is rejected.
	for len(oob) >= unix.CmsgLen(0) {
		hdr, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return fail(err)
		}
		oob = rest
		if hdr.Level != unix.SOL_SOCKET || hdr.Type != unix.SCM_RIGHTS {
			if unexpected == nil {
				unexpected = fmt.Errorf("monitor rpc: unexpected control message (level %d, type %d)", hdr.Level, hdr.Type)
			}
			continue // Later cmsgs may still contain received rights.
		}
		got, err := unix.ParseUnixRights(&unix.SocketControlMessage{Header: hdr, Data: data})
		if err != nil {
			return fail(err)
		}
		sets = append(sets, got)
		all = append(all, got...)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		// The kernel closed the descriptors that did not fit; close the
		// subset it installed in our process before rejecting the read.
		return fail(errors.New("monitor rpc: ancillary data truncated (more fds than the protocol allows)"))
	}
	if unexpected != nil {
		return fail(unexpected)
	}
	for _, got := range sets {
		for _, fd := range got {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
				return fail(err)
			}
		}
		if len(got) > rpcMaxFds {
			return fail(fmt.Errorf("monitor rpc: frame carried %d fds; protocol allows at most %d", len(got), rpcMaxFds))
		}
	}
	return sets, nil
}

// sendFds writes b to c, attaching any fds as SCM_RIGHTS ancillary data
// bound to the first byte of b. It refuses an empty payload with fds
// and does not close the descriptors it sends. On a short write the
// descriptors are already delivered; the caller resends only the
// remaining bytes as plain data.
func sendFds(c *net.UnixConn, b []byte, fds []int) (int, error) {
	if len(fds) > rpcMaxFds {
		return 0, fmt.Errorf("monitor rpc: refusing to send %d fds; protocol allows at most %d", len(fds), rpcMaxFds)
	}
	if len(b) == 0 {
		if len(fds) > 0 {
			return 0, errors.New("monitor rpc: refusing to send SCM_RIGHTS with an empty payload")
		}
		return 0, nil
	}
	if len(fds) == 0 {
		return c.Write(b)
	}
	n, _, err := c.WriteMsgUnix(b, unix.UnixRights(fds...), nil)
	return n, err
}

// fdSender abstracts "write bytes, maybe with descriptors" so the
// short-write handling below can be unit-tested with a mock.
type fdSender interface {
	sendFds(b []byte, fds []int) (int, error)
}

type unixSender struct{ c *net.UnixConn }

func (s unixSender) sendFds(b []byte, fds []int) (int, error) {
	return sendFds(s.c, b, fds)
}

// writeLine writes one complete frame line including the newline and
// resends the remainder after a short write. Descriptors are sent
// before the line as a one-byte herald message, a NUL byte carrying the
// SCM_RIGHTS data. The receiver attributes the descriptors to the line
// following the herald byte. Frame lines are JSON and never contain a
// NUL byte, so the herald is unambiguous in the stream.
func writeLine(w fdSender, line []byte, fds []int) error {
	if len(fds) > 0 {
		if _, err := w.sendFds([]byte{rpcFdHerald}, fds); err != nil {
			return err
		}
		fds = nil
	}
	n, err := w.sendFds(line, fds)
	for err == nil && n < len(line) {
		var k int
		k, err = w.sendFds(line[n:], nil)
		n += k
	}
	if err != nil {
		if n < len(line) {
			return fmt.Errorf("monitor rpc: short write %d/%d bytes: %w", n, len(line), err)
		}
		return err
	}
	return nil
}

// rpcConn is the frame codec for one end of the socketpair between
// tailscaled and the ssh-monitor. It is safe for use from a single
// goroutine per direction, the RPC loops.
type rpcConn struct {
	c *net.UnixConn

	// The write deadline is set before and cleared after every write.
	writeTimeout time.Duration

	// rbuf holds received bytes under assembly plus any complete lines
	// not yet returned. lineFds holds the descriptors received for each
	// line still buffered in rbuf, front-aligned with those lines.
	// Entries are nil for lines that carried no descriptors. Herald
	// bytes are stripped at attribution, so rbuf holds only frame-line
	// bytes.
	rbuf    []byte
	lineFds [][]int

	// Scratch buffers reused by every ReadMsgUnix call. oobBuf is sized
	// for several cmsgs, since one read can span several fd-carrying
	// messages. See rpcMaxHeraldRead.
	readBuf []byte
	oobBuf  []byte
}

// newRPCConn returns a codec over c. The caller keeps ownership of c and
// its read-side deadlines. Close c when done.
func newRPCConn(c *net.UnixConn) *rpcConn {
	return &rpcConn{
		c:            c,
		writeTimeout: rpcWriteTimeout,
		readBuf:      make([]byte, 16<<10),
		oobBuf:       make([]byte, rpcMaxHeraldRead*unix.CmsgSpace(rpcMaxFds*4)),
	}
}

// readFrame reads the next complete frame and the descriptors that
// arrived with it. The caller owns the returned descriptors and must
// close them, typically by passing them to wrapUnixConn. Read deadlines
// are the caller's concern; a read timeout returns os.ErrDeadlineExceeded
// and preserves any partially received line, and any other error closes
// the held descriptors and leaves the connection broken.
func (m *rpcConn) readFrame() (f rpcFrame, fds []int, err error) {
	// On any error other than a read timeout, close the descriptor sets
	// still queued in lineFds. Each error return closes its own fd set
	// before returning.
	defer func() {
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			closeFds(fds)
			for _, set := range m.lineFds {
				closeFds(set)
			}
			m.lineFds = nil
			m.rbuf = nil
		}
	}()

	for {
		// A complete line is buffered. Strip the newline, decode and return.
		if i := bytes.IndexByte(m.rbuf, '\n'); i >= 0 {
			var lfds []int
			if len(m.lineFds) > 0 {
				lfds, m.lineFds = m.lineFds[0], m.lineFds[1:]
			}
			line := m.rbuf[:i]
			m.rbuf = m.rbuf[i+1:]
			if len(line) > rpcMaxLine {
				closeFds(lfds)
				return f, nil, fmt.Errorf("monitor rpc: frame of %d bytes exceeds %d-byte line cap", len(line), rpcMaxLine)
			}
			if bytes.IndexByte(line, 0) >= 0 {
				closeFds(lfds)
				return f, nil, errors.New("monitor rpc: NUL byte in frame")
			}
			if err := json.Unmarshal(line, &f); err != nil {
				closeFds(lfds)
				return f, nil, fmt.Errorf("monitor rpc: bad frame: %w", err)
			}
			if err := f.checkFds(len(lfds)); err != nil {
				closeFds(lfds)
				return f, nil, err
			}
			return f, lfds, nil
		}

		// No newline yet. Refuse to buffer past the cap before reading more.
		if len(m.rbuf) > rpcMaxLine {
			return f, nil, fmt.Errorf("monitor rpc: frame exceeds %d-byte line cap", rpcMaxLine)
		}

		n, oobn, flags, _, rerr := m.c.ReadMsgUnix(m.readBuf, m.oobBuf)
		if rerr != nil {
			return f, nil, rerr
		}
		if n == 0 && oobn == 0 {
			return f, nil, io.EOF
		}
		sets, ferr := recvFdSets(m.oobBuf[:oobn], flags)
		if ferr != nil {
			return f, nil, ferr
		}
		m.rbuf = append(m.rbuf, m.readBuf[:n]...)

		// The appended bytes hold one herald byte per descriptor set.
		// The i-th herald byte in m.rbuf pairs with the i-th set, and
		// the set belongs to the line beginning after its herald. A
		// read can span several messages on some platforms, so a
		// herald can arrive in the same read as later lines' bytes. The
		// pairing is by byte position, so the attribution holds
		// regardless of how the kernel shapes reads.
		//
		// heraldFrames validates the whole batch before any set is
		// queued. A failure closes exactly this read's sets; sets
		// already queued stay owned by m.lineFds, and the deferred
		// cleanup closes them. Validating lazily, assigning as we go,
		// would let a late failure close a set twice: once here, and
		// again in that cleanup, with the second close landing on
		// whichever fd has since taken the number.
		failSets := func(err error) error {
			for _, set := range sets {
				closeFds(set)
			}
			return err
		}
		frames, aerr := heraldFrames(m.rbuf, sets, func(k int) bool {
			return k < len(m.lineFds) && m.lineFds[k] != nil
		})
		if aerr != nil {
			return f, nil, failSets(aerr)
		}
		for i, k := range frames {
			for len(m.lineFds) <= k {
				m.lineFds = append(m.lineFds, nil)
			}
			m.lineFds[k] = sets[i]
		}
		// The herald bytes are paired. Strip them so no NUL reaches
		// the line parser.
		m.rbuf = bytes.ReplaceAll(m.rbuf, []byte{rpcFdHerald}, nil)
	}
}

// writeFrame encodes f as one JSON line and writes it. See sendFds for
// descriptor attachment and ownership. Validation errors leave the channel
// usable. Transport errors close it: a partial write leaves the request outcome
// unknown, so the peer must tear down any children it started.
func (m *rpcConn) writeFrame(f rpcFrame, fds ...int) error {
	if len(fds) > maxFdsForOp(f.Op) {
		return fmt.Errorf("monitor rpc: op %q cannot carry %d fds", f.Op, len(fds))
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > rpcMaxLine {
		return fmt.Errorf("monitor rpc: frame of %d bytes exceeds %d-byte line cap", len(b), rpcMaxLine)
	}
	if err := m.c.SetWriteDeadline(time.Now().Add(m.writeTimeout)); err != nil {
		m.c.Close()
		return err
	}
	defer m.c.SetWriteDeadline(time.Time{})
	if err := writeLine(unixSender{m.c}, b, fds); err != nil {
		m.c.Close()
		return err
	}
	return nil
}

// wrapUnixConn wraps a raw file descriptor in a *net.UnixConn for read,
// write, CloseWrite and deadlines.
//
// The fd is consumed on return, whether the call succeeds or fails: it
// is closed exactly once here, and the returned conn owns an
// independent dup of the socket that the caller must Close.
func wrapUnixConn(fd int) (*net.UnixConn, error) {
	f := os.NewFile(uintptr(fd), "monitor-rpc-fd")
	c, err := net.FileConn(f)
	f.Close() // exactly-once close of fd. The dup in c is unaffected
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("monitor rpc: fd %d is a %T, not a unix stream socket", fd, c)
	}
	return uc, nil
}
