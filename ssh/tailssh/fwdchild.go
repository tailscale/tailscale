// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// The ssh-monitor spawns one-shot forwarding children as "tailscaled
// be-child ssh-fwd", one per dial/listen op.
//
// The child runs as the connection's bound identity, applied by the
// monitor as SysProcAttr.Credential. It performs one dial or bind,
// returns the result descriptor to the monitor over an inherited
// socketpair as one status line, and exits.
//
// The result protocol, from child to monitor over the socketpair, is one
// short newline-terminated line with at most one descriptor attached:
//
//	ok [payload]     success, with the agent socket path or the
//	                 bound TCP address as the payload
//	err <reason>      the op failed, with the reason preserved in
//	                 the reply
//
// After a successful send the child holds its descriptor copy and stays
// alive until the monitor closes the result channel, its receipt
// acknowledgment, and only then closes the descriptor and exits. On
// darwin the kernel's unix-socket GC reclaims a socket whose only
// reference is an in-flight SCM_RIGHTS message, so the sender's copy
// must cover the handoff until the receiver owns the descriptor; see
// beFwdChild and the monitor_rpc.go header.
//
// The monitor side of the protocol, fwdSpawnChild and fwdReadResult
// below, drives these children. The op handlers live in monitor.go.

package tailssh

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// fwdUmask is applied before every unix bind so the socket is created
// directly at 0600, matching OpenSSH StreamLocalBindMask semantics. The
// agent dir is created before the umask change, so it keeps 0700.
const fwdUmask = 0o177

// fwdResultAckWait bounds the child's wait for the monitor's receipt
// acknowledgment after sending its result descriptor. The monitor
// closes the result channel immediately after taking ownership, so the
// wait normally ends at once; the deadline only covers a monitor that
// died without closing.
const fwdResultAckWait = 30 * time.Second

// agentDirRoot is the only parent an agent-forwarding directory is
// created under. The child runs with no environment, so os.TempDir
// cannot redirect it, and it names the parent explicitly anyway;
// tailscaled's removal pins the same root. See removeAgentForwardingDir
// and checkAgentSocketPath.
const agentDirRoot = "/tmp"

// fwdMaxStatus caps the child's status line. Anything longer is a broken
// child, not a long error message.
const fwdMaxStatus = 4096

// fwdChildSpawnPrefix is the argv prefix after the executable path, the
// one the monitor uses to spawn a forwarding child. In tailscaled it is
// "be-child ssh-fwd". Tests override it through the TS_TEST_SSH_FWD_PREFIX
// environment variable, a test-only knob.
var fwdChildSpawnPrefix = []string{"be-child", "ssh-fwd"}

func init() {
	if v := os.Getenv("TS_TEST_SSH_FWD_PREFIX"); v != "" {
		fwdChildSpawnPrefix = strings.Fields(v)
	}
}

// fwdChildSpec is one validated forwarding op, as the monitor passes it to
// the child via argv.
type fwdChildSpec struct {
	op     string // "dial" or "listen"
	net    string // "unix" or "tcp" for listen. Dial is always unix
	addr   string // socket path for unix, address for tcp. Empty for agent
	unlink bool   // listen unix only: unlink-if-owned pre-step
	agent  bool   // listen only: create the agent-forwarding socket
}

// fwdCredGroups builds the supplementary group list for a forwarding
// child's Credential. The primary gid comes first, matching BSD/Darwin's
// egid-first getgroups convention. On darwin the list is truncated to 16
// entries because the kernel's setgroups returns EINVAL beyond that.
func fwdCredGroups(gid uint32, gids []uint32) []uint32 {
	groups := gids
	if len(groups) == 0 || groups[0] != gid {
		groups = append([]uint32{gid}, groups...)
	}
	if runtime.GOOS == "darwin" && len(groups) > 16 {
		groups = groups[:16]
	}
	return groups
}

// fwdSpawnChild spawns one forwarding child with the monitor's spawn-bound
// identity and returns the child plus the monitor's end of the result
// socketpair. The child inherits its socketpair end as fd 3, passed
// as --fd=3.
func fwdSpawnChild(m *monitor, spec fwdChildSpec) (*exec.Cmd, *net.UnixConn, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-fwd: os.Executable: %w", err)
	}

	argv := append(slices.Clone(fwdChildSpawnPrefix),
		"--op="+spec.op,
		"--fd=3",
	)
	if spec.agent {
		argv = append(argv, "--agent")
	} else {
		argv = append(argv, "--net="+spec.net, "--addr="+spec.addr)
		if spec.unlink {
			argv = append(argv, "--unlink=if-owned")
		}
	}
	// A non-root monitor running as the bound identity inherits it; any
	// other identity under a non-root monitor fails the fork with EPERM,
	// which surfaces as the op's error.
	var attr *syscall.SysProcAttr
	if os.Getuid() != 0 && uint64(m.args.uid) == uint64(os.Getuid()) && uint64(m.args.gid) == uint64(os.Getgid()) {
		attr = monChildAttr(false) // Setpgid, and Pdeathsig on linux. Identity is inherited.
	} else {
		attr = fwdChildAttr(m.args) // born unprivileged (Credential) in its own group
	}
	// Test seam: the declared-fds pin asks the child to dump its fd
	// table at exec. The path travels by argv, not by environment: a
	// child running as the connection's user gets no environment.
	if p := os.Getenv("TS_TEST_SSH_FWD_FDINFO"); p != "" {
		argv = append(argv, "--test-fdinfo="+p)
	}
	// Forwarding children run as the connection's user and take
	// everything from argv and the socket: no environment.
	return spawnRPCChild("ssh-fwd", exe, argv, nil, attr)
}

// fwdReadResult reads the one-shot child's status line and result
// descriptor from the socketpair, bounded by the deadline.
func fwdReadResult(c *net.UnixConn, deadline time.Time) (ok bool, payload string, fd int, err error) {
	if err := c.SetReadDeadline(deadline); err != nil {
		return false, "", -1, err
	}
	defer c.SetReadDeadline(time.Time{})
	oob := make([]byte, unix.CmsgSpace(4))
	var line []byte
	var fds []int
	defer func() {
		if err != nil {
			closeFds(fds)
		}
	}()
	for {
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			status, rest, _ := strings.Cut(string(line[:i]), " ")
			var got int = -1
			if len(fds) > 1 {
				return false, "", -1, fmt.Errorf("child sent %d descriptors, want at most 1", len(fds))
			}
			if len(fds) == 1 {
				got, fds = fds[0], nil
			}
			switch status {
			case "ok":
				if got < 0 {
					return false, "", -1, errors.New("child reported ok without a socket")
				}
				return true, rest, got, nil
			case "err":
				if got >= 0 {
					// Refuse defensively.
					unix.Close(got)
				}
				return false, rest, -1, nil
			default:
				return false, "", -1, fmt.Errorf("bad child status %q", string(line[:i]))
			}
		}
		if len(line) > fwdMaxStatus {
			return false, "", -1, fmt.Errorf("child status line exceeds %d bytes", fwdMaxStatus)
		}
		buf := make([]byte, 1024)
		n, oobn, flags, _, rerr := c.ReadMsgUnix(buf, oob)
		if rerr != nil {
			// Deadline expiry with os.ErrDeadlineExceeded, or EOF from the
			// child dying without a result. The caller distinguishes by context.
			return false, "", -1, fmt.Errorf("waiting for child result: %w", rerr)
		}
		sets, ferr := recvFdSets(oob[:oobn], flags)
		if ferr != nil {
			return false, "", -1, ferr
		}
		for _, set := range sets {
			fds = append(fds, set...)
		}
		line = append(line, buf[:n]...)
	}
}

// fwdArgs are the ssh-fwd child's arguments.
type fwdArgs struct {
	op     string
	net    string
	addr   string
	unlink bool
	agent  bool
	fd     int
}

// parseFwdArgs parses the arguments following "be-child ssh-fwd".
func parseFwdArgs(args []string) (fwdArgs, error) {
	var fa fwdArgs
	var unlink string

	flags := flag.NewFlagSet("ssh-fwd", flag.ContinueOnError)
	flags.StringVar(&fa.op, "op", "", "the op to perform: dial or listen")
	flags.StringVar(&fa.net, "net", "", "network: unix or tcp (dial is unix-only)")
	flags.StringVar(&fa.addr, "addr", "", "absolute socket path (unix) or address (tcp)")
	flags.StringVar(&unlink, "unlink", "", `listen unix only: pre-bind unlink policy, "if-owned"`)
	flags.BoolVar(&fa.agent, "agent", false, "listen only: create the agent-forwarding socket")
	flags.IntVar(&fa.fd, "fd", -1, "inherited AF_UNIX stream fd for the result")
	if err := flags.Parse(args); err != nil {
		return fa, err
	}
	if fa.fd < 3 {
		return fa, fmt.Errorf("invalid --fd %d: must be >= 3 (an ExtraFiles fd)", fa.fd)
	}
	switch fa.op {
	case "dial":
		if fa.agent {
			return fa, errors.New("dial does not take --agent")
		}
		if fa.net != "unix" {
			return fa, fmt.Errorf("dial is unix-only, got --net=%q", fa.net)
		}
		if fa.addr == "" || !filepath.IsAbs(fa.addr) {
			return fa, fmt.Errorf("dial: --addr must be an absolute unix socket path, got %q", fa.addr)
		}
	case "listen":
		switch {
		case fa.agent:
			if fa.net != "" || fa.addr != "" || unlink != "" {
				return fa, errors.New("listen --agent takes no --net/--addr/--unlink")
			}
		case fa.net == "unix":
			if fa.addr == "" || !filepath.IsAbs(fa.addr) {
				return fa, fmt.Errorf("listen unix: --addr must be an absolute socket path, got %q", fa.addr)
			}
			if unlink != "" && unlink != "if-owned" {
				return fa, fmt.Errorf("listen unix: --unlink must be if-owned, got %q", unlink)
			}
			fa.unlink = unlink == "if-owned"
		case fa.net == "tcp":
			if fa.addr == "" {
				return fa, errors.New("listen tcp: --addr is required")
			}
		default:
			return fa, fmt.Errorf("listen: --net must be unix or tcp, got %q", fa.net)
		}
	default:
		return fa, fmt.Errorf("unknown --op %q", fa.op)
	}
	return fa, nil
}

// beFwdChild is the entrypoint of the "tailscaled be-child ssh-fwd"
// subcommand. It is the one-shot, born-unprivileged dialer/listener
// child.
func beFwdChild(args []string) error {
	fa, err := parseFwdArgs(args)
	if err != nil {
		return err
	}
	// Mark the inherited result fd close-on-exec immediately at entry:
	// the spawn-path dup arrives without the flag.
	if _, err := unix.FcntlInt(uintptr(fa.fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return fmt.Errorf("ssh-fwd: fcntl(F_SETFD) on fd %d: %w", fa.fd, err)
	}
	c, err := wrapUnixConn(fa.fd)
	if err != nil {
		return fmt.Errorf("ssh-fwd: result fd: %w", err)
	}
	f, payload, err := fwdChildWork(fa)
	if err != nil {
		if f != nil {
			f.Close()
		}
		// The op's error is the result. Deliver it, then exit non-zero.
		// The monitor has the reason either way.
		if serr := fwdSendResult(c, nil, "err "+err.Error()); serr != nil {
			return fmt.Errorf("ssh-fwd: %v (and reporting it: %w)", err, serr)
		}
		return err
	}
	if err := fwdSendResult(c, f, "ok "+payload); err != nil {
		f.Close()
		return fmt.Errorf("ssh-fwd: sending result: %w", err)
	}
	// Hold the descriptor, and this process, until the monitor has
	// received the relayed socket. On darwin, a socket whose only
	// reference is an in-flight SCM_RIGHTS message is reclaimed by the
	// kernel's unix-socket garbage collector before the receiver's
	// recvmsg: the receive side is flushed and buffered data discarded,
	// while recvmsg still returns a usable-looking descriptor that then
	// reads EOF with its peer alive. The monitor closes its end of the
	// result channel right after taking ownership of the descriptor, so
	// the EOF here is the receipt acknowledgment. The deadline bounds
	// the wait against a monitor that died without closing; the
	// monitor's teardown SIGHUP also ends this process.
	c.SetReadDeadline(time.Now().Add(fwdResultAckWait))
	var ack [1]byte
	c.Read(ack[:]) // EOF on receipt, or deadline: exit either way
	f.Close()
	return nil
}

// fwdSendResult delivers the status line and the result descriptor.
func fwdSendResult(c *net.UnixConn, f *os.File, line string) error {
	var fds []int
	if f != nil {
		fds = []int{int(f.Fd())}
	}
	_, err := sendFds(c, []byte(line+"\n"), fds)
	return err
}

// fwdChildWork performs the op and returns the resulting socket as an
// *os.File plus a short status payload. The caller sends the file's
// descriptor to the monitor and then closes the file. The payload is the
// agent socket path, or the bound TCP address.
func fwdChildWork(fa fwdArgs) (*os.File, string, error) {
	switch {
	case fa.op == "dial":
		// Dial is unix-only.
		conn, err := (&net.Dialer{}).Dial("unix", fa.addr)
		if err != nil {
			return nil, "", err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, "", fmt.Errorf("ssh-fwd: dial returned %T", conn)
		}
		f, err := uc.File()
		uc.Close()
		if err != nil {
			return nil, "", err
		}
		return f, "", nil

	case fa.op == "listen" && fa.agent:
		// Agent-forwarding socket. See fwdUmask and ListenAgent. The
		// dir's cleanup is the caller's.
		dir, err := os.MkdirTemp(agentDirRoot, "auth-agent")
		if err != nil {
			return nil, "", err
		}
		sock := filepath.Join(dir, "listener.sock")
		unix.Umask(fwdUmask)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			return nil, "", err
		}
		f, err := ln.(*net.UnixListener).File()
		if err != nil {
			// Close unlinks the just-created socket, which is the desired
			// cleanup.
			ln.Close()
			return nil, "", err
		}
		// The original listener is left open: closing a
		// net.Listen("unix") listener unlinks the socket path. The dup in
		// f keeps it alive, and the original dies with this short-lived
		// process.
		return f, sock, nil

	case fa.op == "listen" && fa.net == "unix":
		// Umask first, so the socket is created directly at 0600. Then
		// the optional if-owned pre-unlink, then the bind. Parent
		// directories are not created; an inaccessible parent fails the
		// bind.
		unix.Umask(fwdUmask)
		if fa.unlink {
			fwdUnlinkIfOwned(fa.addr)
		}
		ln, err := net.Listen("unix", fa.addr)
		if err != nil {
			return nil, "", err
		}
		f, err := ln.(*net.UnixListener).File()
		if err != nil {
			ln.Close()
			return nil, "", err
		}
		// See the agent case. Closing the original would unlink the socket.
		return f, "", nil

	case fa.op == "listen" && fa.net == "tcp":
		// The bind runs with the bound user's credentials. Privileged
		// ports fail EACCES at the kernel.
		ln, err := net.Listen("tcp", fa.addr)
		if err != nil {
			return nil, "", err
		}
		addr := ln.Addr().String()
		f, err := ln.(*net.TCPListener).File()
		ln.Close() // tcp listeners have no path to unlink
		if err != nil {
			return nil, "", err
		}
		return f, addr, nil

	default:
		return nil, "", fmt.Errorf("ssh-fwd: unhandled op shape %+v", fa)
	}
}

// fwdUnlinkIfOwned implements the listen op's unlink-if-owned pre-step:
// an existing socket at addr is removed only when it is a socket owned
// by this process's uid. When the entry is not ours, the subsequent
// bind fails EADDRINUSE and the existing socket stays untouched.
func fwdUnlinkIfOwned(addr string) {
	fi, err := os.Lstat(addr)
	if err != nil {
		// ENOENT means nothing to do. Any other error is reported by the bind.
		return
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Getuid()) {
		return // not ours: advisory refusal
	}
	_ = os.Remove(addr)
}
