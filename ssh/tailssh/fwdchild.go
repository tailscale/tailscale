// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// The ssh-monitor spawns forwarding children as "tailscaled
// be-child ssh-fwd", one per dial/listen op.
//
// The child runs as the connection's bound identity, applied by the
// monitor as SysProcAttr.Credential. A listener or TCP dial child returns
// its socket descriptor over an inherited socketpair as one status line,
// then exits. A Unix dial child instead returns one end of a private socketpair
// and a lifetime pipe writer, and stays alive to relay bytes to the dialed
// service as the bound user. Closing the lifetime pipe terminates the relay
// independently of data-socket half-closes.
//
// The result protocol, from child to monitor over the socketpair, is one
// short newline-terminated line with one descriptor for a listener or TCP
// dial, or two for a Unix dial (data socket and lifetime pipe writer):
//
//	ok [payload]     success, with the agent socket path or the
//	                 bound TCP address as the payload
//	err <reason>      the op failed, with the reason preserved in
//	                 the reply
//
// After a successful send the child holds its descriptor copy until the
// monitor closes the result channel, its receipt acknowledgment. Listener
// and TCP dial children then exit; Unix dial children relay through the private
// socketpair until the connection closes. See monitor_rpc.go for the Darwin
// socket-lifetime requirement that makes acknowledgment necessary.
//
// The monitor side of the protocol, fwdSpawnChild and fwdReadResult
// below, drives these children. The op handlers live in monitor.go.

package tailssh

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
// wait normally ends at once. The deadline bounds the wait if the monitor
// does not acknowledge receipt.
const fwdResultAckWait = 30 * time.Second

// fwdRelayCloseDrainTimeout bounds delivery of queued client payload after a
// full close. A service that stops reading must not retain the relay forever.
const fwdRelayCloseDrainTimeout = 5 * time.Second

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
	net    string // "unix" or "tcp"
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

// fwdReadResult reads the forwarding child's status line and result
// descriptors from the socketpair, bounded by the deadline. Unix dial replies
// carry a data socket and lifetime pipe; other replies carry one socket.
func fwdReadResult(c *net.UnixConn, deadline time.Time, wantFDs int) (ok bool, payload string, fds []int, err error) {
	if err := c.SetReadDeadline(deadline); err != nil {
		return false, "", nil, err
	}
	defer c.SetReadDeadline(time.Time{})
	oob := make([]byte, unix.CmsgSpace(2*4))
	var line []byte
	var received []int
	defer func() { closeFds(received) }()
	for {
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			status, rest, _ := strings.Cut(string(line[:i]), " ")
			switch status {
			case "ok":
				if len(received) != wantFDs {
					return false, "", nil, fmt.Errorf("child sent %d descriptors, want %d", len(received), wantFDs)
				}
				fds, received = received, nil
				return true, rest, fds, nil
			case "err":
				return false, rest, nil, nil
			default:
				return false, "", nil, fmt.Errorf("bad child status %q", string(line[:i]))
			}
		}
		if len(line) > fwdMaxStatus {
			return false, "", nil, fmt.Errorf("child status line exceeds %d bytes", fwdMaxStatus)
		}
		buf := make([]byte, 1024)
		n, oobn, flags, _, rerr := c.ReadMsgUnix(buf, oob)
		if rerr != nil {
			return false, "", nil, fmt.Errorf("waiting for child result: %w", rerr)
		}
		sets, ferr := recvFdSets(oob[:oobn], flags)
		if ferr != nil {
			return false, "", nil, ferr
		}
		for _, set := range sets {
			received = append(received, set...)
		}
		if len(received) > wantFDs {
			return false, "", nil, fmt.Errorf("child sent %d descriptors, want at most %d", len(received), wantFDs)
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
	flags.StringVar(&fa.net, "net", "", "network: unix or tcp")
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
		if err := validateFwdDial(fa.net, fa.addr); err != nil {
			return fa, err
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

// validateFwdDial validates the dial shape on both sides of the child spawn.
// TCP destinations may be hostnames or IP literals; resolution happens in the
// credentialed child, not in the privileged monitor.
func validateFwdDial(network, addr string) error {
	switch network {
	case "unix":
		if !filepath.IsAbs(addr) {
			return fmt.Errorf("dial: addr must be an absolute unix socket path, got %q", addr)
		}
	case "tcp":
		// Only validate the host:port framing and numeric port here.
		// net.DialTimeout in the credentialed child validates/resolves the
		// host. Keep its hostname, scoped-IPv6 and empty-host semantics;
		// do not resolve names in the privileged monitor.
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("dial tcp: %w", err)
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return fmt.Errorf("dial tcp: port %q must be between 1 and 65535", port)
		}
	default:
		return fmt.Errorf("dial: unsupported network %q", network)
	}
	return nil
}

// beFwdChild is the entrypoint of the "tailscaled be-child ssh-fwd"
// subcommand. It is the born-unprivileged dialer, Unix relay or listener child.
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
	defer c.Close()
	var f *os.File
	var payload string
	var relay *net.UnixConn
	var service *net.UnixConn
	var lifetimeRead, lifetimeWrite *os.File
	if fa.op == "dial" && fa.net == "unix" {
		f, relay, service, err = fwdDialRelay(fa.addr)
		if err == nil {
			defer relay.Close()
			defer service.Close()
			lifetimeRead, lifetimeWrite, err = os.Pipe()
			if err == nil {
				defer lifetimeRead.Close()
				defer lifetimeWrite.Close()
			}
		}
	} else {
		f, payload, err = fwdChildWork(fa)
	}
	if f != nil {
		defer f.Close()
	}
	if err != nil {
		// The op's error is the result. Deliver it, then exit non-zero.
		// The monitor has the reason either way.
		if serr := fwdSendResult(c, "err "+err.Error()); serr != nil {
			return fmt.Errorf("ssh-fwd: %v (and reporting it: %w)", err, serr)
		}
		return err
	}
	files := []*os.File{f}
	if lifetimeWrite != nil {
		files = append(files, lifetimeWrite)
	}
	if err := fwdSendResult(c, "ok "+payload, files...); err != nil {
		return fmt.Errorf("ssh-fwd: sending result: %w", err)
	}
	// Keep the descriptors open until the monitor acknowledges receipt by
	// closing the result channel. See the protocol description above.
	c.SetReadDeadline(time.Now().Add(fwdResultAckWait))
	var ack [1]byte
	_, ackErr := c.Read(ack[:])
	f.Close()
	if relay == nil {
		return nil // listener and TCP dial children exit after the handoff
	}
	lifetimeWrite.Close()
	c.Close()
	if !errors.Is(ackErr, io.EOF) {
		return fmt.Errorf("ssh-fwd: dial result not acknowledged: %v", ackErr)
	}
	// The service socket never leaves the credentialed child. The lifetime
	// pipe distinguishes full closure from a data-socket write-half-close:
	// neither data EOF nor a silent service may retain an abandoned relay.
	done := make(chan struct{})
	go func() {
		var buf [1]byte
		_, err := lifetimeRead.Read(buf[:]) // EOF when tailscaled closes or discards the reply
		if !errors.Is(err, os.ErrClosed) {
			// Stop waiting for service output, but let queued client payload
			// drain to the service before closing its write side. Immediate
			// cancellation would discard bytes already accepted by tailscaled.
			deadline := time.Now().Add(fwdRelayCloseDrainTimeout)
			relay.SetReadDeadline(deadline)
			service.SetWriteDeadline(deadline)
			service.CloseRead()
		}
		close(done)
	}()
	fwdBicopy(context.Background(), relay, service)
	lifetimeRead.Close() // stop the lifetime reader if both data directions ended
	<-done
	return nil
}

// fwdDialRelay dials the service as the bound user and returns only the
// daemon-facing end of a private socketpair. The child keeps the service
// socket and the other end for the lifetime of the forwarded connection.
func fwdDialRelay(addr string) (result *os.File, relay, service *net.UnixConn, err error) {
	service, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: addr, Net: "unix"})
	if err != nil {
		return nil, nil, nil, err
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		service.Close()
		return nil, nil, nil, err
	}
	unix.CloseOnExec(pair[0])
	unix.CloseOnExec(pair[1])
	result = os.NewFile(uintptr(pair[0]), "ssh-fwd-dial-result")
	relay, err = wrapUnixConn(pair[1]) // consumes pair[1]
	if err != nil {
		result.Close()
		service.Close()
		return nil, nil, nil, err
	}
	return result, relay, service, nil
}

// fwdSendResult delivers the status line and result descriptors.
func fwdSendResult(c *net.UnixConn, line string, files ...*os.File) error {
	var fds []int
	for _, f := range files {
		fds = append(fds, int(f.Fd()))
	}
	_, err := sendFds(c, []byte(line+"\n"), fds)
	return err
}

// fwdChildWork performs a TCP dial or listener op and returns its socket as an
// *os.File plus a short status payload. The caller sends the file's
// descriptor to the monitor and then closes the file. The payload is the
// agent socket path, or the bound TCP address.
func fwdChildWork(fa fwdArgs) (*os.File, string, error) {
	switch {
	case fa.op == "dial" && fa.net == "tcp":
		// Resolve and create/connect the socket with the bound user's
		// credentials. Passing the descriptor back does not change its
		// kernel socket owner, including for UID-based firewall rules.
		// Unlike Unix sockets, TCP has no per-message SCM_CREDENTIALS,
		// so a persistent user-credential relay is unnecessary.
		conn, err := net.DialTimeout("tcp", fa.addr, monFwdOpDeadline)
		if err != nil {
			return nil, "", err
		}
		defer conn.Close()
		f, err := conn.(*net.TCPConn).File()
		return f, "", err

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
