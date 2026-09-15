// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package portlist

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"go4.org/mem"
	"golang.org/x/sys/unix"
	"tailscale.com/util/dirwalk"
	"tailscale.com/util/mak"
)

func init() {
	newOSImpl = newLinuxImpl
	// Refresh service discovery once per second.
	pollInterval = 1 * time.Second
}

type linuxImpl struct {
	procNetFiles    []*os.File // seeked to start & reused between calls
	readlinkPathBuf []byte
	diagBuf         []byte          // reused for every inet_diag receive
	diagPorts       map[string]Port // keyed by "socket:[<decimal inode>]", matching /proc/<pid>/fd symlink targets

	known            map[string]*portMeta // inode string => metadata
	br               *bufio.Reader
	includeLocalhost bool
	diagFD           int // -1 means not yet opened or closed
	diagPID          uint32
	diagSeq          uint32
	namespace        netNamespace
	diagPermanent    bool
}

type portMeta struct {
	port          Port
	pid           int
	keep          bool
	needsProcName bool
}

func newLinuxImplBase(includeLocalhost bool) *linuxImpl {
	return &linuxImpl{
		br:               bufio.NewReader(eofReader),
		known:            map[string]*portMeta{},
		diagPorts:        map[string]Port{},
		includeLocalhost: includeLocalhost,
		diagFD:           -1,
	}
}

func newLinuxImpl(includeLocalhost bool) osImpl {
	return newLinuxImplWithDiag(includeLocalhost, true)
}

// newLinuxImplWithDiag is also used by the Linux benchmarks to construct a
// proc-only implementation without opening an unused diagnostic socket.
func newLinuxImplWithDiag(includeLocalhost, useDiag bool) *linuxImpl {
	// /proc/thread-self and netlink socket creation use the calling thread's
	// network namespace. Stay on one thread from the namespace check through
	// socket creation so both operations use the same namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	li := newLinuxImplBase(includeLocalhost)
	var procErr error
	li.namespace, procErr = netNamespaceID("/proc/self/ns/net")
	threadNS, threadErr := netNamespaceID("/proc/thread-self/ns/net")
	for _, name := range []string{
		"/proc/net/tcp",
		"/proc/net/tcp6",
		"/proc/net/udp",
		"/proc/net/udp6",
	} {
		f, err := os.Open(name)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Printf("portlist warning; ignoring: %v", err)
			continue
		}
		li.procNetFiles = append(li.procNetFiles, f)
	}
	// /proc/net is resolved through /proc/self, which denotes the process
	// leader. inet_diag is scoped to the calling thread's namespace. If those
	// views differ, use the complete proc fallback rather than mixing them.
	if !useDiag || runtime.GOOS == "android" || (procErr != nil || threadErr != nil || threadNS != li.namespace) {
		li.diagPermanent = true
	} else {
		li.initDiag()
	}
	return li
}

func (li *linuxImpl) initDiag() {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
	if err != nil {
		li.diagPermanent = isDiagCapabilityError(err)
		return
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		li.diagPermanent = isDiagCapabilityError(err)
		return
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		li.diagPermanent = isDiagCapabilityError(err)
		return
	}
	li.diagPID = sa.(*unix.SockaddrNetlink).Pid
	li.diagFD = fd
}

// netNamespace identifies the namespace pinned by the proc and netlink files.
type netNamespace struct{ dev, ino uint64 }

func netNamespaceID(path string) (netNamespace, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return netNamespace{}, err
	}
	return netNamespace{uint64(st.Dev), uint64(st.Ino)}, nil
}

func (li *linuxImpl) sameNetNamespace() bool {
	ns, err := netNamespaceID("/proc/thread-self/ns/net")
	return err == nil && ns == li.namespace
}

func isDiagCapabilityError(err error) bool {
	// A missing protocol diagnostic handler (for example, CONFIG_INET_UDP_DIAG
	// disabled) returns ENOENT after the kernel attempts to load its module.
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EAFNOSUPPORT) ||
		errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS)
}

func (li *linuxImpl) Close() error {
	li.closeDiag()
	for _, f := range li.procNetFiles {
		f.Close()
	}
	li.procNetFiles = nil
	return nil
}

const (
	v6Localhost = "00000000000000000000000001000000:"
	v6Any       = "00000000000000000000000000000000:0000"
	v4Localhost = "0100007F:"
	v4Any       = "00000000:0000"
)

var eofReader = bytes.NewReader(nil)

func (li *linuxImpl) AppendListeningPorts(base []Port) ([]Port, error) {
	if runtime.GOOS == "android" {
		// Android 10+ doesn't allow access to this anymore.
		// https://developer.android.com/about/versions/10/privacy/changes#proc-net-filesystem
		// Ignore it rather than have the system log about our violation.
		return nil, nil
	}
	br := li.br
	defer br.Reset(eofReader)

	// Start by marking all previous known ports as gone. If this mark
	// bit is still false later, we'll remove them.
	for _, pm := range li.known {
		pm.keep = false
	}

	var err error
	if !li.diagPermanent {
		err = li.appendDiagPorts()
	}
	if err != nil || li.diagPermanent {
		for _, f := range li.procNetFiles {
			name := f.Name()
			_, err := f.Seek(0, io.SeekStart)
			if err != nil {
				return nil, err
			}
			br.Reset(f)
			err = li.parseProcNetFile(br, filepath.Base(name))
			if err != nil {
				return nil, fmt.Errorf("parsing %q: %w", name, err)
			}
		}
	}

	// Delete ports that aren't open any longer.
	// And see if there are any process names we need to look for.
	var needProc map[string]*portMeta
	for inode, pm := range li.known {
		if !pm.keep {
			delete(li.known, inode)
			continue
		}
		if pm.needsProcName {
			mak.Set(&needProc, inode, pm)
		}
	}
	err = li.findProcessNames(needProc)
	if err != nil {
		return nil, err
	}

	ret := base
	for _, pm := range li.known {
		ret = append(ret, pm.port)
	}
	return sortAndDedup(ret), nil
}

// appendDiagPorts obtains the same listener set as parseProcNetFile, but asks
// the kernel to do the expensive table filtering. No state is changed until
// all four dumps have completed successfully; callers can safely fall back to
// proc without leaving a partial result in known.
func (li *linuxImpl) appendDiagPorts() error {
	if li.diagPermanent {
		return errors.New("inet_diag unavailable")
	}
	if li.diagFD < 0 {
		// A replacement socket must be created in the namespace where the
		// proc descriptors were opened. Keep the identity check and socket
		// construction on one OS thread; an existing socket remains pinned to
		// its creation namespace and needs no per-poll thread pinning.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if !li.sameNetNamespace() {
			return errors.New("inet_diag: network namespace differs from proc view")
		}
		li.initDiag()
		if li.diagFD < 0 {
			return errors.New("inet_diag unavailable")
		}
	}
	type query struct {
		family uint8
		proto  uint8
	}
	queries := []query{{unix.AF_INET, unix.IPPROTO_TCP}, {unix.AF_INET6, unix.IPPROTO_TCP}, {unix.AF_INET, unix.IPPROTO_UDP}, {unix.AF_INET6, unix.IPPROTO_UDP}}
	newPorts := li.diagPorts
	for inode := range newPorts {
		delete(newPorts, inode)
	}
	for _, q := range queries {
		err := li.diagDump(q.family, q.proto, newPorts)
		if err != nil {
			if isDiagCapabilityError(err) {
				li.diagPermanent = true
			}
			li.closeDiag()
			return err
		}
	}
	for inode, pm := range li.known {
		if p, ok := newPorts[inode]; ok {
			pm.keep = true
			if pm.port.Proto != p.Proto || pm.port.Port != p.Port {
				pm.port.Process, pm.port.Pid = "", 0
				pm.needsProcName = true
			}
			pm.port.Proto, pm.port.Port = p.Proto, p.Port
			continue
		}
		delete(li.known, inode)
	}
	for inode, p := range newPorts {
		if _, ok := li.known[inode]; !ok {
			li.known[inode] = &portMeta{port: p, keep: true, needsProcName: true}
		}
	}
	return nil
}

func (li *linuxImpl) closeDiag() {
	if li.diagFD >= 0 {
		_ = unix.Close(li.diagFD)
		li.diagFD = -1
		li.diagPID = 0
	}
}

// tcpListen is Linux's TCP_LISTEN state from include/net/tcp_states.h.
const tcpListen = 10

func diagRequest(family, proto uint8) []byte {
	// Pack these layouts from include/uapi/linux/inet_diag.h. Offsets below
	// are relative to the start of each struct; states uses native byte order.
	//
	// struct inet_diag_sockid {      // 48 bytes
	//     __be16 idiag_sport;        // 0
	//     __be16 idiag_dport;        // 2
	//     __be32 idiag_src[4];       // 4
	//     __be32 idiag_dst[4];       // 20
	//     __u32  idiag_if;           // 36
	//     __u32  idiag_cookie[2];    // 40
	// };
	// struct inet_diag_req_v2 {      // 56 bytes
	//     __u8 sdiag_family;         // 0
	//     __u8 sdiag_protocol;       // 1
	//     __u8 idiag_ext;            // 2
	//     __u8 pad;                  // 3
	//     __u32 idiag_states;        // 4
	//     struct inet_diag_sockid id; // 8
	// };
	b := make([]byte, 56)
	b[0], b[1] = family, proto
	// Query TCP_LISTEN only. On Linux, entries with a zero remote endpoint in
	// /proc/net/tcp are listeners; requesting other TCP states is substantially
	// slower and does not add ports. UDP uses all states and retains the exact
	// zero-remote filtering above.
	if proto == unix.IPPROTO_TCP {
		binary.NativeEndian.PutUint32(b[4:8], 1<<tcpListen)
	} else {
		binary.NativeEndian.PutUint32(b[4:8], ^uint32(0))
	}
	return b
}

const diagTimeout = 250 * time.Millisecond

// diagDump performs one complete multipart SOCK_DIAG_BY_FAMILY transaction.
// The pinned mdlayher/netlink Conn.Receive (also used by Execute) removes
// NLMSG_DONE without checking its NLM_F_DUMP_INTR flag. Reading datagrams
// directly lets us reject interruptions reported only on that final message.
func (li *linuxImpl) diagDump(family, proto uint8, ports map[string]Port) error {
	li.diagSeq++
	if li.diagSeq == 0 {
		li.diagSeq++
	}
	seq := li.diagSeq
	data := diagRequest(family, proto)
	msg := make([]byte, unix.NLMSG_HDRLEN+len(data))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(msg[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	copy(msg[unix.NLMSG_HDRLEN:], data)
	deadline := time.Now().Add(diagTimeout)
	if err := unix.Sendto(li.diagFD, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	if li.diagBuf == nil {
		li.diagBuf = make([]byte, 128<<10)
	}
	const (
		maxMessages = 1 << 20
		maxRecords  = 1 << 20
		maxBytes    = 128 << 20
	)
	messages := 0
	records := 0
	var totalBytes int
	for messages < maxMessages {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("inet_diag: receive deadline exceeded")
		}
		tv := unix.NsecToTimeval(remaining.Nanoseconds())
		if tv.Sec == 0 && tv.Usec == 0 {
			tv.Usec = 1
		}
		if err := unix.SetsockoptTimeval(li.diagFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return err
		}
		n, _, flags, from, err := unix.Recvmsg(li.diagFD, li.diagBuf, nil, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n > maxBytes-totalBytes {
			return errors.New("inet_diag: response byte limit exceeded")
		}
		totalBytes += n
		if flags&unix.MSG_TRUNC != 0 {
			return errors.New("inet_diag: truncated netlink datagram")
		}
		if sa, ok := from.(*unix.SockaddrNetlink); !ok || sa.Pid != 0 {
			return errors.New("inet_diag: unexpected netlink sender")
		}
		done, err := parseDiagDatagram(li.diagBuf[:n], seq, li.diagPID, family, func(body []byte) error {
			records++
			if records > maxRecords {
				return errors.New("inet_diag: response record limit exceeded")
			}
			// inet_diag_msg has the same address layout as the request. The
			// remote address begins at 24 and inode is the final uint32.
			remote := body[24:40]
			if !allZero(remote) || body[6] != 0 || body[7] != 0 {
				return nil
			}
			local := body[8:24]
			if !li.includeLocalhost && (isDiagV4Localhost(local, family) || isDiagV6Localhost(local, family)) {
				return nil
			}
			port := uint16(body[4])<<8 | uint16(body[5])
			inode := uint64(binary.NativeEndian.Uint32(body[68:72]))
			key := fmt.Sprintf("socket:[%d]", inode)
			ports[key] = Port{Proto: protocolName(proto), Port: port}
			return nil
		})
		if err != nil {
			return err
		}
		messages++
		if done {
			return nil
		}
	}
	return errors.New("inet_diag: response limit exceeded")
}

func protocolName(proto uint8) string {
	if proto == unix.IPPROTO_TCP {
		return "tcp"
	}
	return "udp"
}

// parseDiagDatagram validates one received netlink datagram for an
// inet_diag transaction and invokes onRecord for each diagnostic record.
// It is pure with respect to transport state: callback body slices refer to
// datagram and must be consumed or copied before returning. A false result
// means the multipart transaction has not received NLMSG_DONE yet; the caller
// must continue receiving and reject timeout or EOF without a true result.
func parseDiagDatagram(datagram []byte, seq, pid uint32, family uint8, onRecord func([]byte) error) (done bool, err error) {
	for off := 0; off < len(datagram); {
		if len(datagram)-off < unix.NLMSG_HDRLEN {
			return false, errors.New("inet_diag: truncated netlink header")
		}
		mlen := int(binary.NativeEndian.Uint32(datagram[off : off+4]))
		if mlen < unix.NLMSG_HDRLEN || mlen > len(datagram)-off {
			return false, errors.New("inet_diag: malformed netlink length")
		}
		aligned := (mlen + 3) &^ 3
		if aligned > len(datagram)-off {
			return false, errors.New("inet_diag: missing netlink alignment padding")
		}
		for _, p := range datagram[off+mlen : off+aligned] {
			if p != 0 {
				return false, errors.New("inet_diag: non-zero netlink padding")
			}
		}
		typ := binary.NativeEndian.Uint16(datagram[off+4 : off+6])
		flags := binary.NativeEndian.Uint16(datagram[off+6 : off+8])
		mseq := binary.NativeEndian.Uint32(datagram[off+8 : off+12])
		mpid := binary.NativeEndian.Uint32(datagram[off+12 : off+16])
		if mseq != seq || mpid != pid {
			return false, errors.New("inet_diag: mismatched netlink response")
		}
		if flags&unix.NLM_F_DUMP_INTR != 0 {
			return false, errors.New("inet_diag: dump interrupted")
		}
		body := datagram[off+unix.NLMSG_HDRLEN : off+mlen]
		switch typ {
		case unix.NLMSG_DONE:
			if mlen != unix.NLMSG_HDRLEN && mlen != unix.NLMSG_HDRLEN+4 {
				return false, errors.New("inet_diag: malformed netlink completion")
			}
			if len(body) == 4 && binary.NativeEndian.Uint32(body) != 0 {
				return false, diagNetlinkError(int32(binary.NativeEndian.Uint32(body)))
			}
			if off+aligned != len(datagram) {
				return false, errors.New("inet_diag: data after netlink completion")
			}
			return true, nil
		case unix.NLMSG_ERROR:
			if len(body) < 4 {
				return false, errors.New("inet_diag: truncated netlink error")
			}
			code := int32(binary.NativeEndian.Uint32(body[:4]))
			if code != 0 {
				return false, diagNetlinkError(code)
			}
			return false, errors.New("inet_diag: netlink ACK without completion")
		default:
			if typ != unix.SOCK_DIAG_BY_FAMILY || flags&unix.NLM_F_MULTI == 0 {
				return false, errors.New("inet_diag: unexpected netlink response")
			}
			if len(body) < 72 {
				return false, fmt.Errorf("inet_diag: short response (%d bytes)", len(body))
			}
			if body[0] != family {
				return false, errors.New("inet_diag: response family mismatch")
			}
			if onRecord != nil {
				if err := onRecord(body); err != nil {
					return false, err
				}
			}
		}
		off += aligned
	}
	return false, nil
}

func diagNetlinkError(code int32) error {
	if code > 0 {
		return fmt.Errorf("inet_diag: malformed netlink error code %d", code)
	}
	return fmt.Errorf("inet_diag: netlink error: %w", unix.Errno(-code))
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
func isDiagV4Localhost(b []byte, family uint8) bool {
	return family == unix.AF_INET && b[0] == 127 && b[1] == 0 && b[2] == 0 && b[3] == 1 && allZero(b[4:])
}
func isDiagV6Localhost(b []byte, family uint8) bool {
	return family == unix.AF_INET6 && allZero(b[:15]) && b[15] == 1
}

// fileBase is one of "tcp", "tcp6", "udp", "udp6".
func (li *linuxImpl) parseProcNetFile(r *bufio.Reader, fileBase string) error {
	proto := strings.TrimSuffix(fileBase, "6")

	// skip header row
	_, err := r.ReadSlice('\n')
	if err != nil {
		return err
	}

	fields := make([]mem.RO, 0, 20) // 17 current fields + some future slop

	wantRemote := mem.S(v4Any)
	if strings.HasSuffix(fileBase, "6") {
		wantRemote = mem.S(v6Any)
	}

	// remoteIndex is the index within a line to the remote address field.
	// -1 means not yet found.
	remoteIndex := -1

	// Add an upper bound on how many rows we'll attempt to read just
	// to make sure this doesn't consume too much of their CPU.
	// TODO(bradfitz,crawshaw): adaptively adjust polling interval as function
	// of open sockets.
	const maxRows = 1e6
	rows := 0

	// Scratch buffer for making inode strings.
	inoBuf := make([]byte, 0, 50)

	for {
		line, err := r.ReadSlice('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		rows++
		if rows >= maxRows {
			break
		}
		if len(line) == 0 {
			continue
		}

		// On the first row of output, find the index of the 3rd field (index 2),
		// the remote address. All the rows are aligned, at least until 4 billion open
		// TCP connections, per the Linux get_tcp4_sock's "%4d: " on an int i.
		if remoteIndex == -1 {
			remoteIndex = fieldIndex(line, 2)
			if remoteIndex == -1 {
				break
			}
		}

		if len(line) < remoteIndex || !mem.HasPrefix(mem.B(line).SliceFrom(remoteIndex), wantRemote) {
			// Fast path for not being a listener port.
			continue
		}

		// sl local rem ... inode
		fields = mem.AppendFields(fields[:0], mem.B(line))
		local := fields[1]
		rem := fields[2]
		inode := fields[9]

		if !rem.Equal(wantRemote) {
			// not a "listener" port
			continue
		}

		// If a port is bound to localhost, ignore it.
		// TODO: localhost is bigger than 1 IP, we need to ignore
		// more things.
		if !li.includeLocalhost && (mem.HasPrefix(local, mem.S(v4Localhost)) || mem.HasPrefix(local, mem.S(v6Localhost))) {
			continue
		}

		// Don't use strings.Split here, because it causes
		// allocations significant enough to show up in profiles.
		i := mem.IndexByte(local, ':')
		if i == -1 {
			return fmt.Errorf("%q unexpectedly didn't have a colon", local.StringCopy())
		}
		portv, err := mem.ParseUint(local.SliceFrom(i+1), 16, 16)
		if err != nil {
			return fmt.Errorf("%#v: %s", local.SliceFrom(9).StringCopy(), err)
		}
		inoBuf = append(inoBuf[:0], "socket:["...)
		inoBuf = mem.Append(inoBuf, inode)
		inoBuf = append(inoBuf, ']')

		if pm, ok := li.known[string(inoBuf)]; ok {
			pm.keep = true
			// Rest should be unchanged.
		} else {
			li.known[string(inoBuf)] = &portMeta{
				needsProcName: true,
				keep:          true,
				port: Port{
					Proto: proto,
					Port:  uint16(portv),
				},
			}
		}
	}

	return nil
}

// errDone is an internal sentinel error that we found everything we were looking for.
var errDone = errors.New("done")

// need is keyed by inode string.
func (li *linuxImpl) findProcessNames(need map[string]*portMeta) error {
	if len(need) == 0 {
		return nil
	}
	defer func() {
		// Anything we didn't find, give up on and don't try to look for it later.
		for _, pm := range need {
			pm.needsProcName = false
		}
	}()

	err := foreachPID(func(pid mem.RO) error {
		var procBuf [128]byte
		fdPath := mem.Append(procBuf[:0], mem.S("/proc/"))
		fdPath = mem.Append(fdPath, pid)
		fdPath = mem.Append(fdPath, mem.S("/fd"))

		// Android logs a bunch of audit violations in logcat
		// if we try to open things we don't have access
		// to. So on Android only, ask if we have permission
		// rather than just trying it to determine whether we
		// have permission.
		if runtime.GOOS == "android" && syscall.Access(string(fdPath), unix.R_OK) != nil {
			return nil
		}

		dirwalk.WalkShallow(mem.B(fdPath), func(fd mem.RO, de fs.DirEntry) error {
			targetBuf := make([]byte, 64) // plenty big for "socket:[165614651]"

			linkPath := li.readlinkPathBuf[:0]
			linkPath = fmt.Appendf(linkPath, "/proc/")
			linkPath = mem.Append(linkPath, pid)
			linkPath = append(linkPath, "/fd/"...)
			linkPath = mem.Append(linkPath, fd)
			linkPath = append(linkPath, 0) // terminating NUL
			li.readlinkPathBuf = linkPath  // to reuse its buffer next time
			n, ok := readlink(linkPath, targetBuf)
			if !ok {
				// Not a symlink or no permission.
				// Skip it.
				return nil
			}

			pe := need[string(targetBuf[:n])] // m[string([]byte)] avoids alloc
			if pe == nil {
				return nil
			}
			bs, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid.StringCopy()))
			if err != nil {
				// Usually shouldn't happen. One possibility is
				// the process has gone away, so let's skip it.
				return nil
			}

			argv := strings.Split(strings.TrimSuffix(string(bs), "\x00"), "\x00")
			if p, err := mem.ParseInt(pid, 10, 0); err == nil {
				pe.pid = int(p)
			}
			pe.port.Process = argvSubject(argv...)
			pid64, _ := mem.ParseInt(pid, 10, 0)
			pe.port.Pid = int(pid64)
			pe.needsProcName = false
			delete(need, string(targetBuf[:n]))
			if len(need) == 0 {
				return errDone
			}
			return nil
		})
		return nil
	})
	if err == errDone {
		return nil
	}
	return err
}

func foreachPID(fn func(pidStr mem.RO) error) error {
	err := dirwalk.WalkShallow(mem.S("/proc"), func(name mem.RO, de fs.DirEntry) error {
		if !isNumeric(name) {
			return nil
		}
		return fn(name)
	})
	if os.IsNotExist(err) {
		// This can happen if the directory we're
		// reading disappears during the run. No big
		// deal.
		return nil
	}
	return err
}

func isNumeric(s mem.RO) bool {
	for i, n := 0, s.Len(); i < n; i++ {
		b := s.At(i)
		if b < '0' || b > '9' {
			return false
		}
	}
	return s.Len() > 0
}

// fieldIndex returns the offset in line where the Nth field (0-based) begins, or -1
// if there aren't that many fields. Fields are separated by 1 or more spaces.
func fieldIndex(line []byte, n int) int {
	skip := 0
	for i := 0; i <= n; i++ {
		// Skip spaces.
		for skip < len(line) && line[skip] == ' ' {
			skip++
		}
		if skip == len(line) {
			return -1
		}
		if i == n {
			break
		}
		// Skip non-space.
		for skip < len(line) && line[skip] != ' ' {
			skip++
		}
	}
	return skip
}

// path must be null terminated.
func readlink(path, buf []byte) (n int, ok bool) {
	if len(buf) == 0 || len(path) < 2 || path[len(path)-1] != 0 {
		return 0, false
	}
	var dirfd int = unix.AT_FDCWD
	r0, _, e1 := unix.Syscall6(unix.SYS_READLINKAT,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(&path[0])),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0, 0)
	n = int(r0)
	if e1 != 0 {
		return 0, false
	}
	return n, true
}
