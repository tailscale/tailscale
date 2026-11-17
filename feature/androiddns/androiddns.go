// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// Package androiddns resolves DNS names on Android by speaking the
// dnsproxyd protocol to the system DNS resolver daemon over its unix
// socket, the same mechanism bionic libc's getaddrinfo uses.
//
// It exists for pure Go (non-cgo) binaries built for Android, such as
// CLI tools run under Termux. Android has no /etc/resolv.conf, so
// Go's built-in resolver has no nameservers and every lookup fails.
// Binaries built with cgo don't have this problem: Go's net package
// forces the cgo resolver on Android (golang/go#10714), which calls
// bionic's getaddrinfo, which consults the same daemon this package
// talks to directly. Queries through dnsproxyd get the system's
// per-network DNS configuration and Private DNS (DNS over TLS/HTTPS)
// handling for free.
//
// # Protocol compatibility
//
// The wire protocol is unofficial but effectively frozen, for a
// structural reason rather than a policy one. Its two halves live on
// opposite sides of Android's update split. The client side (bionic's
// getaddrinfo proxy and libnetd_client) ships in the OS system image
// and updates only with a full OS update, which for most devices
// means rarely and eventually never. The server side has been the
// DnsResolver mainline (APEX) module since Android 10, updated via
// Google Play across all supported OS releases at once. A single
// current module binary must therefore keep serving the frozen libc
// clients of every supported Android version simultaneously, so
// existing commands cannot change semantics, much like a kernel
// syscall ABI with the update roles inverted. On the wire this
// package is indistinguishable from an Android 10 era bionic client,
// which cannot be broken without breaking DNS on real devices.
//
// The daemon, its socket, and the getaddrinfo-level commands date to
// 2010 (Android Gingerbread); see system/netd commit 007e987fee and
// bionic commit a1dbf0b453. The raw-packet resnsend command used here
// was added in November 2018 (system/netd commit c0c818f448) to back
// the android_res_nsend NDK API introduced in Android 10 (API 29).
// For the current protocol definition, see ResNSendCommand in
// packages/modules/DnsResolver/DnsProxyListener.cpp and
// resNetworkSend in system/netd/client/NetdClient.cpp.
//
// Android 9 and older have no resnsend; their daemon answers it with
// a textual "500 Command not recognized". On the first such reply
// this package switches (for the rest of the process) to the older
// getaddrinfo command and synthesizes a DNS answer from the addrinfo
// list the daemon returns. That path can only answer A and AAAA
// questions; other query types fail with an error. It works on
// Android 6.0 (API 23) through 9: the command's arguments have been
// the same since Android 5.0 added netId, but 5.x sent the reply in
// an older layout that this package rejects with an error rather
// than parse. The fallback matters in practice: Amazon's Fire OS 7
// devices run Android 9 and were still getting new firmware on it
// in 2026 (tailscale/tailcat#126).
//
// Connecting to the socket requires membership in the AID_INET group,
// which app UIDs (including Termux) hold via the INTERNET permission,
// and SELinux policy grants app domains connect (but not stat) access
// to the socket, since every app's libc performs this exact connect.
// The plausible residual risk is not protocol change but a future
// policy tightening that distinguishes callers, so users of this
// package should treat it as best effort; the automatic installation
// into net.DefaultResolver (see auto.go) probes the socket with a
// connect first and leaves the resolver alone on failure.
//
// # Scope and gating
//
// The package also builds on GOOS=linux, not just GOOS=android,
// because static linux binaries run fine under Android kernels
// (Termux users and rooted devices commonly run our official static
// linux/arm64 builds) and have the same broken resolver there. Those
// builds detect Android at runtime before installing anything: no
// /etc/resolv.conf, the presence of /dev/__properties__ (the bionic
// property service's backing store, present since Android 5.0 and
// never on regular Linux), and a successful dnsproxyd connect.
//
// This is an optional feature, included by default in tailscaled
// builds on Linux and Android; build with the ts_omit_androiddns tag
// to omit it. It is not linked into tsnet by default; tsnet apps and
// other programs opt in with a blank import of this package.
package androiddns

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// socketPath is the dnsproxyd unix socket path. It's a variable only
// so tests can point it at a fake server.
var socketPath = "/dev/socket/dnsproxyd"

// maxCmdSize is FrameworkListener's CMD_BUF_SIZE in AOSP: the entire
// command, including the trailing NUL, must arrive in a single read
// of at most this many bytes.
const maxCmdSize = 1024

// maxAnswerSize is the maximum answer length we accept from the
// daemon. The daemon's own limit (MAXPACKET) is 8 KiB; we allow more
// in case it ever grows.
const maxAnswerSize = 64 << 10

// noResNSend records that the daemon rejected the resnsend command
// as unrecognized, which means this is Android 9 or older and every
// query must go through the getaddrinfo command instead. It's sticky
// for the life of the process: the daemon doesn't grow new commands
// without an OS update.
var noResNSend atomic.Bool

// errUnknownCommand is returned by reply.textError when the daemon
// answers with FrameworkListener's textual "500 Command not
// recognized" instead of the command's binary reply.
var errUnknownCommand = errors.New("androiddns: dnsproxyd does not recognize the command")

// Query sends the wire-format DNS query msg to the system resolver
// daemon and returns the wire-format answer. The answer's ID matches
// the query's ID. An unsuccessful rcode (such as NXDOMAIN) is not an
// error; it's returned in the answer's header for the caller to
// interpret.
//
// The query is resolved on the default network with the system's
// usual policy for the calling UID, as if the process had called
// bionic's getaddrinfo.
//
// On Android 10 and later the query goes to the daemon as is and the
// answer is whatever the upstream server returned. On Android 9 and
// older the daemon can only do getaddrinfo-style lookups, so only A
// and AAAA questions can be answered; see the package documentation.
func Query(ctx context.Context, msg []byte) ([]byte, error) {
	if !noResNSend.Load() {
		ans, err := queryResNSend(ctx, msg)
		if !errors.Is(err, errUnknownCommand) {
			return ans, err
		}
		noResNSend.Store(true)
	}
	return queryGetAddrInfo(ctx, msg)
}

// reply is a daemon connection positioned just past the first four
// bytes of its reply, which are in head. A binary reply's head is a
// big-endian int32; a text reply's is a three digit response code and
// a NUL or space.
type reply struct {
	net.Conn
	head [4]byte
	stop func() bool // cancels the context.AfterFunc watching the conn
}

func (r *reply) Close() error {
	r.stop()
	return r.Conn.Close()
}

// sendCommand connects to the daemon, sends cmd (adding the trailing
// NUL), and returns the reply with its first four bytes read. The
// caller must close the reply.
func sendCommand(ctx context.Context, cmd string) (*reply, error) {
	if len(cmd)+1 > maxCmdSize {
		return nil, fmt.Errorf("androiddns: %d byte command too large for dnsproxyd command buffer", len(cmd)+1)
	}

	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("androiddns: %w", err)
	}
	r := &reply{Conn: c}
	r.stop = context.AfterFunc(ctx, func() { c.Close() })
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}

	// FrameworkListener does a single read and requires the NUL to be
	// in it, so the command must go out in one write.
	if _, err := c.Write([]byte(cmd + "\x00")); err != nil {
		r.Close()
		return nil, fmt.Errorf("androiddns: %w", err)
	}
	if uc, ok := c.(*net.UnixConn); ok {
		uc.CloseWrite()
	}

	if _, err := io.ReadFull(c, r.head[:]); err != nil {
		r.Close()
		return nil, fmt.Errorf("androiddns: reading result: %w", err)
	}
	return r, nil
}

// textError returns an error for a reply that's FrameworkListener
// text (a three digit response code, a space, and a message) rather
// than the command's expected reply: errUnknownCommand if the daemon
// doesn't know the command, otherwise an error quoting the text.
func (r *reply) textError() error {
	rest, _ := io.ReadAll(io.LimitReader(r.Conn, 256))
	text := strings.TrimRight(string(r.head[:])+string(rest), "\x00")
	if strings.HasPrefix(text, "500 Command not recognized") {
		return errUnknownCommand
	}
	return fmt.Errorf("androiddns: dnsproxyd: %q", text)
}

// queryResNSend resolves msg with the resnsend command, which relays
// the raw DNS message and returns the raw answer.
func queryResNSend(ctx context.Context, msg []byte) ([]byte, error) {
	// The command is "resnsend <netId> <flags> <base64 query>".
	// netId 0 is NETID_UNSET, meaning the caller's default network.
	r, err := sendCommand(ctx, "resnsend 0 0 "+base64.StdEncoding.EncodeToString(msg))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// The reply is a big-endian int32 that's either a negative errno
	// or the rcode, followed on success by a big-endian int32 answer
	// length and the raw answer. Its first byte is 0x00 or 0xff; an
	// ASCII digit instead means the daemon replied with text, which
	// on Android 9 and older is "500 Command not recognized".
	if r.head[0] >= '0' && r.head[0] <= '9' {
		return nil, r.textError()
	}
	if res := int32(binary.BigEndian.Uint32(r.head[:])); res < 0 {
		return nil, fmt.Errorf("androiddns: dnsproxyd error %d (%v)", res, syscall.Errno(-res))
	}
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf("androiddns: reading answer length: %w", err)
	}
	ansLen := int32(binary.BigEndian.Uint32(buf[:]))
	if ansLen < 0 || ansLen > maxAnswerSize {
		return nil, fmt.Errorf("androiddns: bogus answer length %d", ansLen)
	}
	ans := make([]byte, ansLen)
	if _, err := io.ReadFull(r, ans); err != nil {
		return nil, fmt.Errorf("androiddns: reading answer: %w", err)
	}
	return ans, nil
}

// Response codes from FrameworkListener's ResponseCode.h that the
// getaddrinfo command replies with.
const (
	codeDnsProxyQueryResult     = "222"
	codeDnsProxyOperationFailed = "401"
)

// Values from bionic's <sys/socket.h> and <netdb.h> that appear in the
// getaddrinfo command and its reply. They are the same on every
// Android ABI.
const (
	afINET     = 2
	afINET6    = 10
	sockStream = 1

	eaiNODATA = 7 // no address associated with the name
	eaiNONAME = 8 // the name does not exist
)

// eaiNames names bionic's EAI_* getaddrinfo error codes, for error
// messages.
var eaiNames = map[int32]string{
	1:  "EAI_ADDRFAMILY",
	2:  "EAI_AGAIN",
	3:  "EAI_BADFLAGS",
	4:  "EAI_FAIL",
	5:  "EAI_FAMILY",
	6:  "EAI_MEMORY",
	7:  "EAI_NODATA",
	8:  "EAI_NONAME",
	9:  "EAI_SERVICE",
	10: "EAI_SOCKTYPE",
	11: "EAI_SYSTEM",
	12: "EAI_BADHINTS",
	13: "EAI_PROTOCOL",
	14: "EAI_OVERFLOW",
}

// queryGetAddrInfo resolves the single A or AAAA question in msg with
// the daemon's getaddrinfo command and synthesizes a DNS answer from
// the addresses it returns. That command is what bionic's getaddrinfo
// proxies through the daemon, so it works on the Android 9 and older
// devices whose daemon lacks resnsend.
func queryGetAddrInfo(ctx context.Context, msg []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return nil, fmt.Errorf("androiddns: parsing query: %w", err)
	}
	q, err := p.Question()
	if err != nil {
		return nil, fmt.Errorf("androiddns: parsing question: %w", err)
	}
	var family int
	switch q.Type {
	case dnsmessage.TypeA:
		family = afINET
	case dnsmessage.TypeAAAA:
		family = afINET6
	default:
		return nil, fmt.Errorf("androiddns: this Android version's dnsproxyd can only answer A and AAAA queries, not %v", q.Type)
	}
	// The daemon tokenizes the command on spaces and interprets
	// quotes and backslashes, and "^" is bionic's placeholder for a
	// NULL hostname. A name Go's resolver produces never contains any
	// of those, but Query is exported.
	name := strings.TrimSuffix(q.Name.String(), ".")
	if name == "" || strings.ContainsFunc(name, func(r rune) bool {
		return r <= ' ' || r >= 0x7f || r == '"' || r == '\\' || r == '^'
	}) {
		return nil, fmt.Errorf("androiddns: invalid name %q", name)
	}

	// The command is "getaddrinfo <name> <service> <ai_flags>
	// <ai_family> <ai_socktype> <ai_protocol> <netId>", with "^" for
	// a NULL service. SOCK_STREAM keeps the daemon from returning
	// each address three times (once per socket type), and netId 0
	// is NETID_UNSET, the caller's default network.
	cmd := fmt.Sprintf("getaddrinfo %s ^ 0 %d %d 0 0", name, family, sockStream)
	r, err := sendCommand(ctx, cmd)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	rcode := dnsmessage.RCodeSuccess
	var addrs []netip.Addr
	switch string(r.head[:3]) {
	case codeDnsProxyQueryResult:
		addrs, err = readAddrInfoList(r)
		if err != nil {
			return nil, err
		}
	case codeDnsProxyOperationFailed:
		// SocketClient::sendBinaryMsg: a big-endian length (4) and
		// then the getaddrinfo return value in native byte order,
		// which is little-endian on every Android ABI.
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, fmt.Errorf("androiddns: reading getaddrinfo error: %w", err)
		}
		if n := binary.BigEndian.Uint32(buf[:4]); n != 4 {
			return nil, fmt.Errorf("androiddns: bogus getaddrinfo error length %d", n)
		}
		switch eai := int32(binary.LittleEndian.Uint32(buf[4:])); eai {
		case eaiNONAME:
			rcode = dnsmessage.RCodeNameError
		case eaiNODATA:
			// Success with no answers.
		default:
			return nil, fmt.Errorf("androiddns: getaddrinfo failed: %s (%d)", eaiNames[eai], eai)
		}
	default:
		return nil, r.textError()
	}

	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	// The daemon doesn't report TTLs and Go's resolver doesn't use
	// them, so the records carry a TTL of 0 rather than an invented
	// number.
	rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class}
	for _, a := range addrs {
		switch {
		case a.Is4() && q.Type == dnsmessage.TypeA:
			err = b.AResource(rh, dnsmessage.AResource{A: a.As4()})
		case a.Is6() && q.Type == dnsmessage.TypeAAAA:
			err = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
		if err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// Upper bounds on the variable length fields of the getaddrinfo
// reply, generous relative to bionic's own limits (sockaddr_storage
// is 128 bytes; a hostname is at most 255).
const (
	maxSockaddrLen  = 128
	maxCanonNameLen = 1024
)

// readAddrInfoList reads the getaddrinfo command's success reply from
// r and returns the addresses in it, in order, without duplicates.
//
// The reply (GetAddrInfoHandler::run and sendaddrinfo in netd's
// DnsProxyListener.cpp) is, for each struct addrinfo in the result
// list, a big-endian 1, then the ai_flags, ai_family, ai_socktype,
// and ai_protocol fields as big-endian int32s, the ai_addrlen as a
// big-endian length followed by the raw sockaddr, and the canonical
// name's length (0 if none, otherwise including its NUL) followed by
// the name; the list ends with a big-endian 0. The fields are sent
// one at a time rather than as the raw struct because a 64-bit netd
// may be talking to a 32-bit process. Android 5.x sent the raw struct
// preceded by its size instead of the 1; that layout is detected and
// rejected.
func readAddrInfoList(r io.Reader) ([]netip.Addr, error) {
	readBE32 := func(what string) (uint32, error) {
		var be [4]byte
		if _, err := io.ReadFull(r, be[:]); err != nil {
			return 0, fmt.Errorf("androiddns: reading %s: %w", what, err)
		}
		return binary.BigEndian.Uint32(be[:]), nil
	}
	readLenAndData := func(what string, maxLen uint32) ([]byte, error) {
		n, err := readBE32(what + " length")
		if err != nil {
			return nil, err
		}
		if n > maxLen {
			return nil, fmt.Errorf("androiddns: bogus %s length %d", what, n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("androiddns: reading %s: %w", what, err)
		}
		return buf, nil
	}
	var addrs []netip.Addr
	for {
		more, err := readBE32("addrinfo marker")
		if err != nil {
			return nil, err
		}
		if more == 0 {
			return addrs, nil
		}
		if more != 1 {
			return nil, fmt.Errorf("androiddns: unsupported getaddrinfo reply layout (marker %d); Android 6.0 or later is required", more)
		}
		var fields [4]uint32 // ai_flags, ai_family, ai_socktype, ai_protocol
		for i := range fields {
			if fields[i], err = readBE32("addrinfo field"); err != nil {
				return nil, err
			}
		}
		family := fields[1]
		sa, err := readLenAndData("sockaddr", maxSockaddrLen)
		if err != nil {
			return nil, err
		}
		if _, err := readLenAndData("canonical name", maxCanonNameLen); err != nil {
			return nil, err
		}
		var a netip.Addr
		switch {
		case family == afINET && len(sa) >= 8: // sockaddr_in: family, port, addr
			a = netip.AddrFrom4([4]byte(sa[4:8]))
		case family == afINET6 && len(sa) >= 24: // sockaddr_in6: family, port, flowinfo, addr, scope_id
			a = netip.AddrFrom16([16]byte(sa[8:24]))
		default:
			continue
		}
		if !slices.Contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
}

// available reports whether the dnsproxyd socket exists and accepts
// connections. It's a connect test rather than a stat because SELinux
// grants app domains connect access to the socket without getattr.
func available() bool {
	c, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
