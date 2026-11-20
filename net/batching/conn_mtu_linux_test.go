// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package batching

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"tailscale.com/net/packet"
)

const (
	// mtuTestMTU is the MTU of lo in the tests' namespace. IPv6 leaves an
	// interface below 1280, and both address families are under test.
	mtuTestMTU = 1300
	// mtuTestMaxBatch keeps a batch within the default receive buffer, which an
	// unprivileged namespace can't raise.
	mtuTestMaxBatch = 16
	mtuTestEnv      = "TS_TEST_BATCHING_MTU_NAMESPACE"
)

// inMTUNamespace reports whether the test runs in a network namespace whose lo
// has MTU mtuTestMTU. Called outside one, it runs the test again in a new one
// and reports false; the caller then returns. The test is skipped where
// unprivileged user namespaces are forbidden.
func inMTUNamespace(t *testing.T) bool {
	t.Helper()
	if os.Getenv(mtuTestEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
		cmd.Env = append(os.Environ(), mtuTestEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		out, err := cmd.CombinedOutput()
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOSPC) {
			t.Skipf("can't create a user and network namespace: %v", err)
		}
		if err != nil {
			t.Fatalf("in namespace: %v\n%s", err, out)
		}
		if strings.Contains(string(out), "--- SKIP: "+t.Name()+" (") {
			t.Skipf("skipped in namespace:\n%s", out)
		}
		return false
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatal(err)
	}
	ifr.SetUint32(mtuTestMTU)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFMTU, ifr); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("can't configure lo: %v", err)
		}
		t.Fatal(err)
	}
	ifr.SetUint16(unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}
	return true
}

// mtuTestFamily is an address family with the largest UDP payload that fits in
// mtuTestMTU unfragmented.
type mtuTestFamily struct {
	network    string
	loopback   netip.Addr
	maxPayload int
}

var mtuTestFamilies = []mtuTestFamily{
	{"udp4", netip.MustParseAddr("127.0.0.1"), mtuTestMTU - 20 - 8},
	{"udp6", netip.MustParseAddr("::1"), mtuTestMTU - 40 - 8},
}

// recordingWriter passes writes on to the real socket, and counts the messages
// it was given holding more than one datagram.
type recordingWriter struct {
	xnetBatchReaderWriter
	coalesced int
}

func (w *recordingWriter) WriteBatch(msgs []ipv6.Message, flags int) (int, error) {
	for _, m := range msgs {
		if len(m.Buffers) > 1 {
			w.coalesced++
		}
	}
	return w.xnetBatchReaderWriter.WriteBatch(msgs, flags)
}

// mtuTestEnd is one sender and one receiver over lo.
type mtuTestEnd struct {
	conn     *linuxBatchingConn
	recorder *recordingWriter
	receiver *net.UDPConn
	dst      netip.AddrPort
}

func newMTUTestEnd(t *testing.T, fam mtuTestFamily, dontFragment bool) *mtuTestEnd {
	t.Helper()
	bind := &net.UDPAddr{IP: fam.loopback.AsSlice()}
	receiver, err := net.ListenUDP(fam.network, bind)
	if errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.EAFNOSUPPORT) {
		t.Skipf("no %s loopback: %v", fam.network, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { receiver.Close() })
	sender, err := net.ListenUDP(fam.network, bind)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sender.Close() })

	discover := unix.IP_PMTUDISC_DONT
	if dontFragment {
		discover = unix.IP_PMTUDISC_DO
	}
	level, opt := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER
	if fam.network == "udp6" {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
	}
	rc, err := sender.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sockErr error
	if err := rc.Control(func(fd uintptr) { sockErr = unix.SetsockoptInt(int(fd), level, opt, discover) }); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}

	conn, ok := TryUpgradeToConn(sender, fam.network, "", nil).(*linuxBatchingConn)
	if !ok {
		t.Skip("no batching connection on this kernel")
	}
	if !conn.txOffload.Load() {
		t.Skip("no UDP GSO on this kernel")
	}
	rec := &recordingWriter{xnetBatchReaderWriter: conn.xpc}
	conn.xpc = rec
	return &mtuTestEnd{
		conn:     conn,
		recorder: rec,
		receiver: receiver,
		dst:      receiver.LocalAddr().(*net.UDPAddr).AddrPort(),
	}
}

// drain returns the datagrams that reached the receiver before now. It sends a
// marker after them and reads up to it, so its result doesn't depend on timing.
func (e *mtuTestEnd) drain(t *testing.T) [][]byte {
	t.Helper()
	marker := []byte("end of batch")
	if _, err := e.conn.WriteToUDPAddrPort(marker, e.dst); err != nil {
		t.Fatal(err)
	}
	if err := e.receiver.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	buf := make([]byte, 1<<16)
	for {
		n, err := e.receiver.Read(buf)
		if err != nil {
			t.Fatalf("reading after %d datagrams: %v", len(got), err)
		}
		if bytes.Equal(buf[:n], marker) {
			return got
		}
		got = append(got, bytes.Clone(buf[:n]))
	}
}

// mtuTestDatagrams returns buffers for WriteBatchTo holding datagrams of the
// given UDP payload sizes, each with a distinct content, and what the receiver
// must see for each. Sizes count the Geneve header when vni is set.
func mtuTestDatagrams(sizes []int, geneve packet.GeneveHeader) (buffs, want [][]byte) {
	for i, size := range sizes {
		b := make([]byte, packet.GeneveFixedHeaderLength+size)
		payload := b[packet.GeneveFixedHeaderLength:]
		if geneve.VNI.IsSet() {
			payload = b[packet.GeneveFixedHeaderLength+packet.GeneveFixedHeaderLength:]
			geneve.Encode(b[packet.GeneveFixedHeaderLength:])
		}
		binary.BigEndian.PutUint32(payload, uint32(i+1))
		for j := 4; j < len(payload); j++ {
			payload[j] = byte(i)
		}
		wire := b[packet.GeneveFixedHeaderLength:]
		if geneve.VNI.IsSet() {
			// WriteBatchTo encodes the header at the start of the buffer it
			// is given when coalescing, and just before the offset otherwise.
			buffs = append(buffs, wire)
		} else {
			buffs = append(buffs, b)
		}
		want = append(want, bytes.Clone(wire))
	}
	return buffs, want
}

// mtuTestSizes draws a batch: runs of equal sizes, which coalesce, each under
// or over the path's limit, some ending in a smaller tail.
func mtuTestSizes(r *rand.Rand, maxPayload int) []int {
	const minSize = 40 // above the sentinel's 1 byte and a Geneve header
	var sizes []int
	for len(sizes) < 1+r.IntN(mtuTestMaxBatch) {
		var size int
		switch r.IntN(4) {
		case 0:
			size = maxPayload // the largest that fits
		case 1:
			size = maxPayload + 1 // the smallest that doesn't
		case 2:
			size = minSize + 1 + r.IntN(maxPayload-minSize)
		case 3:
			size = maxPayload + 1 + r.IntN(200)
		}
		for range 1 + r.IntN(6) {
			sizes = append(sizes, size)
		}
		if r.IntN(3) == 0 {
			sizes = append(sizes, minSize+r.IntN(size-minSize))
		}
	}
	return sizes[:min(len(sizes), mtuTestMaxBatch)]
}

func withoutSentinels(datagrams [][]byte) [][]byte {
	var kept [][]byte
	for _, d := range datagrams {
		if len(d) != len(neverGSOEqualTailSentinelPayload) {
			kept = append(kept, d)
		}
	}
	return kept
}

func sameDatagrams(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func describeDatagrams(datagrams [][]byte) string {
	sizes := make([]int, len(datagrams))
	for i, d := range datagrams {
		sizes[i] = len(d)
	}
	return fmt.Sprint(sizes)
}

// mtuTestVariants are the settings of a write that decide how it is coalesced
// and what it carries.
var mtuTestVariants = []struct {
	name     string
	geneve   bool
	sentinel bool
}{
	{name: "plain"},
	{name: "geneve", geneve: true},
	{name: "sentinel", sentinel: true},
}

// TestWriteBatchToOverMTU states what a batch does on a path whose MTU is below
// some of its datagrams, over real sockets and generated batches. Let U be the
// datagrams of a batch that fit the MTU, in order, and O those that don't.
//
//   - Don't-fragment off (magicsock's default): the receiver gets all of the
//     batch, in order and once each, the write returns nil, and offload stays on.
//     The kernel refuses a coalesced O and fragments the same datagram sent
//     singly, so losing it would lose what the socket can deliver.
//   - Don't-fragment on (peer path MTU discovery): the receiver gets exactly U,
//     in order, and the write returns EMSGSIZE if O is not empty and nil if it is.
//   - In both, offload stays on and a later batch of U is still coalesced: one
//     destination's path must not degrade the socket.
func TestWriteBatchToOverMTU(t *testing.T) {
	if !inMTUNamespace(t) {
		return
	}
	for _, fam := range mtuTestFamilies {
		for _, v := range mtuTestVariants {
			for _, dontFragment := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/dontFragment=%v", fam.network, v.name, dontFragment), func(t *testing.T) {
					testWriteBatchToOverMTU(t, fam, v.geneve, v.sentinel, dontFragment)
				})
			}
		}
	}
}

func testWriteBatchToOverMTU(t *testing.T, fam mtuTestFamily, withGeneve, sentinel, dontFragment bool) {
	e := newMTUTestEnd(t, fam, dontFragment)
	if sentinel {
		knob := new(atomic.Bool)
		knob.Store(true)
		e.conn.neverGSOEqualTail = knob
	}
	var geneve packet.GeneveHeader
	if withGeneve {
		geneve.VNI.Set(1)
		geneve.Protocol = packet.GeneveProtocolWireGuard
	}
	const iterations = 1000
	r := rand.New(rand.NewPCG(1, 0))
	for iter := range iterations {
		sizes := mtuTestSizes(r, fam.maxPayload)
		buffs, want := mtuTestDatagrams(sizes, geneve)
		fits := want[:0:0]
		for _, d := range want {
			if len(d) <= fam.maxPayload {
				fits = append(fits, d)
			}
		}
		expected, expectedErr := want, error(nil)
		if dontFragment {
			expected = fits
			if len(fits) != len(want) {
				expectedErr = unix.EMSGSIZE
			}
		}

		err := e.conn.WriteBatchTo(buffs, e.dst, geneve, packet.GeneveFixedHeaderLength)
		got := e.drain(t)
		if sentinel {
			got = withoutSentinels(got)
		}
		context := fmt.Sprintf("iteration %d sizes %v", iter, sizes)
		if !sameDatagrams(got, expected) {
			t.Fatalf("%s: receiver got sizes %s, want %s", context, describeDatagrams(got), describeDatagrams(expected))
		}
		if expectedErr == nil && err != nil {
			t.Fatalf("%s: write returned %v, want nil", context, err)
		}
		if expectedErr != nil && !errors.Is(err, expectedErr) {
			t.Fatalf("%s: write returned %v, want %v", context, err, expectedErr)
		}
		if !e.conn.txOffload.Load() {
			t.Fatalf("%s: offload turned off", context)
		}
	}

	// A batch that fits after all those refusals is still coalesced.
	sizes := make([]int, mtuTestMaxBatch)
	for i := range sizes {
		sizes[i] = fam.maxPayload
	}
	buffs, want := mtuTestDatagrams(sizes, geneve)
	e.recorder.coalesced = 0
	if err := e.conn.WriteBatchTo(buffs, e.dst, geneve, packet.GeneveFixedHeaderLength); err != nil {
		t.Fatal(err)
	}
	if e.recorder.coalesced != 1 {
		t.Errorf("batch that fits went out in %d coalesced messages, want 1", e.recorder.coalesced)
	}
	if got := withoutSentinels(e.drain(t)); !sameDatagrams(got, want) {
		t.Errorf("receiver got sizes %s, want %s", describeDatagrams(got), describeDatagrams(want))
	}
}

// TestWriteBatchToOverMTUDropsSentinel checks that a coalesced message refused
// for size leaves no sentinel on the wire: the tail exists only to change how a
// coalesced message is segmented.
func TestWriteBatchToOverMTUDropsSentinel(t *testing.T) {
	if !inMTUNamespace(t) {
		return
	}
	fam := mtuTestFamilies[0]
	e := newMTUTestEnd(t, fam, false)
	knob := new(atomic.Bool)
	knob.Store(true)
	e.conn.neverGSOEqualTail = knob
	sizes := make([]int, appendSentinelTailBatchSizeThreshold)
	for i := range sizes {
		sizes[i] = fam.maxPayload + 100
	}
	buffs, want := mtuTestDatagrams(sizes, packet.GeneveHeader{})
	if err := e.conn.WriteBatchTo(buffs, e.dst, packet.GeneveHeader{}, packet.GeneveFixedHeaderLength); err != nil {
		t.Fatal(err)
	}
	if got := e.drain(t); !sameDatagrams(got, want) {
		t.Errorf("receiver got sizes %s, want %s", describeDatagrams(got), describeDatagrams(want))
	}
}

// refusingWriter is a batch writer for what no kernel at hand does: it records
// each message's datagrams and refuses as told, in the error form of x/net's
// WriteBatch on Linux.
type refusingWriter struct {
	refuse func(ipv6.Message) error
	sent   [][]int // datagram sizes of each accepted message
	calls  int
}

func (w *refusingWriter) ReadBatch([]ipv6.Message, int) (int, error) { return 0, nil }

func (w *refusingWriter) WriteBatch(msgs []ipv6.Message, _ int) (int, error) {
	w.calls++
	for i, m := range msgs {
		if err := w.refuse(m); err != nil {
			if i > 0 {
				return i, nil // sendmmsg reports the refusal on the next call
			}
			return 0, &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendmmsg", err)}
		}
		sizes := make([]int, len(m.Buffers))
		for j, b := range m.Buffers {
			sizes[j] = len(b)
		}
		w.sent = append(w.sent, sizes)
	}
	return len(msgs), nil
}

func newRefusingConn(t *testing.T, w *refusingWriter) *linuxBatchingConn {
	t.Helper()
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	c, ok := TryUpgradeToConn(uc, "udp4", "", nil).(*linuxBatchingConn)
	if !ok {
		t.Skip("no batching connection on this kernel")
	}
	c.xpc = w
	c.txOffload.Store(true)
	return c
}

// TestWriteBatchToEINVAL covers kernels before Linux 6.14, whose oversized GSO
// send fails with EINVAL (https://github.com/torvalds/linux/commit/235174b).
func TestWriteBatchToEINVAL(t *testing.T) {
	addr := netip.MustParseAddrPort("127.0.0.1:1")

	t.Run("coalesced message goes out singly and the rest coalesced", func(t *testing.T) {
		w := &refusingWriter{refuse: func(m ipv6.Message) error {
			if len(m.Buffers) > 1 && len(m.Buffers[0]) == 100 {
				return unix.EINVAL
			}
			return nil
		}}
		c := newRefusingConn(t, w)
		// Sizes grow, so each run starts a message of its own.
		buffs := [][]byte{make([]byte, 100), make([]byte, 100), make([]byte, 200), make([]byte, 200)}
		if err := c.WriteBatchTo(buffs, addr, packet.GeneveHeader{}, 0); err != nil {
			t.Fatalf("got %v, want nil", err)
		}
		want := "[[100] [100] [200 200]]"
		if got := fmt.Sprint(w.sent); got != want {
			t.Errorf("sent %s, want %s", got, want)
		}
		if !c.txOffload.Load() {
			t.Error("offload turned off")
		}
	})

	t.Run("an uncoalesced EINVAL isn't about size and returns at once", func(t *testing.T) {
		w := &refusingWriter{refuse: func(ipv6.Message) error { return unix.EINVAL }}
		c := newRefusingConn(t, w)
		buffs := [][]byte{make([]byte, 100), make([]byte, 200)}
		if err := c.WriteBatchTo(buffs, addr, packet.GeneveHeader{}, 0); !errors.Is(err, unix.EINVAL) {
			t.Fatalf("got %v, want EINVAL", err)
		}
		if w.calls != 1 {
			t.Errorf("got %d writes, want 1", w.calls)
		}
	})

	t.Run("a single send's EINVAL after splitting is returned", func(t *testing.T) {
		w := &refusingWriter{refuse: func(ipv6.Message) error { return unix.EINVAL }}
		c := newRefusingConn(t, w)
		buffs := [][]byte{make([]byte, 100), make([]byte, 100)}
		if err := c.WriteBatchTo(buffs, addr, packet.GeneveHeader{}, 0); !errors.Is(err, unix.EINVAL) {
			t.Fatalf("got %v, want EINVAL", err)
		}
	})

	t.Run("a refusal survives a later message that splits and succeeds", func(t *testing.T) {
		w := &refusingWriter{refuse: func(m ipv6.Message) error {
			switch {
			case len(m.Buffers[0]) == 100:
				return unix.EMSGSIZE
			case len(m.Buffers) > 1:
				return unix.EINVAL
			}
			return nil
		}}
		c := newRefusingConn(t, w)
		buffs := [][]byte{make([]byte, 100), make([]byte, 200), make([]byte, 200)}
		if err := c.WriteBatchTo(buffs, addr, packet.GeneveHeader{}, 0); !errors.Is(err, unix.EMSGSIZE) {
			t.Fatalf("got %v, want EMSGSIZE", err)
		}
		if got, want := fmt.Sprint(w.sent), "[[200] [200]]"; got != want {
			t.Errorf("sent %s, want %s", got, want)
		}
	})

	t.Run("EIO still disables offload", func(t *testing.T) {
		w := &refusingWriter{refuse: func(m ipv6.Message) error {
			if len(m.Buffers) > 1 {
				return unix.EIO
			}
			return nil
		}}
		c := newRefusingConn(t, w)
		buffs := [][]byte{make([]byte, 100), make([]byte, 100)}
		c.WriteBatchTo(buffs, addr, packet.GeneveHeader{}, 0)
		if c.txOffload.Load() {
			t.Error("offload still on after EIO")
		}
		if got, want := fmt.Sprint(w.sent), "[[100] [100]]"; got != want {
			t.Errorf("sent %s, want %s", got, want)
		}
	})
}
