// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package batching

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"tailscale.com/hostinfo"
	"tailscale.com/net/neterror"
	"tailscale.com/net/packet"
	"tailscale.com/types/nettype"
	"tailscale.com/util/clientmetric"
)

// xnetBatchReaderWriter defines the batching i/o methods of
// golang.org/x/net/ipv4.PacketConn (and ipv6.PacketConn).
// TODO(jwhited): This should eventually be replaced with the standard library
// implementation of https://github.com/golang/go/issues/45886
type xnetBatchReaderWriter interface {
	xnetBatchReader
	xnetBatchWriter
}

type xnetBatchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type xnetBatchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

var (
	// [linuxBatchingConn] implements [Conn].
	_ Conn = (*linuxBatchingConn)(nil)
)

// linuxBatchingConn is a UDP socket that provides batched i/o. It implements
// [Conn].
type linuxBatchingConn struct {
	pc                 *net.UDPConn
	xpc                xnetBatchReaderWriter
	rxOffload          bool        // supports UDP GRO or similar
	txOffload          atomic.Bool // supports UDP GSO or similar
	sendBatchPool      sync.Pool
	rxqOverflowsMetric *clientmetric.Metric

	// readOpMu guards read operations that must perform accounting against
	// rxqOverflows in single-threaded fashion. There are no concurrent usages
	// of read operations at the time of writing (2026-03-09), but it would be
	// unidiomatic to push this responsibility onto callers.
	readOpMu     sync.Mutex
	rxqOverflows uint32 // kernel pumps a cumulative counter, which we track to push a clientmetric delta value
}

func (c *linuxBatchingConn) ReadFromUDPAddrPort(p []byte) (n int, addr netip.AddrPort, err error) {
	return 0, netip.AddrPort{}, errors.New("single packet reads are unsupported")
}

func (c *linuxBatchingConn) SetDeadline(t time.Time) error {
	return c.pc.SetDeadline(t)
}

func (c *linuxBatchingConn) SetReadDeadline(t time.Time) error {
	return c.pc.SetReadDeadline(t)
}

func (c *linuxBatchingConn) SetWriteDeadline(t time.Time) error {
	return c.pc.SetWriteDeadline(t)
}

const (
	// This was initially established for Linux, but may split out to
	// GOOS-specific values later. It originates as UDP_MAX_SEGMENTS in the
	// kernel's TX path, and UDP_GRO_CNT_MAX for RX.
	udpSegmentMaxDatagrams = 64
)

const (
	// Exceeding these values results in EMSGSIZE.
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	maxIPv6PayloadLen = 1<<16 - 1 - 8
)

// coalesceMessages iterates 'buffs', setting and coalescing them in 'msgs'
// where possible while maintaining datagram order.
//
// All msgs have their Addr field set to addr.
//
// All msgs[i].Buffers[0] are preceded by a Geneve header (geneve) if geneve.VNI.IsSet().
func (c *linuxBatchingConn) coalesceMessages(addr *net.UDPAddr, geneve packet.GeneveHeader, buffs [][]byte, msgs []ipv6.Message, offset int) int {
	var (
		base     = -1 // index of msg we are currently coalescing into
		gsoSize  int  // segmentation size of msgs[base]
		dgramCnt int  // number of dgrams coalesced into msgs[base]
		endBatch bool // tracking flag to start a new batch on next iteration of buffs
	)
	maxPayloadLen := maxIPv4PayloadLen
	if addr.IP.To4() == nil {
		maxPayloadLen = maxIPv6PayloadLen
	}
	vniIsSet := geneve.VNI.IsSet()
	for i, buff := range buffs {
		if vniIsSet {
			geneve.Encode(buff)
		} else {
			buff = buff[offset:]
		}
		if i > 0 {
			msgLen := len(buff)
			baseLenBefore := len(msgs[base].Buffers[0])
			freeBaseCap := cap(msgs[base].Buffers[0]) - baseLenBefore
			if msgLen+baseLenBefore <= maxPayloadLen &&
				msgLen <= gsoSize &&
				msgLen <= freeBaseCap &&
				dgramCnt < udpSegmentMaxDatagrams &&
				!endBatch {
				msgs[base].Buffers[0] = append(msgs[base].Buffers[0], make([]byte, msgLen)...)
				copy(msgs[base].Buffers[0][baseLenBefore:], buff)
				if i == len(buffs)-1 {
					setGSOSizeInControl(&msgs[base].OOB, uint16(gsoSize))
				}
				dgramCnt++
				if msgLen < gsoSize {
					// A smaller than gsoSize packet on the tail is legal, but
					// it must end the batch.
					endBatch = true
				}
				continue
			}
		}
		if dgramCnt > 1 {
			setGSOSizeInControl(&msgs[base].OOB, uint16(gsoSize))
		}
		// Reset prior to incrementing base since we are preparing to start a
		// new potential batch.
		endBatch = false
		base++
		gsoSize = len(buff)
		msgs[base].OOB = msgs[base].OOB[:0]
		msgs[base].Buffers[0] = buff
		msgs[base].Addr = addr
		dgramCnt = 1
	}
	return base + 1
}

type sendBatch struct {
	msgs []ipv6.Message
	ua   *net.UDPAddr
}

func (c *linuxBatchingConn) getSendBatch() *sendBatch {
	batch := c.sendBatchPool.Get().(*sendBatch)
	return batch
}

func (c *linuxBatchingConn) putSendBatch(batch *sendBatch) {
	for i := range batch.msgs {
		batch.msgs[i] = ipv6.Message{Buffers: batch.msgs[i].Buffers, OOB: batch.msgs[i].OOB}
	}
	c.sendBatchPool.Put(batch)
}

func (c *linuxBatchingConn) WriteBatchTo(buffs [][]byte, addr netip.AddrPort, geneve packet.GeneveHeader, offset int) error {
	batch := c.getSendBatch()
	defer c.putSendBatch(batch)
	if addr.Addr().Is6() {
		as16 := addr.Addr().As16()
		copy(batch.ua.IP, as16[:])
		batch.ua.IP = batch.ua.IP[:16]
	} else {
		as4 := addr.Addr().As4()
		copy(batch.ua.IP, as4[:])
		batch.ua.IP = batch.ua.IP[:4]
	}
	batch.ua.Port = int(addr.Port())
	var (
		n       int
		retried bool
	)
retry:
	if c.txOffload.Load() {
		n = c.coalesceMessages(batch.ua, geneve, buffs, batch.msgs, offset)
	} else {
		vniIsSet := geneve.VNI.IsSet()
		if vniIsSet {
			offset -= packet.GeneveFixedHeaderLength
		}
		for i := range buffs {
			if vniIsSet {
				geneve.Encode(buffs[i])
			}
			batch.msgs[i].Buffers[0] = buffs[i][offset:]
			batch.msgs[i].Addr = batch.ua
			batch.msgs[i].OOB = batch.msgs[i].OOB[:0]
		}
		n = len(buffs)
	}

	err := c.writeBatch(batch.msgs[:n])
	if err != nil && c.txOffload.Load() && neterror.ShouldDisableUDPGSO(err) {
		c.txOffload.Store(false)
		retried = true
		goto retry
	}
	if retried {
		return neterror.ErrUDPGSODisabled{OnLaddr: c.pc.LocalAddr().String(), RetryErr: err}
	}
	return err
}

func (c *linuxBatchingConn) SyscallConn() (syscall.RawConn, error) {
	return c.pc.SyscallConn()
}

func (c *linuxBatchingConn) writeBatch(msgs []ipv6.Message) error {
	var head int
	for {
		n, err := c.xpc.WriteBatch(msgs[head:], 0)
		if err != nil || n == len(msgs[head:]) {
			// Returning the number of packets written would require
			// unraveling individual msg len and gso size during a coalesced
			// write. The top of the call stack disregards partial success,
			// so keep this simple for now.
			return err
		}
		head += n
	}
}

// splitCoalescedMessages splits coalesced messages from the tail of dst
// beginning at index 'firstMsgAt' into the head of the same slice. It reports
// the number of elements to evaluate in msgs for nonzero len (msgs[i].N). An
// error is returned if a socket control message cannot be parsed or a split
// operation would overflow msgs.
func (c *linuxBatchingConn) splitCoalescedMessages(msgs []ipv6.Message, firstMsgAt int) (n int, err error) {
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return n, err
		}
		var (
			gsoSize    int
			start      int
			end        = msg.N
			numToSplit = 1
		)
		gsoSize, err = getGSOSizeFromControl(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errors.New("splitting coalesced packet resulted in overflow")
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			if end > msg.N {
				end = msg.N
			}
			n++
		}
		if i != n-1 {
			// It is legal for bytes to move within msg.Buffers[0] as a result
			// of splitting, so we only zero the source msg len when it is not
			// the destination of the last split operation above.
			msg.N = 0
		}
	}
	return n, nil
}

// getDataFromControl returns the data portion of the first control msg with
// matching cmsgLevel, matching cmsgType, and min data len of minDataLen, in
// control. If no matching cmsg is found or the len(control) < unix.SizeofCmsghdr,
// this function returns nil data. A non-nil error will be returned if
// len(control) > unix.SizeofCmsghdr but its contents cannot be parsed as a
// socket control message.
func getDataFromControl(control []byte, cmsgLevel, cmsgType int32, minDataLen int) ([]byte, error) {
	var (
		hdr  unix.Cmsghdr
		data []byte
		rem  = control
		err  error
	)

	for len(rem) > unix.SizeofCmsghdr {
		hdr, data, rem, err = unix.ParseOneSocketControlMessage(rem)
		if err != nil {
			return nil, fmt.Errorf("error parsing socket control message: %w", err)
		}
		if hdr.Level == cmsgLevel && hdr.Type == cmsgType && len(data) >= minDataLen {
			return data, nil
		}
	}
	return nil, nil
}

// getRXQOverflowsFromControl returns the rxq overflows cumulative counter found
// in control. If no rxq counter is found or the len(control) < unix.SizeofCmsghdr,
// this function returns 0. A non-nil error will be returned if control is
// malformed.
func getRXQOverflowsFromControl(control []byte) (uint32, error) {
	data, err := getDataFromControl(control, unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 4)
	if err != nil {
		return 0, err
	}
	if len(data) >= 4 {
		return binary.NativeEndian.Uint32(data), nil
	}
	return 0, nil
}

// handleRXQOverflowCounter handles any rx queue overflow counter contained in
// the tail of msgs.
func (c *linuxBatchingConn) handleRXQOverflowCounter(msgs []ipv6.Message, n int, rxErr error) {
	if n == 0 || rxErr != nil || c.rxqOverflowsMetric == nil {
		return
	}
	tailMsg := msgs[n-1] // we only care about the latest value as it's a cumulative counter
	if tailMsg.NN == 0 {
		return
	}
	rxqOverflows, err := getRXQOverflowsFromControl(tailMsg.OOB[:tailMsg.NN])
	if err != nil {
		return
	}
	// The counter is always present once nonzero on the kernel side. Compare it
	// with our previous view, push the delta to the clientmetric, and update
	// our view.
	if rxqOverflows == c.rxqOverflows {
		return
	}
	delta := int64(rxqOverflows - c.rxqOverflows)
	c.rxqOverflowsMetric.Add(delta)
	c.rxqOverflows = rxqOverflows
}

func (c *linuxBatchingConn) ReadBatch(msgs []ipv6.Message, flags int) (n int, err error) {
	c.readOpMu.Lock()
	defer c.readOpMu.Unlock()
	if !c.rxOffload || len(msgs) < 2 {
		n, err = c.xpc.ReadBatch(msgs, flags)
		c.handleRXQOverflowCounter(msgs, n, err)
		return n, err
	}
	// Read into the tail of msgs, split into the head.
	readAt := len(msgs) - 2
	n, err = c.xpc.ReadBatch(msgs[readAt:], 0)
	if err != nil || n == 0 {
		return 0, err
	}
	c.handleRXQOverflowCounter(msgs[readAt:], n, err)
	return c.splitCoalescedMessages(msgs, readAt)
}

func (c *linuxBatchingConn) LocalAddr() net.Addr {
	return c.pc.LocalAddr().(*net.UDPAddr)
}

func (c *linuxBatchingConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return c.pc.WriteToUDPAddrPort(b, addr)
}

func (c *linuxBatchingConn) Close() error {
	return c.pc.Close()
}

// tryEnableRXQOverflowsCounter attempts to enable the SO_RXQ_OVFL socket option
// on pconn, and returns the result. SO_RXQ_OVFL was added in Linux v2.6.33.
func tryEnableRXQOverflowsCounter(pconn nettype.PacketConn) (enabled bool) {
	if c, ok := pconn.(*net.UDPConn); ok {
		rc, err := c.SyscallConn()
		if err != nil {
			return
		}
		rc.Control(func(fd uintptr) {
			enabled = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 1) == nil
		})
	}
	return enabled
}

// tryEnableUDPOffload attempts to enable the UDP_GRO socket option on pconn,
// and returns two booleans indicating TX and RX UDP offload support.
func tryEnableUDPOffload(pconn nettype.PacketConn) (hasTX bool, hasRX bool) {
	if c, ok := pconn.(*net.UDPConn); ok {
		rc, err := c.SyscallConn()
		if err != nil {
			return
		}
		err = rc.Control(func(fd uintptr) {
			_, errSyscall := syscall.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
			hasTX = errSyscall == nil
			errSyscall = syscall.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
			hasRX = errSyscall == nil
		})
		if err != nil {
			return false, false
		}
	}
	return hasTX, hasRX
}

// getGSOSizeFromControl returns the GSO size found in control associated with a
// cmsg type of UDP_GRO, which the kernel populates in the read direction. If no
// GSO size is found or the len(control) < unix.SizeofCmsghdr, this function
// returns 0. A non-nil error will be returned if control is malformed.
func getGSOSizeFromControl(control []byte) (int, error) {
	data, err := getDataFromControl(control, unix.SOL_UDP, unix.UDP_GRO, 2)
	if err != nil {
		return 0, err
	}
	if len(data) >= 2 {
		return int(binary.NativeEndian.Uint16(data)), nil
	}
	return 0, nil
}

// setGSOSizeInControl sets a socket control message in control containing
// gsoSize with an associated cmsg type of UDP_SEGMENT, which we are responsible
// for populating prior to writing towards the kernel. If len(control) < controlMessageSize
// control's len will be set to 0.
func setGSOSizeInControl(control *[]byte, gsoSize uint16) {
	*control = (*control)[:0]
	if cap(*control) < int(unsafe.Sizeof(unix.Cmsghdr{})) {
		return
	}
	if cap(*control) < controlMessageSize {
		return
	}
	*control = (*control)[:cap(*control)]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&(*control)[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16((*control)[unix.SizeofCmsghdr:], gsoSize)
	*control = (*control)[:unix.CmsgSpace(2)]
}

var (
	rxqOverflowsMetricsMu     sync.Mutex
	rxqOverflowsMetricsByName map[string]*clientmetric.Metric
)

// getRXQOverflowsMetric returns a counter-based [*clientmetric.Metric] for the
// provided name in a thread-safe manner. Callers may pass the same metric name
// multiple times, which is common across rebinds of the underlying, associated
// [Conn].
func getRXQOverflowsMetric(name string) *clientmetric.Metric {
	if len(name) == 0 {
		return nil
	}
	rxqOverflowsMetricsMu.Lock()
	defer rxqOverflowsMetricsMu.Unlock()
	m, ok := rxqOverflowsMetricsByName[name]
	if ok {
		return m
	}
	if rxqOverflowsMetricsByName == nil {
		rxqOverflowsMetricsByName = make(map[string]*clientmetric.Metric)
	}
	m = clientmetric.NewCounter(name)
	rxqOverflowsMetricsByName[name] = m
	return m
}

// TryUpgradeToConn probes the capabilities of the OS and pconn, and upgrades
// pconn to a [Conn] if appropriate. A batch size of [IdealBatchSize] is
// suggested for the best performance. If len(rxqOverflowsMetricName) is
// nonzero, then read ops will propagate the SO_RXQ_OVFL control message counter
// to a clientmetric with the supplied name.
func TryUpgradeToConn(pconn nettype.PacketConn, network string, batchSize int, rxqOverflowsMetricName string) nettype.PacketConn {
	if runtime.GOOS != "linux" {
		// Exclude Android.
		return pconn
	}
	if network != "udp4" && network != "udp6" {
		return pconn
	}
	if strings.HasPrefix(hostinfo.GetOSVersion(), "2.") {
		// recvmmsg/sendmmsg were added in 2.6.33, but we support down to
		// 2.6.32 for old NAS devices. See https://github.com/tailscale/tailscale/issues/6807.
		// As a cheap heuristic: if the Linux kernel starts with "2", just
		// consider it too old for mmsg. Nobody who cares about performance runs
		// such ancient kernels. UDP offload was added much later, so no
		// upgrades are available.
		return pconn
	}
	uc, ok := pconn.(*net.UDPConn)
	if !ok {
		return pconn
	}
	b := &linuxBatchingConn{
		pc: uc,
		sendBatchPool: sync.Pool{
			New: func() any {
				ua := &net.UDPAddr{
					IP: make([]byte, 16),
				}
				msgs := make([]ipv6.Message, batchSize)
				for i := range msgs {
					msgs[i].Buffers = make([][]byte, 1)
					msgs[i].Addr = ua
					msgs[i].OOB = make([]byte, controlMessageSize)
				}
				return &sendBatch{
					ua:   ua,
					msgs: msgs,
				}
			},
		},
	}
	switch network {
	case "udp4":
		b.xpc = ipv4.NewPacketConn(uc)
	case "udp6":
		b.xpc = ipv6.NewPacketConn(uc)
	default:
		panic("bogus network")
	}
	var txOffload bool
	txOffload, b.rxOffload = tryEnableUDPOffload(uc)
	b.txOffload.Store(txOffload)
	if len(rxqOverflowsMetricName) > 0 && tryEnableRXQOverflowsCounter(uc) {
		// Don't register the metric unless the socket option has been
		// successfully set, otherwise we will report a misleading zero value
		// counter on the wire. This is one reason why we prefer to handle
		// clientmetric instantiation internally, vs letting callers pass them
		// to TryUpgradeToConn.
		b.rxqOverflowsMetric = getRXQOverflowsMetric(rxqOverflowsMetricName)
	}
	return b
}

var controlMessageSize = -1 // bomb if used for allocation before init

func init() {
	controlMessageSize =
		unix.CmsgSpace(2) + // UDP_GRO or UDP_SEGMENT gsoSize (uint16)
			unix.CmsgSpace(4) // SO_RXQ_OVFL counter (uint32)
}

// MinControlMessageSize returns the minimum control message size required to
// support read batching via [Conn.ReadBatch].
func MinControlMessageSize() int {
	return controlMessageSize
}

const IdealBatchSize = 128
