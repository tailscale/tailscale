// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tunlinkstats

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/feature"
	"tailscale.com/net/tstun"
	"tailscale.com/util/clientmetric"
)

func init() {
	feature.Register("tunlinkstats")
	tstun.HookPollTUNLinkStats.Set(start)
}

var (
	startOnce sync.Once
)

const (
	pollInterval = 15 * time.Second
)

// poll polls link statistics for ifName over netlink every [pollInterval]. It
// returns at the first error encountered, e.g. ENODEV on process/dev shutdown.
func poll(ifName string) {
	ifIndex, err := getIfIndex(ifName)
	if err != nil {
		return
	}
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	var (
		registerOnce sync.Once
		txQueueDrops *clientmetric.Metric
	)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for range ticker.C {
		stats, err := getStats(conn, ifIndex)
		if err != nil {
			return
		}
		registerOnce.Do(func() {
			// Don't register the clientmetric until we've successfully
			// polled. A zero value metric would be misleading if polling
			// fails, i.e. nil/absence has meaning.
			txQueueDrops = clientmetric.NewCounter("tundev_tx_queue_drops")
		})
		delta := int64(stats.txDropped) - txQueueDrops.Value()
		txQueueDrops.Add(delta)
	}
}

func start(ifName string) {
	startOnce.Do(func() {
		go poll(ifName)
	})
}

// ifStatsMsg is struct if_stats_msg from uapi/linux/if_link.h.
type ifStatsMsg struct {
	family     uint8
	pad1       uint8
	pad2       uint16
	ifIndex    uint32
	filterMask uint32
}

// encode encodes i in binary form for use over netlink in an RTM_GETSTATS
// request.
func (i *ifStatsMsg) encode() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(i)), unsafe.Sizeof(ifStatsMsg{}))
}

// getIfIndex returns the interface index for ifName via ioctl.
func getIfIndex(ifName string) (uint32, error) {
	ifr, err := unix.NewIfreq(ifName)
	if err != nil {
		return 0, err
	}
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	err = unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, ifr)
	if err != nil {
		return 0, err
	}
	return ifr.Uint32(), nil
}

// getStats returns [rtnlLinkStats64] via netlink RTM_GETSTATS over the provided
// conn for the provided ifIndex.
func getStats(conn *netlink.Conn, ifIndex uint32) (rtnlLinkStats64, error) {
	const iflaStatsLink64 = 1 // IFLA_STATS_LINK_64 from uapi/linux/if_link.h
	const iflaStatsLink64FilterMask = 1 << (iflaStatsLink64 - 1)
	reqData := ifStatsMsg{
		family:     unix.AF_UNSPEC,
		ifIndex:    ifIndex,
		filterMask: iflaStatsLink64FilterMask,
	}
	req := netlink.Message{
		Header: netlink.Header{
			Flags: netlink.Request,
			Type:  unix.RTM_GETSTATS,
		},
		Data: reqData.encode(),
	}
	msgs, err := conn.Execute(req)
	if err != nil {
		return rtnlLinkStats64{}, err
	}
	if len(msgs) != 1 {
		return rtnlLinkStats64{}, fmt.Errorf("expected one netlink response message, got: %d", len(msgs))
	}
	msg := msgs[0]
	if msg.Header.Type != unix.RTM_NEWSTATS {
		return rtnlLinkStats64{}, fmt.Errorf("expected RTM_NEWSTATS (%d) netlink response, got: %d", unix.RTM_NEWSTATS, msg.Header.Type)
	}
	sizeOfIfStatsMsg := int(unsafe.Sizeof(ifStatsMsg{}))
	if len(msg.Data) < sizeOfIfStatsMsg {
		return rtnlLinkStats64{}, fmt.Errorf("length of netlink response data < %d, got: %d", sizeOfIfStatsMsg, len(msg.Data))
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[sizeOfIfStatsMsg:])
	if err != nil {
		return rtnlLinkStats64{}, err
	}
	for ad.Next() {
		if ad.Type() == iflaStatsLink64 {
			stats := rtnlLinkStats64{}
			ad.Do(func(b []byte) error {
				return stats.decode(b)
			})
			if ad.Err() != nil {
				return rtnlLinkStats64{}, ad.Err()
			}
			return stats, nil
		}
	}
	return rtnlLinkStats64{}, errors.New("no stats found in netlink response")
}

// rtnlLinkStats64 is struct rtnl_link_stats64 from uapi/linux/if_link.h up to
// the addition of the RTM_GETSTATS netlink message (Linux commit 10c9ead9f3c6).
// Newer fields are omitted. Since we expect this type in response to RTM_GETSTATS,
// we marry them together from a minimum kernel version perspective (Linux v4.7).
// Field documentation is copied from the kernel verbatim.
type rtnlLinkStats64 struct {
	// rxPackets is the number of good packets received by the interface.
	// For hardware interfaces counts all good packets received from the device
	// by the host, including packets which host had to drop at various stages
	// of processing (even in the driver).
	rxPackets uint64

	// txPackets is the number of packets successfully transmitted.
	// For hardware interfaces counts packets which host was able to successfully
	// hand over to the device, which does not necessarily mean that packets
	// had been successfully transmitted out of the device, only that device
	// acknowledged it copied them out of host memory.
	txPackets uint64

	// rxBytes is the number of good received bytes, corresponding to rxPackets.
	// For IEEE 802.3 devices should count the length of Ethernet Frames
	// excluding the FCS.
	rxBytes uint64

	// txBytes is the number of good transmitted bytes, corresponding to txPackets.
	// For IEEE 802.3 devices should count the length of Ethernet Frames
	// excluding the FCS.
	txBytes uint64

	// rxErrors is the total number of bad packets received on this network device.
	// This counter must include events counted by rxLengthErrors,
	// rxCRCErrors, rxFrameErrors and other errors not otherwise counted.
	rxErrors uint64

	// txErrors is the total number of transmit problems.
	// This counter must include events counted by txAbortedErrors,
	// txCarrierErrors, txFIFOErrors, txHeartbeatErrors,
	// txWindowErrors and other errors not otherwise counted.
	txErrors uint64

	// rxDropped is the number of packets received but not processed,
	// e.g. due to lack of resources or unsupported protocol.
	// For hardware interfaces this counter may include packets discarded
	// due to L2 address filtering but should not include packets dropped
	// by the device due to buffer exhaustion which are counted separately in
	// rxMissedErrors (since procfs folds those two counters together).
	rxDropped uint64

	// txDropped is the number of packets dropped on their way to transmission,
	// e.g. due to lack of resources.
	txDropped uint64

	// multicast is the number of multicast packets received.
	// For hardware interfaces this statistic is commonly calculated
	// at the device level (unlike rxPackets) and therefore may include
	// packets which did not reach the host.
	// For IEEE 802.3 devices this counter may be equivalent to:
	//  - 30.3.1.1.21 aMulticastFramesReceivedOK
	multicast uint64

	// collisions is the number of collisions during packet transmissions.
	collisions uint64

	// rxLengthErrors is the number of packets dropped due to invalid length.
	// Part of aggregate "frame" errors in /proc/net/dev.
	// For IEEE 802.3 devices this counter should be equivalent to a sum of:
	//  - 30.3.1.1.23 aInRangeLengthErrors
	//  - 30.3.1.1.24 aOutOfRangeLengthField
	//  - 30.3.1.1.25 aFrameTooLongErrors
	rxLengthErrors uint64

	// rxOverErrors is the receiver FIFO overflow event counter.
	// Historically the count of overflow events. Such events may be reported
	// in the receive descriptors or via interrupts, and may not correspond
	// one-to-one with dropped packets.
	// The recommended interpretation for high speed interfaces is the number
	// of packets dropped because they did not fit into buffers provided by the
	// host, e.g. packets larger than MTU or next buffer in the ring was not
	// available for a scatter transfer.
	// Part of aggregate "frame" errors in /proc/net/dev.
	// This statistic corresponds to hardware events and is not commonly used
	// on software devices.
	rxOverErrors uint64

	// rxCRCErrors is the number of packets received with a CRC error.
	// Part of aggregate "frame" errors in /proc/net/dev.
	// For IEEE 802.3 devices this counter must be equivalent to:
	//  - 30.3.1.1.6 aFrameCheckSequenceErrors
	rxCRCErrors uint64

	// rxFrameErrors is the receiver frame alignment errors.
	// Part of aggregate "frame" errors in /proc/net/dev.
	// For IEEE 802.3 devices this counter should be equivalent to:
	//  - 30.3.1.1.7 aAlignmentErrors
	rxFrameErrors uint64

	// rxFIFOErrors is the receiver FIFO error counter.
	// Historically the count of overflow events. Those events may be reported
	// in the receive descriptors or via interrupts, and may not correspond
	// one-to-one with dropped packets.
	// This statistic is used on software devices, e.g. to count software
	// packet queue overflow (can) or sequencing errors (GRE).
	rxFIFOErrors uint64

	// rxMissedErrors is the count of packets missed by the host.
	// Folded into the "drop" counter in /proc/net/dev.
	// Counts number of packets dropped by the device due to lack of buffer
	// space. This usually indicates that the host interface is slower than
	// the network interface, or host is not keeping up with the receive
	// packet rate.
	// This statistic corresponds to hardware events and is not used on
	// software devices.
	rxMissedErrors uint64

	// txAbortedErrors is part of aggregate "carrier" errors in /proc/net/dev.
	// For IEEE 802.3 devices capable of half-duplex operation this counter
	// must be equivalent to:
	//  - 30.3.1.1.11 aFramesAbortedDueToXSColls
	// High speed interfaces may use this counter as a general device discard
	// counter.
	txAbortedErrors uint64

	// txCarrierErrors is the number of frame transmission errors due to loss
	// of carrier during transmission.
	// Part of aggregate "carrier" errors in /proc/net/dev.
	// For IEEE 802.3 devices this counter must be equivalent to:
	//  - 30.3.1.1.13 aCarrierSenseErrors
	txCarrierErrors uint64

	// txFIFOErrors is the number of frame transmission errors due to device
	// FIFO underrun / underflow. This condition occurs when the device begins
	// transmission of a frame but is unable to deliver the entire frame to
	// the transmitter in time for transmission.
	// Part of aggregate "carrier" errors in /proc/net/dev.
	txFIFOErrors uint64

	// txHeartbeatErrors is the number of Heartbeat / SQE Test errors for
	// old half-duplex Ethernet.
	// Part of aggregate "carrier" errors in /proc/net/dev.
	// For IEEE 802.3 devices possibly equivalent to:
	//  - 30.3.2.1.4 aSQETestErrors
	txHeartbeatErrors uint64

	// txWindowErrors is the number of frame transmission errors due to late
	// collisions (for Ethernet - after the first 64B of transmission).
	// Part of aggregate "carrier" errors in /proc/net/dev.
	// For IEEE 802.3 devices this counter must be equivalent to:
	//  - 30.3.1.1.10 aLateCollisions
	txWindowErrors uint64

	// rxCompressed is the number of correctly received compressed packets.
	// This counter is only meaningful for interfaces which support packet
	// compression (e.g. CSLIP, PPP).
	rxCompressed uint64

	// txCompressed is the number of transmitted compressed packets.
	// This counter is only meaningful for interfaces which support packet
	// compression (e.g. CSLIP, PPP).
	txCompressed uint64

	// rxNoHandler is the number of packets received on the interface but
	// dropped by the networking stack because the device is not designated
	// to receive packets (e.g. backup link in a bond).
	rxNoHandler uint64
}

// decode unpacks a [rtnlLinkStats64] from the raw bytes of a netlink attribute
// payload, e.g. IFLA_STATS64. The kernel writes the struct in host byte order,
// so binary.NativeEndian is used throughout. The buffer may be larger than the
// struct to allow for future kernel additions.
func (s *rtnlLinkStats64) decode(b []byte) error {
	const minSize = 24 * 8
	if len(b) < minSize {
		return fmt.Errorf("rtnlLinkStats64.decode: buffer too short: got %d bytes, want at least %d", len(b), minSize)
	}
	s.rxPackets = binary.NativeEndian.Uint64(b[0:])
	s.txPackets = binary.NativeEndian.Uint64(b[8:])
	s.rxBytes = binary.NativeEndian.Uint64(b[16:])
	s.txBytes = binary.NativeEndian.Uint64(b[24:])
	s.rxErrors = binary.NativeEndian.Uint64(b[32:])
	s.txErrors = binary.NativeEndian.Uint64(b[40:])
	s.rxDropped = binary.NativeEndian.Uint64(b[48:])
	s.txDropped = binary.NativeEndian.Uint64(b[56:])
	s.multicast = binary.NativeEndian.Uint64(b[64:])
	s.collisions = binary.NativeEndian.Uint64(b[72:])
	s.rxLengthErrors = binary.NativeEndian.Uint64(b[80:])
	s.rxOverErrors = binary.NativeEndian.Uint64(b[88:])
	s.rxCRCErrors = binary.NativeEndian.Uint64(b[96:])
	s.rxFrameErrors = binary.NativeEndian.Uint64(b[104:])
	s.rxFIFOErrors = binary.NativeEndian.Uint64(b[112:])
	s.rxMissedErrors = binary.NativeEndian.Uint64(b[120:])
	s.txAbortedErrors = binary.NativeEndian.Uint64(b[128:])
	s.txCarrierErrors = binary.NativeEndian.Uint64(b[136:])
	s.txFIFOErrors = binary.NativeEndian.Uint64(b[144:])
	s.txHeartbeatErrors = binary.NativeEndian.Uint64(b[152:])
	s.txWindowErrors = binary.NativeEndian.Uint64(b[160:])
	s.rxCompressed = binary.NativeEndian.Uint64(b[168:])
	s.txCompressed = binary.NativeEndian.Uint64(b[176:])
	s.rxNoHandler = binary.NativeEndian.Uint64(b[184:])
	return nil
}
