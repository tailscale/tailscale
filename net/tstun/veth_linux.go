// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/asavie/xdp"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
)

// This file borrows a lot of values from tap_linux.go, e.g. ourMAC.

func init() { createVETH = createVETHLinux }

const queueID = 0 // TODO explore alternatives

// TODO: do better
var dstMAC = net.HardwareAddr{0x30, 0x2D, 0x66, 0xEC, 0x7A, 0x94}

func createVETHLinux(vethName string) (device tun.Device, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tstun: veth: %w", err)
		}
	}()
	vethBEName := vethName + "be"
	cmd := exec.Command("ip", "link", "add", vethName, "type", "veth", "peer", "name", vethBEName)
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip link add %s: %v: %s", vethName, err, b)
	}
	if b, err := exec.Command("ip", "link", "set", "dev", vethName, "arp", "off").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip link up %s: %v: %s", vethName, err, b)
	}
	// TODO why do we need to set the MTU here?
	if b, err := exec.Command("ip", "link", "set", "dev", vethName, "mtu", strconv.Itoa(DefaultMTU)).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip link mtu %s: %v: %s", vethName, err, b)
	}
	if b, err := exec.Command("ip", "link", "set", "dev", vethName, "up").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip link up %s: %v: %s", vethName, err, b)
	}
	if b, err := exec.Command("ip", "link", "set", "dev", vethBEName, "up").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip link up %s: %v: %s", vethBEName, err, b)
	}
	ourMACStr := fmt.Sprintf("%x:%x:%x:%x:%x:%x", ourMAC[0], ourMAC[1], ourMAC[2], ourMAC[3], ourMAC[4], ourMAC[5])
	if b, err := exec.Command("ip", "link", "set", "dev", vethBEName, "address", ourMACStr).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ifconfig %s hw ether: %v: %s", vethBEName, err, b)
	}
	dstMACStr := fmt.Sprintf("%x:%x:%x:%x:%x:%x", dstMAC[0], dstMAC[1], dstMAC[2], dstMAC[3], dstMAC[4], dstMAC[5])
	if b, err := exec.Command("ip", "link", "set", "dev", vethName, "address", dstMACStr).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ifconfig %s hw ether: %v: %s", vethBEName, err, b)
	}
	// TODO ubuntu does not ship with ethtool by default.
	// If we don't have ethtool we can calculate checksums ourselves, see wrap.go.
	// I took a quick look at the strace and it's mysterious.
	if b, err := exec.Command("ethtool", "-K", vethName, "tx", "off", "rx", "off").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("checksum offloading: %v: %s", err, b)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces: %v", err)
	}

	ifBEIndex := -1
	for _, iface := range ifaces {
		if iface.Name == vethBEName {
			ifBEIndex = iface.Index
			break
		}
	}
	if ifBEIndex == -1 {
		return nil, errors.New("could not find veth index")
	}

	program, err := xdp.NewProgram(queueID + 1)
	if err != nil {
		return nil, fmt.Errorf("xdp.NewProgram: %w", err)
	}
	if err := program.Attach(ifBEIndex); err != nil {
		return nil, fmt.Errorf("xdp program failed to attach: %w", err)
	}

	xsk, err := xdp.NewSocket(ifBEIndex, queueID, nil)
	if err != nil {
		return nil, fmt.Errorf("xdp failed to create socket: %w", err)
	}
	if err := program.Register(queueID, xsk.FD()); err != nil {
		return nil, fmt.Errorf("xdp failed to register socket: %w", err)
	}

	//ip link add ve_A type veth peer name ve_B
	d := &vethDevice{
		name:      vethName,
		events:    make(chan tun.Event, 1),
		program:   program,
		ifBEIndex: ifBEIndex,
		xsk:       xsk,
	}

	fmt.Printf("createVETHLinux: NumFreeFillSlots=%d\n", d.xsk.NumFreeFillSlots())
	fmt.Printf("createVETHLinux: NumFreeTxSlots=%d\n", d.xsk.NumFreeTxSlots())
	return d, nil
}

// vethDevice implements tun.Device, using a virtual ethernet pair and AF_XDP.
type vethDevice struct {
	name      string
	events    chan tun.Event
	program   *xdp.Program
	ifBEIndex int
	xsk       *xdp.Socket

	pollEvent rawfile.PollEvent

	rxMu    sync.Mutex // guards rxDescs
	rxDescs []xdp.Desc

	txMu    sync.Mutex // guards txDescs, txCur
	txDescs []xdp.Desc
	txNext  int
}

// File implements tun.Device.File.
func (d *vethDevice) File() *os.File { panic("no file for veth/xdp") }

func (d *vethDevice) blockingPoll(events pollEvent) (numReceived, numCompleted int, err error) {
	//return d.xsk.Poll(-1)
	d.pollEvent = rawfile.PollEvent{
		FD:     int32(d.xsk.FD()),
		Events: int16(events),
	}
	/*if d.xsk.NumFilled() > 0 {
		d.pollEvent.Events |= unix.POLLIN
	}
	/*if d.xsk.NumTransmitted() > 0 {
		d.pollEvent.Events |= unix.POLLOUT
	}*/
	if d.pollEvent.Events == 0 {
		return
	}
	for err = unix.EINTR; err == unix.EINTR; {
		_, errNo := rawfile.BlockingPoll(&d.pollEvent, 1, nil)
		if errNo == 0 {
			err = nil
		} else {
			err = errNo
		}
	}
	if err != nil {
		fmt.Printf("blockingPoll err=%v (%d)", err, err)
		return 0, 0, err
	}
	numReceived = d.xsk.NumReceived()
	numCompleted = d.xsk.NumCompleted()
	if numCompleted > 0 {
		d.xsk.Complete(numCompleted)
	}
	return numReceived, numCompleted, err
}

// Read implements tun.Device.Read.
// read a packet from the device (without any additional headers)
func (d *vethDevice) Read(b []byte, off int) (int, error) {
	d.rxMu.Lock()
	defer d.rxMu.Unlock()

	for len(d.rxDescs) == 0 {
		if n := d.xsk.NumFreeFillSlots(); n > 0 {
			d.xsk.Fill(d.xsk.GetDescs(n, true))
		}
		numRx, _, err := d.blockingPoll(pollRx)
		if err != nil {
			return 0, fmt.Errorf("veth: %w", err)
		}
		d.rxDescs = d.xsk.Receive(numRx)
		//fmt.Printf("vethDevice.Read numRx=%d, len(d.rxDescs)=%d\n", numRx, len(d.rxDescs))
		//fmt.Printf("--- vethDevice.Read: NumFreeFillSlots: %d numRx: %d, len(rxDescs): %d\n", n, numRx, len(d.rxDescs))
	}
	if len(d.rxDescs) == 0 {
		return 0, fmt.Errorf("veth: %w", io.EOF) // TODO: what error?
	}
	data := d.xsk.GetFrame(d.rxDescs[0])
	n := copy(b[off:], data)
	//fmt.Printf("--- vethDevice.Read: frame data len=%d (n=%d): %x\n", len(data), n, data)
	d.rxDescs = d.rxDescs[1:]
	return n, nil
}

// Write implements tun.Device.Write.
// writes a packet to the device (without any additional headers)
func (d *vethDevice) Write(b []byte, off int) (int, error) {
	d.txMu.Lock()
	defer d.txMu.Unlock()

	for len(d.txDescs) == 0 {
		if numCompleted := d.xsk.NumCompleted(); numCompleted > 0 {
			d.xsk.Complete(numCompleted)
		}
		d.txNext = 0
		d.txDescs = d.xsk.GetDescs(d.xsk.NumFreeTxSlots(), false)
		if len(d.txDescs) == 0 {
			_, _, err := d.blockingPoll(pollTx)
			if err != nil {
				return 0, fmt.Errorf("veth: Write: %w", io.EOF)
			}
		}
		//fmt.Printf("veth.Write len(txDescs)=%d\n", len(d.txDescs))
	}

	n := copy(d.xsk.GetFrame(d.txDescs[d.txNext]), b[off:])
	d.txDescs[d.txNext].Len = uint32(n)
	d.txNext++

	if d.txNext == len(d.txDescs) {
		return len(b), d.flushTxLocked()
	}
	return len(b), nil
}

// Flush implements tun.Device.Flush.
// flush all previous writes to the device
func (d *vethDevice) Flush() error {
	d.txMu.Lock()
	defer d.txMu.Unlock()
	return d.flushTxLocked()
}

func (d *vethDevice) flushTxLocked() error {
	if d.txNext == 0 {
		return nil
	}
	if d.xsk.Transmit(d.txDescs[:d.txNext]) > 0 {
		if numCompleted := d.xsk.NumCompleted(); numCompleted > 0 {
			d.xsk.Complete(numCompleted)
		}
	}
	// We pick up the transmission using the blocking poll in Write.
	d.txDescs = nil
	d.txNext = 0
	return nil
}

type pollEvent int

const (
	pollRx = pollEvent(unix.POLLIN)
	pollTx = pollEvent(unix.POLLOUT)
)

// MTU implements tun.Device.MTU.
func (d *vethDevice) MTU() (int, error) { return DefaultMTU, nil } // TODO

// Name implements tun.Device.Name.
func (d *vethDevice) Name() (string, error) { return d.name, nil }

// Events implements tun.Device.Events.
// returns a constant channel of events related to the device
func (d *vethDevice) Events() chan tun.Event {
	d.events <- tun.EventUp
	// TODO EventDown, EventMTUUpdate
	return d.events
}

// Close implements tun.Device.Close.
// stops the device and closes the event channel
func (d *vethDevice) Close() error {
	close(d.events)
	d.program.Unregister(queueID)
	d.xsk.Close()
	d.program.Detach(d.ifBEIndex)
	d.program.Close()
	return nil
}
