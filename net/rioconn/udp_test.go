// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn_test

import (
	"bytes"
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/net/ipv6"
	"tailscale.com/net/batching"
	"tailscale.com/net/packet"
	"tailscale.com/net/rioconn"
	"tailscale.com/types/nettype"
)

// [UDPConn] implements the following interfaces.
var (
	_ batching.Conn      = (*rioconn.UDPConn)(nil)
	_ net.PacketConn     = (*rioconn.UDPConn)(nil)
	_ nettype.PacketConn = (*rioconn.UDPConn)(nil)
	_ syscall.Conn       = (*rioconn.UDPConn)(nil)
)

func TestListenUDP(t *testing.T) {
	tests := []struct {
		network           string
		address           string
		wantLocalAddrPort netip.AddrPort
		wantDualStack     bool
	}{
		{
			network: "udp", address: "127.0.0.1:0", wantLocalAddrPort: netip.MustParseAddrPort("127.0.0.1:0"),
		},
		{
			network: "udp4", address: "127.0.0.1:0", wantLocalAddrPort: netip.MustParseAddrPort("127.0.0.1:0"),
		},
		{
			network: "udp", address: "[::1]:0", wantLocalAddrPort: netip.MustParseAddrPort("[::1]:0"),
		},
		{
			network: "udp6", address: "[::1]:0", wantLocalAddrPort: netip.MustParseAddrPort("[::1]:0"),
		},
		{
			network: "udp", address: "0.0.0.0:0", wantLocalAddrPort: netip.MustParseAddrPort("0.0.0.0:0"),
		},
		{
			network: "udp4", address: "0.0.0.0:0", wantLocalAddrPort: netip.MustParseAddrPort("0.0.0.0:0"),
		},
		{
			network: "udp", address: "[::]:0", wantLocalAddrPort: netip.MustParseAddrPort("[::]:0"),
		},
		{
			network: "udp6", address: "[::]:0", wantLocalAddrPort: netip.MustParseAddrPort("[::]:0"),
		},
		{
			network: "udp", address: ":0", wantLocalAddrPort: netip.MustParseAddrPort("[::]:0"), wantDualStack: true,
		},
		{
			network: "udp4", address: ":0", wantLocalAddrPort: netip.MustParseAddrPort("0.0.0.0:0"),
		},
		{
			network: "udp6", address: ":0", wantLocalAddrPort: netip.MustParseAddrPort("[::]:0"),
		},
		{
			network: "udp", address: ":41613", wantLocalAddrPort: netip.MustParseAddrPort("[::]:41613"), wantDualStack: true,
		},
		{
			network: "udp4", address: ":41613", wantLocalAddrPort: netip.MustParseAddrPort("0.0.0.0:41613"), wantDualStack: false,
		},
		{
			network: "udp6", address: ":41613", wantLocalAddrPort: netip.MustParseAddrPort("[::]:41613"), wantDualStack: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.network+"/"+tt.address, func(t *testing.T) {
			addr, err := net.ResolveUDPAddr(tt.network, tt.address)
			if err != nil {
				t.Fatalf("ResolveUDPAddr(%q, %q) error: %v", tt.network, tt.address, err)
			}

			conn, err := rioconn.ListenUDP(tt.network, addr)
			if err != nil {
				t.Fatalf("ListenUDP(%q, %q) error: %v", tt.network, tt.address, err)
			}
			t.Cleanup(func() {
				err := conn.Close()
				if err != nil {
					t.Errorf("Close() error: %v", err)
				}
			})

			gotAddressPort := conn.LocalAddrPort()
			if wantAddress := tt.wantLocalAddrPort.Addr(); gotAddressPort.Addr().Compare(wantAddress) != 0 {
				t.Errorf("LocalAddrPort() Addr = %v; want %v", gotAddressPort.Addr(), tt.wantLocalAddrPort.Addr())
			}
			if wantPort := tt.wantLocalAddrPort.Port(); wantPort != 0 && gotAddressPort.Port() != wantPort {
				t.Errorf("LocalAddrPort() Port = %v; want %v", gotAddressPort.Port(), wantPort)
			}
			if gotDualStack := conn.IsDualStack(); gotDualStack != tt.wantDualStack {
				t.Errorf("IsDualStack() = %v; want %v", gotDualStack, tt.wantDualStack)
			}
		})
	}
}

func TestUDPSendReceiveBatch(t *testing.T) {
	const defaultBatchSize = 64

	t.Parallel()

	tests := []struct {
		name             string
		network          string
		pattern          []int
		iterations       int
		sendBatchSize    int
		receiveBatchSize int
		uso              bool
	}{
		{
			name:    "udp4/single",
			network: "udp4",
			pattern: []int{1312},
		},
		{
			name:       "udp4/batch",
			network:    "udp4",
			pattern:    []int{1312},
			iterations: 1024,
		},
		{
			name:    "udp4/single/max",
			network: "udp4",
			pattern: []int{rioconn.MaxUDPPayloadIPv4},
		},
		{
			name:       "udp4/batch/max",
			network:    "udp4",
			pattern:    []int{rioconn.MaxUDPPayloadIPv4},
			iterations: 1024,
		},
		{
			name:    "udp6/single",
			network: "udp6",
			pattern: []int{1312},
		},
		{
			name:       "udp6/batch",
			network:    "udp6",
			pattern:    []int{1312},
			iterations: 1024,
		},
		{
			name:    "udp6/single/max",
			network: "udp6",
			pattern: []int{rioconn.MaxUDPPayloadIPv6},
		},
		{
			name:       "udp6/batch/max",
			network:    "udp6",
			pattern:    []int{rioconn.MaxUDPPayloadIPv6},
			iterations: 10,
		},
		{
			name:       "udp6/batch/uso",
			network:    "udp6",
			pattern:    []int{1312},
			iterations: 10,
			uso:        true,
		},
		{
			name:       "udp6/batch/max/uso",
			network:    "udp6",
			pattern:    []int{rioconn.MaxUDPPayloadIPv6},
			iterations: 10,
			uso:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			udpSendReceiveBatch(t,
				tt.pattern, max(1, tt.iterations),
				cmp.Or(tt.sendBatchSize, defaultBatchSize),
				cmp.Or(tt.receiveBatchSize, defaultBatchSize),
				tt.network, tt.network,
				[]rioconn.UDPOption{
					rioconn.USO(tt.uso),
				}, nil,
			)
		})
	}
}

func FuzzUDPSendReceiveBatch(f *testing.F) {
	batchSizes := []uint16{1, 64}
	packetSizes := []uint16{0, 1, 64, 1312, 9000, rioconn.MaxUDPPayloadIPv4}
	numIterations := []uint16{1024}
	uso := []bool{false, true}
	uro := []bool{false, true}

	for _, packetLen := range packetSizes {
		for _, numIter := range numIterations {
			for _, batchSize := range batchSizes {
				for _, usoEnabled := range uso {
					for _, uroEnabled := range uro {
						f.Add(packetLen, numIter, batchSize, batchSize, usoEnabled, uroEnabled)
					}
				}
			}
		}
	}

	f.Fuzz(func(t *testing.T, packetLen, numIterations, sendBatchSize, receiveBatchSize uint16, usoEnabled, uroEnabled bool) {
		network := "udp4"
		maxPacketLen := uint16(rioconn.MaxUDPPayloadIPv4)

		if packetLen > maxPacketLen {
			t.Skipf("packetLen is too large: %d", packetLen)
		}
		if numIterations > 10_000 {
			t.Skipf("numIterations is too large: %d", numIterations)
		}
		if sendBatchSize == 0 || sendBatchSize > 1024 {
			t.Skipf("sendBatchSize is out of range: %d", sendBatchSize)
		}
		if receiveBatchSize == 0 || receiveBatchSize > 1024 {
			t.Skipf("receiveBatchSize is out of range: %d", receiveBatchSize)
		}

		packetLengthPattern := []int{int(packetLen)}
		udpSendReceiveBatch(t, packetLengthPattern, int(numIterations),
			int(sendBatchSize), int(receiveBatchSize), network, network,
			[]rioconn.UDPOption{
				rioconn.RxMemoryLimit(128 << 10),
				rioconn.TxMemoryLimit(512 << 10),
				rioconn.USO(usoEnabled),
			},
			[]rioconn.UDPOption{
				rioconn.RxMemoryLimit(512 << 10),
				rioconn.TxMemoryLimit(128 << 10),
				rioconn.URO(uroEnabled),
			},
		)
	})
}

// udpSendReceive sends and receives batches of UDP packets between two
// [rioconn.UDPConn] instances over the loopback interface.
//
// It uses the provided packet length pattern, iteration count,
// batch sizes, networks, and connection options.
func udpSendReceiveBatch(
	tb testing.TB,
	packetLengthPattern []int,
	numIterations int,
	sendBatchSize, receiveBatchSize int,
	senderNetwork, receiverNetwork string,
	senderOpts, receiverOpts []rioconn.UDPOption,
) {
	stopMsg := []byte("STOP")

	sender, err := rioconn.ListenUDP(senderNetwork, loopbackUDPAddr(senderNetwork, 0), senderOpts...)
	if err != nil {
		tb.Fatalf("ListenUDP(%s, nil) error: %v", senderNetwork, err)
	}
	defer sender.Close()

	receiver, err := rioconn.ListenUDP(receiverNetwork, loopbackUDPAddr(receiverNetwork, 0), receiverOpts...)
	if err != nil {
		tb.Fatalf("ListenUDP(%s, nil) error: %v", receiverNetwork, err)
	}
	defer receiver.Close()

	// Do not allocate buffers larger than needed for the test.
	maxPacketLen := max(len(stopMsg), slices.Max(packetLengthPattern))

	outBuffs := make([][]byte, sendBatchSize)
	for i := range outBuffs {
		outBuffs[i] = make([]byte, maxPacketLen)
	}

	inMsgs := make([]ipv6.Message, receiveBatchSize)
	for i := range inMsgs {
		inMsgs[i].Buffers = make([][]byte, 1)
		inMsgs[i].Buffers[0] = make([]byte, maxPacketLen)
	}

	readerResult := make(chan error, 1)
	writerResult := make(chan error, 1)

	go func() {
		defer close(writerResult)

		dstAddr := receiver.LocalAddrPort()

		bytes := 0
		packets := 0
		iteration := 0
		for iteration < numIterations {
			outBuffs := outBuffs[:cap(outBuffs)]
			for k := range outBuffs {
				packetLen := packetLengthPattern[packets%len(packetLengthPattern)]
				out := outBuffs[k][:packetLen]
				outBuffs[k] = out
				for j := 0; j < packetLen; j++ {
					out[j] = byte('A' + bytes%26)
					bytes++
				}
				packets++
				if packets%len(packetLengthPattern) == 0 {
					iteration++
				}
				if iteration >= numIterations {
					outBuffs = outBuffs[:k+1]
					break
				}
			}
			if err := sender.WriteBatchTo(outBuffs, dstAddr, packet.GeneveHeader{}, 0); err != nil {
				writerResult <- fmt.Errorf("failed to send batch #%d: %w", iteration, err)
				return
			}
		}

		tb.Logf("Writer done sending %d packets and %d bytes in %d iterations", packets, bytes, iteration)
		tb.Logf("Sending STOP messages to signal the reader to stop")
		for {
			select {
			case <-readerResult:
				tb.Logf("Reader has stopped, no need to send more STOP messages")
				return
			default:
			}

			if _, err := sender.WriteTo(stopMsg, net.UDPAddrFromAddrPort(dstAddr)); err != nil {
				writerResult <- fmt.Errorf("failed to send a STOP message: %w", err)
				return
			}
		}
	}()

	go func() {
		defer close(readerResult)

		bytesReceived := 0
		for {
			n, err := receiver.ReadBatch(inMsgs, 0)
			if err != nil {
				readerResult <- fmt.Errorf("ReadBatch() error: %w", err)
				return
			}
			for i := range n {
				msg := inMsgs[i]
				if bytes.Equal(msg.Buffers[0][:msg.N], stopMsg) {
					tb.Logf("Received a STOP message, reader is stopping")
					return
				}
				for j := 0; j < msg.N; j++ {
					expectedByte := byte('A' + bytesReceived%26)
					if msg.Buffers[0][j] != expectedByte {
						readerResult <- fmt.Errorf("unexpected byte at position %d: got %v, want %v",
							bytesReceived, msg.Buffers[0][j], expectedByte)
						return
					}
					bytesReceived++
				}
			}
		}
	}()

	if err := <-writerResult; err != nil {
		tb.Fatalf("writer error: %v", err)
	}
	if err := <-readerResult; err != nil {
		tb.Fatalf("reader error: %v", err)
	}
}

func TestUDPReadWrite(t *testing.T) {
	sender, err := rioconn.ListenUDP("udp4", loopbackUDPAddr("udp4", 0))
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer sender.Close()

	receiver, err := rioconn.ListenUDP("udp4", loopbackUDPAddr("udp4", 0))
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer receiver.Close()

	message := []byte("Hello, world!")

	n, err := sender.WriteTo(message, net.UDPAddrFromAddrPort(receiver.LocalAddrPort()))
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(message) {
		t.Fatalf("WriteTo: wrote %d bytes, want %d", n, len(message))
	}

	buf := make([]byte, 1024)
	n, addr, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], message) {
		t.Fatalf("ReadFrom: got %q, want %q", buf[:n], message)
	}
	if addr.String() != net.UDPAddrFromAddrPort(sender.LocalAddrPort()).String() {
		t.Fatalf("ReadFrom: got addr %v, want %v", addr, sender.LocalAddrPort())
	}
}

func TestUDPReadFromUDPAddrPort(t *testing.T) {
	sender, err := rioconn.ListenUDP("udp4", loopbackUDPAddr("udp4", 0))
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer sender.Close()

	receiver, err := rioconn.ListenUDP("udp4", loopbackUDPAddr("udp4", 0))
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer receiver.Close()

	message := []byte("Hello, world!")

	n, err := sender.WriteToUDPAddrPort(message, receiver.LocalAddrPort())
	if err != nil {
		t.Fatalf("WriteToUDPAddrPort: %v", err)
	}
	if n != len(message) {
		t.Fatalf("WriteToUDPAddrPort: wrote %d bytes, want %d", n, len(message))
	}

	buf := make([]byte, 1024)
	n, addr, err := receiver.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("ReadFromUDPAddrPort: %v", err)
	}
	if !bytes.Equal(buf[:n], message) {
		t.Fatalf("ReadFromUDPAddrPort: got %q, want %q", buf[:n], message)
	}
	if addr != sender.LocalAddrPort() {
		t.Fatalf("ReadFromUDPAddrPort: got addr %v, want %v", addr, sender.LocalAddrPort())
	}
}

func loopbackUDPAddr(network string, port int) *net.UDPAddr {
	switch network {
	case "udp4":
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	case "udp6":
		return &net.UDPAddr{IP: net.IPv6loopback, Port: port}
	default:
		panic(fmt.Sprintf("unsupported network: %s", network))
	}
}
