// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

// Command rioperf is a simple traffic generator and performance test tool for rioconn.UDPConn.
//
// Run with "server" to start the server, or "client <dest>" to send traffic to it.
package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/net/ipv6"
	"tailscale.com/net/packet"
	"tailscale.com/net/rioconn"
)

func main() {
	root := &ffcli.Command{
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
		ShortUsage: "rioperf <client|server> [flags]",
		ShortHelp:  "rioconn performance test tool",
		FlagSet:    flag.NewFlagSet("rioperf", flag.ExitOnError),
		Subcommands: []*ffcli.Command{
			{
				Name:       "server",
				ShortUsage: "server [flags]",
				ShortHelp:  "Start a server",
				FlagSet:    buildServerFlags(),
				Exec: func(ctx context.Context, args []string) error {
					runServer()
					return nil
				},
			},
			{
				Name:       "client",
				ShortUsage: "client <dest> [flags]",
				ShortHelp:  "Start a client",
				FlagSet:    buildClientFlags(),
				Exec: func(ctx context.Context, args []string) error {
					if len(args) < 1 {
						return flag.ErrHelp
					}
					destStr := args[0]
					if !strings.Contains(destStr, ":") {
						destStr += ":0"
					}
					destUDPAddr, err := net.ResolveUDPAddr("udp", destStr)
					if err != nil {
						return fmt.Errorf("invalid destination address: %w", err)
					}
					if destUDPAddr.Port == 0 && clientFlags.port != 0 {
						destUDPAddr.Port = clientFlags.port
					}
					destAddrPort := destUDPAddr.AddrPort()
					destAddrPort = netip.AddrPortFrom(
						destAddrPort.Addr().Unmap(),
						destAddrPort.Port(),
					)
					runClient(destAddrPort)
					return nil
				},
			},
		},
	}

	if err := root.ParseAndRun(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

var serverFlags struct {
	port      int
	batch     int
	maxMsgLen int
	uro       bool
	memLimit  uintptr
}

func buildServerFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	fs.IntVar(&serverFlags.port, "port", 9999, "UDP port to listen on")
	fs.IntVar(&serverFlags.batch, "batch", 64, "number of packets to read per batch")
	fs.IntVar(&serverFlags.maxMsgLen, "maxlen", math.MaxUint16, "maximum length of each UDP message to receive")
	fs.BoolVar(&serverFlags.uro, "uro", false, "enable UDP RSC Offload (URO)")
	fs.Func("mem", "memory limit for RIO buffers (e.g. 512k, 1m, 16m)", func(s string) error {
		var err error
		serverFlags.memLimit, err = parseSize(s)
		return err
	})
	return fs
}

var clientFlags struct {
	port      int
	batchSize int
	msgLen    int
	uso       bool
	memLimit  uintptr
}

func buildClientFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	fs.IntVar(&clientFlags.port, "port", 9999, "UDP port to send to")
	fs.IntVar(&clientFlags.batchSize, "batch", 64, "number of packets to send per batch")
	fs.IntVar(&clientFlags.msgLen, "len", 1312, "length of each UDP message to send")
	fs.BoolVar(&clientFlags.uso, "uso", true, "enable UDP Segmentation Offload (USO)")
	fs.Func("mem", "memory limit for RIO buffers (e.g. 512k, 1m, 16m)", func(s string) error {
		var err error
		clientFlags.memLimit, err = parseSize(s)
		return err
	})
	return fs
}

func runServer() {
	opts := []rioconn.UDPOption{
		rioconn.URO(serverFlags.uro),
		rioconn.RxMemoryLimit(serverFlags.memLimit),
		rioconn.TxMemoryLimit(serverFlags.memLimit),
		rioconn.RxMaxPayloadLen(uintptr(serverFlags.maxMsgLen)),
	}

	conn, err := rioconn.ListenUDP("udp4", &net.UDPAddr{Port: serverFlags.port}, opts...)
	if err != nil {
		fmt.Printf("Failed to create connection: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Server listening on %v\n", conn.LocalAddrPort())

	msgs := make([]ipv6.Message, serverFlags.batch)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].Buffers[0] = make([]byte, conn.Config().Rx().MaxPayloadLen())
	}

	var mu sync.Mutex
	var sessionID uint64
	var sessionPackets, sessionBytes uint64
	var sessionStart time.Time
	var lastReceived time.Time

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			if !lastReceived.IsZero() && time.Since(lastReceived) >= 1*time.Second && sessionPackets > 0 {
				dt := lastReceived.Sub(sessionStart)
				if dt > 0 {
					pps := float64(sessionPackets) / dt.Seconds()
					bitrate, units := formatBitrate(float64(sessionBytes) * 8 / dt.Seconds())
					fmt.Printf("[avg] %.2f Mpps %.2f %s over %.1fs\n", pps/1e6, bitrate, units, dt.Seconds())
				}
				sessionPackets = 0
				sessionBytes = 0
				lastReceived = time.Time{}
			}
			mu.Unlock()
		}
	}()

	var totalPackets, totalBytes uint64
	var lastPackets, lastBytes uint64
	lastReport := time.Now()

	for {
		n, err := conn.ReadBatch(msgs, 0)
		if err != nil {
			fmt.Printf("ReadBatch error: %v\n", err)
			os.Exit(1)
		}

		now := time.Now()
		mu.Lock()
		if lastReceived.IsZero() {
			sessionStart = now
			sessionID++
			fmt.Printf("\nSession %d started by %v\n", sessionID, msgs[0].Addr)
		}
		for i := 0; i < n; i++ {
			totalBytes += uint64(msgs[i].N)
			sessionBytes += uint64(msgs[i].N)
		}
		totalPackets += uint64(n)
		sessionPackets += uint64(n)
		lastReceived = now
		mu.Unlock()

		if pktsDelta := totalPackets - lastPackets; pktsDelta > 1024 {
			if now.Sub(lastReport) >= time.Second {
				dt := now.Sub(lastReport)
				bytesDelta := totalBytes - lastBytes
				pps := float64(pktsDelta) / dt.Seconds()
				bitrate, units := formatBitrate(float64(bytesDelta) * 8 / dt.Seconds())
				fmt.Printf("%.2f Mpps %.2f %s\n", pps/1e6, bitrate, units)
				lastPackets = totalPackets
				lastBytes = totalBytes
				lastReport = now
			}
		}
	}
}

func runClient(destAddrPort netip.AddrPort) {
	opts := []rioconn.UDPOption{
		rioconn.USO(clientFlags.uso),
		rioconn.RxMemoryLimit(clientFlags.memLimit),
		rioconn.TxMemoryLimit(clientFlags.memLimit),
		rioconn.TxMaxPayloadLen(uintptr(clientFlags.msgLen)),
	}

	conn, err := rioconn.ListenUDP("udp4", &net.UDPAddr{}, opts...)
	if err != nil {
		fmt.Printf("Failed to create connection: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Client sending to %v from %v\n", destAddrPort, conn.LocalAddrPort())

	buffs := make([][]byte, clientFlags.batchSize)
	for i := range buffs {
		buffs[i] = make([]byte, clientFlags.msgLen)
		for j := range buffs[i] {
			buffs[i][j] = byte(i + j)
		}
	}

	var totalPackets, totalBytes uint64
	var lastPackets, lastBytes uint64
	start := time.Now()
	lastReport := start
	endTime := start.Add(30 * time.Second)

	for {
		if err := conn.WriteBatchTo(buffs, destAddrPort, packet.GeneveHeader{}, 0); err != nil {
			fmt.Fprintf(os.Stderr, "WriteBatchTo error: %v\n", err)
			break
		}

		totalPackets += uint64(len(buffs))
		totalBytes += uint64(len(buffs) * clientFlags.msgLen)

		if pktsDelta := totalPackets - lastPackets; pktsDelta > 1024 {
			now := time.Now()
			if now.After(endTime) {
				break
			}
			if dt := now.Sub(lastReport); dt >= time.Second {
				bytesDelta := totalBytes - lastBytes
				pps := float64(pktsDelta) / dt.Seconds()
				bitrate, units := formatBitrate(float64(bytesDelta) * 8 / dt.Seconds())
				fmt.Printf("%.2f Mpps %.2f %s\n", pps/1e6, bitrate, units)
				lastPackets = totalPackets
				lastBytes = totalBytes
				lastReport = now
			}
		}
	}

	elapsed := time.Since(start).Seconds()
	pps := float64(totalPackets) / elapsed
	bitrate, units := formatBitrate(float64(totalBytes) * 8 / elapsed)
	fmt.Printf("\n[avg] %.2f Mpps %.2f %s over %.1fs\n", pps/1e6, bitrate, units, endTime.Sub(start).Seconds())
}

func parseSize(s string) (uintptr, error) {
	if s = strings.TrimSpace(s); s == "" {
		return 0, fmt.Errorf("empty size")
	}
	multiplier := uintptr(1)

	last := s[len(s)-1]
	switch last {
	case 'k', 'K':
		multiplier = 1 << 10
		s = s[:len(s)-1]
	case 'm', 'M':
		multiplier = 1 << 20
		s = s[:len(s)-1]
	case 'g', 'G':
		multiplier = 1 << 30
		s = s[:len(s)-1]
	}

	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}

	return uintptr(n) * multiplier, nil
}

func formatBitrate[T float64 | int64](bps T) (n float64, unit string) {
	const (
		Kbps = 1000
		Mbps = 1000 * Kbps
		Gbps = 1000 * Mbps
	)

	switch {
	case float64(bps) >= 0.9*Gbps:
		return float64(bps) / float64(Gbps), "Gbps"
	case float64(bps) >= 0.9*Mbps:
		return float64(bps) / float64(Mbps), "Mbps"
	case float64(bps) >= 0.9*Kbps:
		return float64(bps) / float64(Kbps), "Kbps"
	default:
		return float64(bps), "bps"
	}
}
