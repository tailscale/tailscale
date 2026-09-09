package socks5

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
)

// TestUDPConcurrentClientAddrRace hammers the UDP associate path with
// back-to-back requests to several targets without waiting for each
// response, so the client->target goroutine keeps writing udpClientAddr
// while the per-target target->client goroutines read it.
func TestUDPConcurrentClientAddrRace(t *testing.T) {
	const echoServers = 4
	echo := make([]net.PacketConn, echoServers)
	for i := range echo {
		ln, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go udpEchoServer(ln)
		echo[i] = ln
	}
	defer func() {
		for _, l := range echo {
			l.Close()
		}
	}()

	socks5ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socks5ln.Addr().(*net.TCPAddr).Port
	go socks5Server(socks5ln)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{socks5Version, 0x01, noAuthRequired}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	target := socksAddr{addrType: ipv4, addr: "0.0.0.0", port: 0}
	tp, err := target.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(append([]byte{socks5Version, byte(udpAssociate), 0x00}, tp...)); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, err := parseSocksAddr(bytes.NewReader(buf[3:n]))
	if err != nil {
		t.Fatal(err)
	}
	ua, err := net.ResolveUDPAddr("udp", proxyAddr.hostPort())
	if err != nil {
		t.Fatal(err)
	}
	uc, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	// Drain responses in the background; we don't care about ordering.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 2048)
		for {
			if _, err := uc.Read(b); err != nil {
				return
			}
		}
	}()

	// Fire without waiting, so writes and reads of udpClientAddr overlap.
	for round := 0; round < 200; round++ {
		for i := range echo {
			p := echo[i].LocalAddr().(*net.UDPAddr).Port
			a := socksAddr{addrType: ipv4, addr: "127.0.0.1", port: uint16(p)}
			pkt, err := (&udpRequest{addr: a}).marshal()
			if err != nil {
				t.Fatal(err)
			}
			pkt = append(pkt, fmt.Appendf(nil, "r%d-%d", round, i)...)
			if _, err := uc.Write(pkt); err != nil {
				t.Fatal(err)
			}
		}
	}
	uc.Close()
	wg.Wait()
}
