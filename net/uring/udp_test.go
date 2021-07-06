package uring

import (
	"net"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestUDPSendRecv(t *testing.T) {
	if !Available() {
		t.Skip("io_uring not available")
	}
	c := qt.New(t)

	listen, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 9999})
	t.Cleanup(func() { listen.Close() })
	c.Assert(err, qt.IsNil)

	conn, err := NewUDPConn(listen)
	t.Cleanup(func() { conn.Close() })
	if err != nil {
		t.Skipf("io_uring not available: %v", err)
	}
	addr := listen.LocalAddr()
	sendBuf := make([]byte, 200)
	for i := range sendBuf {
		sendBuf[i] = byte(i)
	}
	recvBuf := make([]byte, 200)

	// Write one direction.
	_, err = conn.WriteTo(sendBuf, addr)
	c.Assert(err, qt.IsNil)
	n, ipp, err := conn.ReadFromNetaddr(recvBuf)
	c.Assert(err, qt.IsNil)
	c.Assert(recvBuf[:n], qt.DeepEquals, sendBuf)

	// Write the other direction, to check that ipp is correct.
	_, err = conn.WriteTo(sendBuf, ipp.UDPAddr())
	c.Assert(err, qt.IsNil)
	n, _, err = conn.ReadFromNetaddr(recvBuf)
	c.Assert(err, qt.IsNil)
	c.Assert(recvBuf[:n], qt.DeepEquals, sendBuf)
}

// TODO(jknodt): maybe delete the test below because it's redundant

const TestPort = 3636

var serverAddr = &net.UDPAddr{
	Port: TestPort,
}

func NewUDPTestServer(t *testing.T) error {
	conn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		return err
	}
	go func() {
		for {
			buf := make([]byte, 512)
			_, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				t.Errorf("failed to read on server: %v", err)
				break
			}
		}
	}()
	return nil
}

func TestUDPConn(t *testing.T) {
	if !Available() {
		t.Skip("io_uring not available")
	}
	c := qt.New(t)
	// TODO add a closer here
	err := NewUDPTestServer(t)
	c.Assert(err, qt.IsNil)
	udpConn, err := net.DialUDP("udp", nil, serverAddr)
	c.Assert(err, qt.IsNil)
	defer udpConn.Close()

	conn, err := NewUDPConn(udpConn)
	c.Assert(err, qt.IsNil)
	defer conn.Close()

	content := []byte("a test string to check udpconn works 😀 with non-unicode input")
	n, err := conn.WriteTo(content, serverAddr)
	c.Assert(err, qt.IsNil)
	if n != len(content) {
		t.Errorf("written len mismatch: want %v, got %v", len(content), n)
	}

	// Test many writes at once
	for i := 0; i < 1000; i++ {
		n, err := conn.WriteTo(content, serverAddr)
		c.Assert(err, qt.IsNil)
		if n != len(content) {
			t.Errorf("written len mismatch: want %v, got %v", len(content), n)
		}
	}
}
