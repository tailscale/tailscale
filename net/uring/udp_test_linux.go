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
