// +build linux

package uring

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
)

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
			buf := make([]byte, 0, 512)
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				t.Errorf("failed to read on server: %v", err)
				break
			}
			t.Logf("%s, %v, %v", buf, n, err)
		}
	}()
	return nil
}

func NewUDPIOURingConnTestServer(t *testing.T) error {
	conn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		return err
	}
	go func() {
		for {
			buf := make([]byte, 0, 512)
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				t.Errorf("failed to read on server: %v", err)
				break
			}
			t.Logf("%s, %v, %v", buf, n, err)
		}
	}()
	return nil
}

func TestUDPConn(t *testing.T) {
	err := NewUDPTestServer(t)
	if err != nil {
		t.Errorf("failed to start UDPServer: %v", err)
	}
	udpConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Errorf("failed to start udp connection to server: %v", err)
	}
	defer udpConn.Close()

	conn, err := NewUDPConn(udpConn)
	if err != nil {
		t.Errorf("failed to start io_uring udp connection: %v", err)
	}
	defer conn.Close()

	content := []byte("a test string to check udpconn works 😀 with non-unicode input")
	n, err := conn.WriteTo(content, serverAddr)
	if err != nil {
		t.Errorf("conn write failed: %v", err)
	}
	if n != len(content) {
		t.Errorf("written len mismatch: want %v, got %v", len(content), n)
	}

	// Test many writes at once
	for i := 0; i < 1000; i++ {
		n, err := conn.WriteTo(content, serverAddr)
		if err != nil {
			t.Errorf("conn write failed: %v", err)
		}
		if n != len(content) {
			t.Errorf("written len mismatch: want %v, got %v", len(content), n)
		}
	}
}

func TestFile(t *testing.T) {
	tmpFile, err := ioutil.TempFile(".", "uring-test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})
	f, err := NewFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to create io_uring file: %v", err)
	}
	content := []byte("a test string to check writing works 😀 with non-unicode input")
	n, err := f.Write(content)
	if n != len(content) {
		t.Errorf("mismatch between written len and content len: want %d, got %d", len(content), n)
	}
	if err != nil {
		t.Errorf("file write failed: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Errorf("file close failed: %v", err)
	}
}
