// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlbase

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	chp "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/nettest"
	tsnettest "tailscale.com/net/nettest"
	"tailscale.com/types/key"
)

const testProtocolVersion = 1

func TestMessageSize(t *testing.T) {
	// This test is a regression guard against someone looking at
	// maxCiphertextSize, going "huh, we could be more efficient if it
	// were larger, and accidentally violating the Noise spec. Do not
	// change this max value, it's a deliberate limitation of the
	// cryptographic protocol we use (see Section 3 "Message Format"
	// of the Noise spec).
	const max = 65535
	if maxCiphertextSize > max {
		t.Fatalf("max ciphertext size is %d, which is larger than the maximum noise message size %d", maxCiphertextSize, max)
	}
}

func TestConnBasic(t *testing.T) {
	client, server := pair(t)

	sb := sinkReads(server)

	want := "test"
	if _, err := io.WriteString(client, want); err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	client.Close()

	if got := sb.String(4); got != want {
		t.Fatalf("wrong content received: got %q, want %q", got, want)
	}
	if err := sb.Error(); err != io.EOF {
		t.Fatal("client close wasn't seen by server")
	}
	if sb.Total() != 4 {
		t.Fatalf("wrong amount of bytes received: got %d, want 4", sb.Total())
	}
}

// bufferedWriteConn wraps a net.Conn and gives control over how
// Writes get batched out.
type bufferedWriteConn struct {
	net.Conn
	w           *bufio.Writer
	manualFlush bool
}

func (c *bufferedWriteConn) Write(bs []byte) (int, error) {
	n, err := c.w.Write(bs)
	if err == nil && !c.manualFlush {
		err = c.w.Flush()
	}
	return n, err
}

// TestFastPath exercises the Read codepath that can receive multiple
// Noise frames at once and decode each in turn without making another
// syscall.
func TestFastPath(t *testing.T) {
	s1, s2 := tsnettest.NewConn("noise", 128000)
	b := &bufferedWriteConn{s1, bufio.NewWriterSize(s1, 10000), false}
	client, server := pairWithConns(t, b, s2)

	b.manualFlush = true

	sb := sinkReads(server)

	const packets = 10
	s := "test"
	for i := 0; i < packets; i++ {
		// Many separate writes, to force separate Noise frames that
		// all get buffered up and then all sent as a single slice to
		// the server.
		if _, err := io.WriteString(client, s); err != nil {
			t.Fatalf("client write1 failed: %v", err)
		}
	}
	if err := b.w.Flush(); err != nil {
		t.Fatalf("client flush failed: %v", err)
	}
	client.Close()

	want := strings.Repeat(s, packets)
	if got := sb.String(len(want)); got != want {
		t.Fatalf("wrong content received: got %q, want %q", got, want)
	}
	if err := sb.Error(); err != io.EOF {
		t.Fatalf("client close wasn't seen by server")
	}
}

// Writes things larger than a single Noise frame, to check the
// chunking on the encoder and decoder.
func TestBigData(t *testing.T) {
	client, server := pair(t)

	serverReads := sinkReads(server)
	clientReads := sinkReads(client)

	const sz = 15 * 1024 // 15KiB
	clientStr := strings.Repeat("abcde", sz/5)
	serverStr := strings.Repeat("fghij", sz/5*2)

	if _, err := io.WriteString(client, clientStr); err != nil {
		t.Fatalf("writing client>server: %v", err)
	}
	if _, err := io.WriteString(server, serverStr); err != nil {
		t.Fatalf("writing server>client: %v", err)
	}

	if serverGot := serverReads.String(sz); serverGot != clientStr {
		t.Error("server didn't receive what client sent")
	}
	if clientGot := clientReads.String(2 * sz); clientGot != serverStr {
		t.Error("client didn't receive what server sent")
	}

	getNonce := func(n [chp.NonceSize]byte) uint64 {
		if binary.BigEndian.Uint32(n[:4]) != 0 {
			panic("unexpected nonce")
		}
		return binary.BigEndian.Uint64(n[4:])
	}

	// Reach into the Conns and verify the cipher nonces advanced as
	// expected.
	if getNonce(client.tx.nonce) != getNonce(server.rx.nonce) {
		t.Error("desynchronized client tx nonce")
	}
	if getNonce(server.tx.nonce) != getNonce(client.rx.nonce) {
		t.Error("desynchronized server tx nonce")
	}
	if n := getNonce(client.tx.nonce); n != 4 {
		t.Errorf("wrong client tx nonce, got %d want 4", n)
	}
	if n := getNonce(server.tx.nonce); n != 8 {
		t.Errorf("wrong client tx nonce, got %d want 8", n)
	}
}

// readerConn wraps a net.Conn and routes its Reads through a separate
// io.Reader.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c readerConn) Read(bs []byte) (int, error) { return c.r.Read(bs) }

// Check that the receiver can handle not being able to read an entire
// frame in a single syscall.
func TestDataTrickle(t *testing.T) {
	s1, s2 := tsnettest.NewConn("noise", 128000)
	client, server := pairWithConns(t, s1, readerConn{s2, iotest.OneByteReader(s2)})
	serverReads := sinkReads(server)

	const sz = 10000
	clientStr := strings.Repeat("abcde", sz/5)
	if _, err := io.WriteString(client, clientStr); err != nil {
		t.Fatalf("writing client>server: %v", err)
	}

	serverGot := serverReads.String(sz)
	if serverGot != clientStr {
		t.Error("server didn't receive what client sent")
	}
}

func TestConnStd(t *testing.T) {
	// You can run this test manually, and noise.Conn should pass all
	// of them except for TestConn/PastTimeout,
	// TestConn/FutureTimeout, TestConn/ConcurrentMethods, because
	// those tests assume that write errors are recoverable, and
	// they're not on our Conn due to cipher security.
	t.Skip("not all tests can pass on this Conn, see https://github.com/golang/go/issues/46977")
	nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
		s1, s2 := tsnettest.NewConn("noise", 4096)
		controlKey := key.NewMachine()
		machineKey := key.NewMachine()
		serverErr := make(chan error, 1)
		go func() {
			var err error
			c2, err = Server(context.Background(), s2, controlKey, nil)
			serverErr <- err
		}()
		c1, err = Client(context.Background(), s1, machineKey, controlKey.Public(), testProtocolVersion)
		if err != nil {
			s1.Close()
			s2.Close()
			return nil, nil, nil, fmt.Errorf("connecting client: %w", err)
		}
		if err := <-serverErr; err != nil {
			c1.Close()
			s1.Close()
			s2.Close()
			return nil, nil, nil, fmt.Errorf("connecting server: %w", err)
		}
		return c1, c2, func() {
			c1.Close()
			c2.Close()
		}, nil
	})
}

// tests that the idle memory overhead of a Conn blocked in a read is
// reasonable (under 2K). It was previously over 8KB with two 4KB
// buffers for rx/tx. This make sure we don't regress. Hopefully it
// doesn't turn into a flaky test. If so, const max can be adjusted,
// or it can be deleted or reworked.
func TestConnMemoryOverhead(t *testing.T) {
	num := 1000
	if testing.Short() {
		num = 100
	}
	ng0 := runtime.NumGoroutine()

	runtime.GC()
	var ms0 runtime.MemStats
	runtime.ReadMemStats(&ms0)

	var closers []io.Closer
	closeAll := func() {
		for _, c := range closers {
			c.Close()
		}
		closers = nil
	}
	defer closeAll()

	for i := 0; i < num; i++ {
		client, server := pair(t)
		closers = append(closers, client, server)
		go func() {
			var buf [1]byte
			client.Read(buf[:])
		}()
	}

	t0 := time.Now()
	deadline := t0.Add(3 * time.Second)
	var ngo int
	for time.Now().Before(deadline) {
		runtime.GC()
		ngo = runtime.NumGoroutine()
		if ngo >= num {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ngo < num {
		t.Fatalf("only %v goroutines; expected %v+", ngo, num)
	}
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	growthTotal := int64(ms.HeapAlloc) - int64(ms0.HeapAlloc)
	growthEach := float64(growthTotal) / float64(num)
	t.Logf("Alloced %v bytes, %.2f B/each", growthTotal, growthEach)
	const max = 2000
	if growthEach > max {
		t.Errorf("allocated more than expected; want max %v bytes/each", max)
	}

	closeAll()

	// And make sure our goroutines go away too.
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ngo = runtime.NumGoroutine()
		if ngo < ng0+num/10 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ngo >= ng0+num/10 {
		t.Errorf("goroutines didn't go back down; started at %v, now %v", ng0, ngo)
	}
}

// mkConns creates synthetic Noise Conns wrapping the given net.Conns.
// This function is for testing just the Conn transport logic without
// having to muck about with Noise handshakes.
func mkConns(s1, s2 net.Conn) (*Conn, *Conn) {
	var k1, k2 [chp.KeySize]byte
	if _, err := rand.Read(k1[:]); err != nil {
		panic(err)
	}
	if _, err := rand.Read(k2[:]); err != nil {
		panic(err)
	}

	ret1 := &Conn{
		conn: s1,
		tx:   txState{cipher: newCHP(k1)},
		rx:   rxState{cipher: newCHP(k2)},
	}
	ret2 := &Conn{
		conn: s2,
		tx:   txState{cipher: newCHP(k2)},
		rx:   rxState{cipher: newCHP(k1)},
	}

	return ret1, ret2
}

type readSink struct {
	r io.Reader

	cond *sync.Cond
	sync.Mutex
	bs  bytes.Buffer
	err error
}

func sinkReads(r io.Reader) *readSink {
	ret := &readSink{
		r: r,
	}
	ret.cond = sync.NewCond(&ret.Mutex)
	go func() {
		var buf [4096]byte
		for {
			n, err := r.Read(buf[:])
			ret.Lock()
			ret.bs.Write(buf[:n])
			if err != nil {
				ret.err = err
			}
			ret.cond.Broadcast()
			ret.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return ret
}

func (s *readSink) String(total int) string {
	s.Lock()
	defer s.Unlock()
	for s.bs.Len() < total && s.err == nil {
		s.cond.Wait()
	}
	if s.err != nil {
		total = s.bs.Len()
	}
	return string(s.bs.Bytes()[:total])
}

func (s *readSink) Error() error {
	s.Lock()
	defer s.Unlock()
	for s.err == nil {
		s.cond.Wait()
	}
	return s.err
}

func (s *readSink) Total() int {
	s.Lock()
	defer s.Unlock()
	return s.bs.Len()
}

func pairWithConns(t *testing.T, clientConn, serverConn net.Conn) (*Conn, *Conn) {
	var (
		controlKey = key.NewMachine()
		machineKey = key.NewMachine()
		server     *Conn
		serverErr  = make(chan error, 1)
	)
	go func() {
		var err error
		server, err = Server(context.Background(), serverConn, controlKey, nil)
		serverErr <- err
	}()

	client, err := Client(context.Background(), clientConn, machineKey, controlKey.Public(), testProtocolVersion)
	if err != nil {
		t.Fatalf("client connection failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server connection failed: %v", err)
	}
	return client, server
}

func pair(t *testing.T) (*Conn, *Conn) {
	s1, s2 := tsnettest.NewConn("noise", 128000)
	return pairWithConns(t, s1, s2)
}
