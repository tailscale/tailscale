// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlbase

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	chp "golang.org/x/crypto/chacha20poly1305"
)

func FuzzWholeMessageLocked(f *testing.F) {
	f.Add([]byte{4, 0x00, 0x02})
	// One complete record frame (3-byte header + 2-byte payload)
	f.Add([]byte{byte(msgTypeRecord), 0x00, 0x02, 0xaa, 0xbb})
	// Two consecutive frames
	f.Add([]byte{byte(msgTypeRecord), 0x00, 0x02, 0xaa, 0xbb, byte(msgTypeRecord), 0x00, 0x01, 0xcc})
	// Empty buffer and zero-length frame
	f.Add([]byte{})
	f.Add([]byte{byte(msgTypeRecord), 0x00, 0x00})
	// A length field of 0xffff, far beyond any possible buffer
	f.Add([]byte{byte(msgTypeRecord), 0xff, 0xff})
	// rx.next (from last byte) beyond rx.n, making available negative
	f.Add([]byte{byte(msgTypeRecord), 0x00, 0x00, 0xff})
	// A frame that exactly fills maxMessageSize (3-byte header + 0x0ffd payload), and one byte over
	f.Add(append([]byte{byte(msgTypeRecord), 0x0f, 0xfd}, make([]byte, maxMessageSize-headerLen)...))
	f.Add(append([]byte{byte(msgTypeRecord), 0x0f, 0xfe}, make([]byte, maxMessageSize-headerLen-1)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		var c Conn
		c.rx.buf = new(maxMsgBuffer)
		n := min(len(data), maxMessageSize)
		copy(c.rx.buf[:], data[:n])
		c.rx.n = n
		if len(data) > 0 {
			c.rx.next = int(data[len(data)-1]) % (maxMessageSize + 1)
		}
		_ = c.wholeMessageLocked()
	})
}

// newTestAEAD returns an AEAD keyed with all-zeros for use in fuzz
// tests. The cipher is stateless, so it can be shared across iterations
// as long as each iteration uses a fresh Conn (fresh nonce).
func newTestAEAD(tb testing.TB) cipher.AEAD {
	key := make([]byte, chp.KeySize)
	aead, err := chp.New(key)
	if err != nil {
		tb.Fatal(err)
	}
	return aead
}

// sealFrame produces one valid Noise record frame containing plaintext,
// encrypted with nonce. The returned slice is freshly allocated so it
// can be used as fuzz seed data.
func sealFrame(aead cipher.AEAD, nonce *nonce, plaintext []byte) []byte {
	buf := new(maxMsgBuffer)
	buf[0] = msgTypeRecord
	binary.BigEndian.PutUint16(buf[1:headerLen], uint16(len(plaintext)+chp.Overhead))
	ret := aead.Seal(buf[:headerLen], nonce[:], plaintext, nil)
	return slices.Clone(ret)
}

func FuzzDecryptLocked(f *testing.F) {
	aead := newTestAEAD(f)

	var nonce nonce
	f.Add([]byte{4, 2, 0, 3, 6})
	// Frames with a wrong message type byte, hitting the type-check error path
	f.Add([]byte{0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x01, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x03, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	// Ciphertext shorter than the AEAD overhead, all reaching Open failure
	f.Add([]byte{byte(msgTypeRecord), 0x00, 0x00})
	f.Add([]byte{byte(msgTypeRecord), 0x00, 0x01, 0xaa})
	f.Add(append([]byte{byte(msgTypeRecord), 0x00, 0x0f}, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))
	// Exactly 16 bytes of ciphertext with a bogus tag
	f.Add(append([]byte{byte(msgTypeRecord), 0x00, 0x10}, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))
	// A length field of 0xffff with only 100 bytes of ciphertext behind it
	f.Add(append([]byte{byte(msgTypeRecord), 0xff, 0xff}, make([]byte, 100)...))
	// Seed with a validly-encrypted frame so the successful Open path,
	// nonce increment and plaintext consumption are reached.
	f.Add(sealFrame(aead, &nonce, []byte("hello")))
	// A valid empty-plaintext frame at nonce 0, for the zero-length success path
	f.Add(sealFrame(aead, &nonce, nil))
	nonce.Increment()
	f.Add(sealFrame(aead, &nonce, nil))

	f.Fuzz(func(t *testing.T, msg []byte) {
		if len(msg) < headerLen {
			return
		}
		var c Conn
		c.rx.cipher = aead
		_ = c.decryptLocked(msg)
	})
}

// fuzzConn is a net.Conn that yields the fuzzed bytes and then EOF.
type fuzzConn struct {
	r *bytes.Reader
}

func (fuzzConn) Write([]byte) (int, error) { return 0, nil }
func (c fuzzConn) Close() error            { return nil }
func (c fuzzConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
func (fuzzConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (fuzzConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (fuzzConn) SetDeadline(time.Time) error      { return nil }
func (fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (fuzzConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "" }

// recordConn captures everything written to it, and optionally fails a
// chosen write. Used to drive Conn.Write without real I/O.
type recordConn struct {
	bs     bytes.Buffer
	writes int
	failAt int // index of the write that should fail; -1 for never
}

func (c *recordConn) Write(p []byte) (int, error) {
	if c.failAt == c.writes {
		c.writes++
		return 0, errWriteFailure{}
	}
	c.writes++
	return c.bs.Write(p)
}
func (*recordConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (*recordConn) Close() error                    { return nil }
func (*recordConn) LocalAddr() net.Addr             { return dummyAddr{} }
func (*recordConn) RemoteAddr() net.Addr            { return dummyAddr{} }
func (*recordConn) SetDeadline(time.Time) error     { return nil }
func (*recordConn) SetReadDeadline(time.Time) error { return nil }
func (*recordConn) SetWriteDeadline(time.Time) error {
	return nil
}

type errWriteFailure struct{}

func (errWriteFailure) Error() string { return "write failure" }

func FuzzConnRead(f *testing.F) {
	aead := newTestAEAD(f)

	var nonce nonce
	frame1 := sealFrame(aead, &nonce, []byte("hello"))
	nonce.Increment()
	frame2 := sealFrame(aead, &nonce, nil)
	twoFrames := append(frame1, frame2...)

	// Fuzz data follows the two prepended frames, so it is consumed at nonce 2
	nonce.Increment()
	// A third valid frame so the success path is reached again (the fuzzer can't forge AEAD)
	f.Add(sealFrame(aead, &nonce, []byte("x")))
	// In-size frames with a wrong type byte
	f.Add(append([]byte{byte(msgTypeError), 0x00, 0x13}, make([]byte, 19)...))
	f.Add(append([]byte{byte(msgTypeInitiation), 0x00, 0x13}, make([]byte, 19)...))
	// Short and full-size garbage ciphertexts, hitting Open failure
	f.Add([]byte{byte(msgTypeRecord), 0x00, 0x00})
	f.Add([]byte{byte(msgTypeRecord), 0x00, 0x01, 0xaa})
	f.Add(append([]byte{byte(msgTypeRecord), 0x00, 0x10}, make([]byte, 16)...))
	f.Add(append([]byte{byte(msgTypeRecord), 0x00, 0x10}, bytes.Repeat([]byte{0xab}, 16)...))
	// Length-field boundaries of readNLocked: exactly maxMessageSize, and just over
	f.Add(append([]byte{byte(msgTypeRecord), 0x0f, 0xfd}, make([]byte, maxMessageSize-headerLen)...))
	f.Add(append([]byte{byte(msgTypeRecord), 0x0f, 0xfd}, make([]byte, maxMessageSize-headerLen-1)...))
	f.Add([]byte{byte(msgTypeRecord), 0x0f, 0xfe})
	f.Add([]byte{byte(msgTypeRecord), 0x10, 0x00})
	f.Add([]byte{byte(msgTypeRecord), 0xff, 0xff})

	f.Add(twoFrames)
	f.Add(bytes.Repeat([]byte{'a'}, maxMessageSize+10))

	f.Fuzz(func(t *testing.T, data []byte) {
		var c Conn
		c.rx.cipher = aead
		stream := append(slices.Clone(twoFrames), data...)
		c.conn = &fuzzConn{r: bytes.NewReader(stream)}

		var buf [maxPlaintextSize]byte
		for range 3 {
			if _, err := c.Read(buf[:]); err != nil {
				break
			}
		}
	})
}

func FuzzConnWrite(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte{'a'}, maxPlaintextSize+1)) // force frame splitting
	// Even final byte: no forced write failure, reaching the success path
	f.Add([]byte("hell"))
	// Successful multi-frame chunking of an over-length payload
	f.Add(append(bytes.Repeat([]byte{'b'}, maxPlaintextSize), 'c', 'd'))
	// An empty write, skipping the frame loop entirely
	f.Add([]byte{})

	aead := newTestAEAD(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		var c Conn
		c.tx.cipher = aead
		rec := &recordConn{failAt: -1}
		if len(data) > 0 && data[len(data)-1]%2 == 1 {
			// Force the first frame write to fail, exercising the errPartialWrite fatal-error path
			rec.failAt = 0
		}
		c.conn = rec

		_, _ = c.Write(data)
		// A second write must observe the recorded error (or succeed)
		_, _ = c.Write([]byte("x"))
	})
}
