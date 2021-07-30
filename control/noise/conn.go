// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package noise implements the base transport of the Tailscale 2021
// control protocol.
//
// The base transport implements Noise IK, instantiated with
// Curve25519, ChaCha20Poly1305 and BLAKE2s.
package noise

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	chp "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"tailscale.com/types/key"
)

const (
	// maxMessageSize is the maximum size of a protocol frame on the
	// wire, including header and payload.
	maxMessageSize = 4096
	// maxCiphertextSize is the maximum amount of ciphertext bytes
	// that one protocol frame can carry, after framing.
	maxCiphertextSize = maxMessageSize - headerLen
	// maxPlaintextSize is the maximum amount of plaintext bytes that
	// one protocol frame can carry, after encryption and framing.
	maxPlaintextSize = maxCiphertextSize - poly1305.TagSize
)

// A Conn is a secured Noise connection. It implements the net.Conn
// interface, with the unusual trait that any write error (including a
// SetWriteDeadline induced i/o timeout) causes all future writes to
// fail.
type Conn struct {
	conn          net.Conn
	version       uint16
	peer          key.Public
	handshakeHash [blake2s.Size]byte
	rx            rxState
	tx            txState
}

// rxState is all the Conn state that Read uses.
type rxState struct {
	sync.Mutex
	cipher    cipher.AEAD
	nonce     [chp.NonceSize]byte
	buf       [maxMessageSize]byte
	n         int    // number of valid bytes in buf
	next      int    // offset of next undecrypted packet
	plaintext []byte // slice into buf of decrypted bytes
}

// txState is all the Conn state that Write uses.
type txState struct {
	sync.Mutex
	cipher cipher.AEAD
	nonce  [chp.NonceSize]byte
	buf    [maxMessageSize]byte
	err    error // records the first partial write error for all future calls
}

// ProtocolVersion returns the protocol version that was used to
// establish this Conn.
func (c *Conn) ProtocolVersion() int {
	return int(c.version)
}

// HandshakeHash returns the Noise handshake hash for the connection,
// which can be used to bind other messages to this connection
// (i.e. to ensure that the message wasn't replayed from a different
// connection).
func (c *Conn) HandshakeHash() [blake2s.Size]byte {
	return c.handshakeHash
}

// Peer returns the peer's long-term public key.
func (c *Conn) Peer() key.Public {
	return c.peer
}

// validNonce reports whether nonce is in the valid range for use: 0
// through 2^64-2.
func validNonce(nonce []byte) bool {
	return binary.BigEndian.Uint32(nonce[:4]) == 0 && binary.BigEndian.Uint64(nonce[4:]) != invalidNonce
}

// readNLocked reads into c.rx.buf until buf contains at least total
// bytes. Returns a slice of the available bytes in rxBuf, or an
// error if fewer than total bytes are available.
func (c *Conn) readNLocked(total int) ([]byte, error) {
	if total > maxMessageSize {
		return nil, errReadTooBig{total}
	}
	for {
		if total <= c.rx.n {
			return c.rx.buf[:c.rx.n], nil
		}

		n, err := c.conn.Read(c.rx.buf[c.rx.n:])
		c.rx.n += n
		if err != nil {
			return nil, err
		}
	}
}

// decryptLocked decrypts msg (which is header+ciphertext) in-place
// and sets c.rx.plaintext to the decrypted bytes.
func (c *Conn) decryptLocked(msg []byte) (err error) {
	if hdrVersion(msg) != c.version {
		return fmt.Errorf("received message with unexpected protocol version %d, want %d", hdrVersion(msg), c.version)
	}
	if hdrType(msg) != msgTypeRecord {
		return fmt.Errorf("received message with unexpected type %d, want %d", hdrType(msg), msgTypeRecord)
	}
	// We don't check the length field here, because the caller
	// already did in order to figure out how big the msg slice should
	// be.
	ciphertext := msg[headerLen:]

	if !validNonce(c.rx.nonce[:]) {
		return errCipherExhausted{}
	}

	c.rx.plaintext, err = c.rx.cipher.Open(ciphertext[:0], c.rx.nonce[:], ciphertext, nil)

	// Safe to increment the nonce here, because we checked for nonce
	// wraparound above.
	binary.BigEndian.PutUint64(c.rx.nonce[4:], 1+binary.BigEndian.Uint64(c.rx.nonce[4:]))

	if err != nil {
		// Once a decryption has failed, our Conn is no longer
		// synchronized with our peer. Nuke the cipher state to be
		// safe, so that no further decryptions are attempted. Future
		// read attempts will return net.ErrClosed.
		c.rx.cipher = nil
	}
	return err
}

// encryptLocked encrypts plaintext into c.tx.buf (including the
// packet header) and returns a slice of the ciphertext, or an error
// if the cipher is exhausted (i.e. can no longer be used safely).
func (c *Conn) encryptLocked(plaintext []byte) ([]byte, error) {
	if !validNonce(c.tx.nonce[:]) {
		// Received 2^64-1 messages on this cipher state. Connection
		// is no longer usable.
		return nil, errCipherExhausted{}
	}

	setHeader(c.tx.buf[:headerLen], protocolVersion, msgTypeRecord, len(plaintext)+poly1305.TagSize)
	ret := c.tx.cipher.Seal(c.tx.buf[:headerLen], c.tx.nonce[:], plaintext, nil)

	// Safe to increment the nonce here, because we checked for nonce
	// wraparound above.
	binary.BigEndian.PutUint64(c.tx.nonce[4:], 1+binary.BigEndian.Uint64(c.tx.nonce[4:]))

	return ret, nil
}

// wholeMessageLocked returns a slice of one whole Noise transport
// message from c.rx.buf, if one whole message is available, and
// advances the read state to the next Noise message in the
// buffer. Returns nil without advancing read state if there isn't one
// whole message in c.rx.buf.
func (c *Conn) wholeMessageLocked() []byte {
	available := c.rx.n - c.rx.next
	if available < headerLen {
		return nil
	}
	bs := c.rx.buf[c.rx.next:c.rx.n]
	totalSize := headerLen + hdrLen(bs)
	if len(bs) < totalSize {
		return nil
	}
	c.rx.next += totalSize
	return bs[:totalSize]
}

// decryptOneLocked decrypts one Noise transport message, reading from
// c.conn as needed, and sets c.rx.plaintext to point to the decrypted
// bytes. c.rx.plaintext is only valid if err == nil.
func (c *Conn) decryptOneLocked() error {
	c.rx.plaintext = nil

	// Fast path: do we have one whole ciphertext frame buffered
	// already?
	if bs := c.wholeMessageLocked(); bs != nil {
		return c.decryptLocked(bs)
	}

	if c.rx.next != 0 {
		// To simplify the read logic, move the remainder of the
		// buffered bytes back to the head of the buffer, so we can
		// grow it without worrying about wraparound.
		c.rx.n = copy(c.rx.buf[:], c.rx.buf[c.rx.next:c.rx.n])
		c.rx.next = 0
	}

	bs, err := c.readNLocked(headerLen)
	if err != nil {
		return err
	}
	// The rest of the header (besides the length field) gets verified
	// in decryptLocked, not here.
	messageLen := headerLen + hdrLen(bs)
	bs, err = c.readNLocked(messageLen)
	if err != nil {
		return err
	}
	bs = bs[:messageLen]

	c.rx.next = len(bs)

	return c.decryptLocked(bs)
}

// Read implements io.Reader.
func (c *Conn) Read(bs []byte) (int, error) {
	c.rx.Lock()
	defer c.rx.Unlock()

	if c.rx.cipher == nil {
		return 0, net.ErrClosed
	}
	// If no plaintext is buffered, decrypt incoming frames until we
	// have some plaintext. Zero-byte Noise frames are allowed in this
	// protocol, which is why we have to loop here rather than decrypt
	// a single additional frame.
	for len(c.rx.plaintext) == 0 {
		if err := c.decryptOneLocked(); err != nil {
			return 0, err
		}
	}
	n := copy(bs, c.rx.plaintext)
	c.rx.plaintext = c.rx.plaintext[n:]
	return n, nil
}

// Write implements io.Writer.
func (c *Conn) Write(bs []byte) (n int, err error) {
	c.tx.Lock()
	defer c.tx.Unlock()

	if c.tx.err != nil {
		return 0, c.tx.err
	}
	defer func() {
		if err != nil {
			// All write errors are fatal for this conn, so clear the
			// cipher state whenever an error happens.
			c.tx.cipher = nil
		}
		if c.tx.err == nil {
			// Only set c.tx.err if not nil so that we can return one
			// error on the first failure, and a different one for
			// subsequent calls. See the error handling around Write
			// below for why.
			c.tx.err = err
		}
	}()

	if c.tx.cipher == nil {
		return 0, net.ErrClosed
	}

	var sent int
	for len(bs) > 0 {
		toSend := bs
		if len(toSend) > maxPlaintextSize {
			toSend = bs[:maxPlaintextSize]
		}
		bs = bs[len(toSend):]

		ciphertext, err := c.encryptLocked(toSend)
		if err != nil {
			return 0, err
		}

		n, err := c.conn.Write(ciphertext)
		sent += n
		if err != nil {
			// Return the raw error on the Write that actually
			// failed. For future writes, return that error wrapped in
			// a desync error.
			c.tx.err = errPartialWrite{err}
			return sent, err
		}
	}
	return sent, nil
}

// Close implements io.Closer.
func (c *Conn) Close() error {
	closeErr := c.conn.Close() // unblocks any waiting reads or writes

	// Remove references to live cipher state. Strictly speaking this
	// is unnecessary, but we want to try and hand the active cipher
	// state to the garbage collector promptly, to preserve perfect
	// forward secrecy as much as we can.
	c.rx.Lock()
	c.rx.cipher = nil
	c.rx.Unlock()
	c.tx.Lock()
	c.tx.cipher = nil
	c.tx.Unlock()
	return closeErr
}

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// errCipherExhausted is the error returned when we run out of nonces
// on a cipher.
type errCipherExhausted struct{}

func (errCipherExhausted) Error() string {
	return "cipher exhausted, no more nonces available for current key"
}
func (errCipherExhausted) Timeout() bool   { return false }
func (errCipherExhausted) Temporary() bool { return false }

// errPartialWrite is the error returned when the cipher state has
// become unusable due to a past partial write.
type errPartialWrite struct {
	err error
}

func (e errPartialWrite) Error() string {
	return fmt.Sprintf("cipher state desynchronized due to partial write (%v)", e.err)
}
func (e errPartialWrite) Unwrap() error   { return e.err }
func (e errPartialWrite) Temporary() bool { return false }
func (e errPartialWrite) Timeout() bool   { return false }

// errReadTooBig is the error returned when the peer sent an
// unacceptably large Noise frame.
type errReadTooBig struct {
	requested int
}

func (e errReadTooBig) Error() string {
	return fmt.Sprintf("requested read of %d bytes exceeds max allowed Noise frame size", e.requested)
}
func (e errReadTooBig) Temporary() bool {
	// permanent error because this error only occurs when our peer
	// sends us a frame so large we're unwilling to ever decode it.
	return false
}
func (e errReadTooBig) Timeout() bool { return false }
