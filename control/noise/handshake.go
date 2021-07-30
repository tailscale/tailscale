// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noise

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/blake2s"
	chp "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
	"tailscale.com/types/key"
)

const (
	// protocolName is the name of the specific instantiation of the
	// Noise protocol we're using. Each field is defined in the Noise
	// spec, and shouldn't be changed unless we're switching to a
	// different Noise protocol instance.
	protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	// protocolVersion is the version of the Tailscale base
	// protocol that Client will use when initiating a handshake.
	protocolVersion uint16 = 1
	// protocolVersionPrefix is the name portion of the protocol
	// name+version string that gets mixed into the Noise handshake as
	// a prologue.
	//
	// This mixing verifies that both clients agree that
	// they're executing the Tailscale control protocol at a specific
	// version that matches the advertised version in the cleartext
	// packet header.
	protocolVersionPrefix = "Tailscale Control Protocol v"
	invalidNonce          = ^uint64(0)
)

func protocolVersionPrologue(version uint16) []byte {
	ret := make([]byte, 0, len(protocolVersionPrefix)+5) // 5 bytes is enough to encode all possible version numbers.
	ret = append(ret, protocolVersionPrefix...)
	return strconv.AppendUint(ret, uint64(version), 10)
}

// Client initiates a Noise client handshake, returning the resulting
// Noise connection.
//
// The context deadline, if any, covers the entire handshaking
// process. Any preexisting Conn deadline is removed.
func Client(ctx context.Context, conn net.Conn, machineKey key.Private, controlKey key.Public) (*Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting conn deadline: %w", err)
		}
		defer func() {
			conn.SetDeadline(time.Time{})
		}()
	}

	var s symmetricState
	s.Initialize()

	// prologue
	s.MixHash(protocolVersionPrologue(protocolVersion))

	// <- s
	// ...
	s.MixHash(controlKey[:])

	// -> e, es, s, ss
	init := mkInitiationMessage()
	machineEphemeral := key.NewPrivate()
	machineEphemeralPub := machineEphemeral.Public()
	copy(init.EphemeralPub(), machineEphemeralPub[:])
	s.MixHash(machineEphemeralPub[:])
	if err := s.MixDH(machineEphemeral, controlKey); err != nil {
		return nil, fmt.Errorf("computing es: %w", err)
	}
	machineKeyPub := machineKey.Public()
	s.EncryptAndHash(init.MachinePub(), machineKeyPub[:])
	if err := s.MixDH(machineKey, controlKey); err != nil {
		return nil, fmt.Errorf("computing ss: %w", err)
	}
	s.EncryptAndHash(init.Tag(), nil) // empty message payload

	if _, err := conn.Write(init[:]); err != nil {
		return nil, fmt.Errorf("writing initiation: %w", err)
	}

	// Read in the payload and look for errors/protocol violations from the server.
	var resp responseMessage
	if _, err := io.ReadFull(conn, resp.Header()); err != nil {
		return nil, fmt.Errorf("reading response header: %w", err)
	}
	if resp.Version() != protocolVersion {
		return nil, fmt.Errorf("unexpected version %d from server, want %d", resp.Version(), protocolVersion)
	}
	if resp.Type() != msgTypeResponse {
		if resp.Type() != msgTypeError {
			return nil, fmt.Errorf("unexpected response message type %d", resp.Type())
		}
		msg := make([]byte, resp.Length())
		if _, err := io.ReadFull(conn, msg); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("server error: %q", msg)
	}
	if resp.Length() != len(resp.Payload()) {
		return nil, fmt.Errorf("wrong length %d received for handshake response", resp.Length())
	}
	if _, err := io.ReadFull(conn, resp.Payload()); err != nil {
		return nil, err
	}

	// <- e, ee, se
	var controlEphemeralPub key.Public
	copy(controlEphemeralPub[:], resp.EphemeralPub())
	s.MixHash(controlEphemeralPub[:])
	if err := s.MixDH(machineEphemeral, controlEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing ee: %w", err)
	}
	if err := s.MixDH(machineKey, controlEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing se: %w", err)
	}
	if err := s.DecryptAndHash(nil, resp.Tag()); err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}

	c1, c2, err := s.Split()
	if err != nil {
		return nil, fmt.Errorf("finalizing handshake: %w", err)
	}

	c := &Conn{
		conn:          conn,
		version:       protocolVersion,
		peer:          controlKey,
		handshakeHash: s.h,
		tx: txState{
			cipher: c1,
		},
		rx: rxState{
			cipher: c2,
		},
	}
	return c, nil
}

// Server initiates a Noise server handshake, returning the resulting
// Noise connection.
//
// The context deadline, if any, covers the entire handshaking
// process.
func Server(ctx context.Context, conn net.Conn, controlKey key.Private) (*Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting conn deadline: %w", err)
		}
		defer func() {
			conn.SetDeadline(time.Time{})
		}()
	}

	// Deliberately does not support formatting, so that we don't echo
	// attacker-controlled input back to them.
	sendErr := func(msg string) error {
		if len(msg) >= 1<<16 {
			msg = msg[:1<<16]
		}
		var hdr [headerLen]byte
		setHeader(hdr[:], protocolVersion, msgTypeError, len(msg))
		if _, err := conn.Write(hdr[:]); err != nil {
			return fmt.Errorf("sending %q error to client: %w", msg, err)
		}
		if _, err := io.WriteString(conn, msg); err != nil {
			return fmt.Errorf("sending %q error to client: %w", msg, err)
		}
		return fmt.Errorf("refused client handshake: %q", msg)
	}

	var s symmetricState
	s.Initialize()

	var init initiationMessage
	if _, err := io.ReadFull(conn, init.Header()); err != nil {
		return nil, err
	}
	if init.Version() != protocolVersion {
		return nil, sendErr("unsupported protocol version")
	}
	if init.Type() != msgTypeInitiation {
		return nil, sendErr("unexpected handshake message type")
	}
	if init.Length() != len(init.Payload()) {
		return nil, sendErr("wrong handshake initiation length")
	}
	if _, err := io.ReadFull(conn, init.Payload()); err != nil {
		return nil, err
	}

	// prologue. Can only do this once we at least think the client is
	// handshaking using a supported version.
	s.MixHash(protocolVersionPrologue(protocolVersion))

	// <- s
	// ...
	controlKeyPub := controlKey.Public()
	s.MixHash(controlKeyPub[:])

	// -> e, es, s, ss
	var machineEphemeralPub key.Public
	copy(machineEphemeralPub[:], init.EphemeralPub())
	s.MixHash(machineEphemeralPub[:])
	if err := s.MixDH(controlKey, machineEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing es: %w", err)
	}
	var machineKey key.Public
	if err := s.DecryptAndHash(machineKey[:], init.MachinePub()); err != nil {
		return nil, fmt.Errorf("decrypting machine key: %w", err)
	}
	if err := s.MixDH(controlKey, machineKey); err != nil {
		return nil, fmt.Errorf("computing ss: %w", err)
	}
	if err := s.DecryptAndHash(nil, init.Tag()); err != nil {
		return nil, fmt.Errorf("decrypting initiation tag: %w", err)
	}

	// <- e, ee, se
	resp := mkResponseMessage()
	controlEphemeral := key.NewPrivate()
	controlEphemeralPub := controlEphemeral.Public()
	copy(resp.EphemeralPub(), controlEphemeralPub[:])
	s.MixHash(controlEphemeralPub[:])
	if err := s.MixDH(controlEphemeral, machineEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing ee: %w", err)
	}
	if err := s.MixDH(controlEphemeral, machineKey); err != nil {
		return nil, fmt.Errorf("computing se: %w", err)
	}
	s.EncryptAndHash(resp.Tag(), nil) // empty message payload

	c1, c2, err := s.Split()
	if err != nil {
		return nil, fmt.Errorf("finalizing handshake: %w", err)
	}

	if _, err := conn.Write(resp[:]); err != nil {
		return nil, err
	}

	c := &Conn{
		conn:          conn,
		version:       protocolVersion,
		peer:          machineKey,
		handshakeHash: s.h,
		tx: txState{
			cipher: c2,
		},
		rx: rxState{
			cipher: c1,
		},
	}
	return c, nil
}

// symmetricState is the SymmetricState object from the Noise protocol
// spec. It contains all the symmetric cipher state of an in-flight
// handshake. Field names match the variable names in the spec.
type symmetricState struct {
	finished bool

	h  [blake2s.Size]byte
	ck [blake2s.Size]byte

	k [chp.KeySize]byte
	n uint64

	mixer hash.Hash // for updating h
}

func (s *symmetricState) checkFinished() {
	if s.finished {
		panic("attempted to use symmetricState after Split was called")
	}
}

// Initialize sets s to the initial handshake state, prior to
// processing any Noise messages.
func (s *symmetricState) Initialize() {
	s.checkFinished()
	if s.mixer != nil {
		panic("symmetricState cannot be reused")
	}
	s.h = blake2s.Sum256([]byte(protocolName))
	s.ck = s.h
	s.k = [chp.KeySize]byte{}
	s.n = invalidNonce
	s.mixer = newBLAKE2s()
}

// MixHash updates s.h to be BLAKE2s(s.h || data), where || is
// concatenation.
func (s *symmetricState) MixHash(data []byte) {
	s.checkFinished()
	s.mixer.Reset()
	s.mixer.Write(s.h[:])
	s.mixer.Write(data)
	s.mixer.Sum(s.h[:0])
}

// MixDH updates s.ck and s.k with the result of X25519(priv, pub).
//
// MixDH corresponds to MixKey(X25519(...))) in the spec. Implementing
// it as a single function allows for strongly-typed arguments that
// reduce the risk of error in the caller (e.g. invoking X25519 with
// two private keys, or two public keys), and thus producing the wrong
// calculation.
func (s *symmetricState) MixDH(priv key.Private, pub key.Public) error {
	s.checkFinished()
	keyData, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return fmt.Errorf("computing X25519: %w", err)
	}

	r := hkdf.New(newBLAKE2s, keyData, s.ck[:], nil)
	if _, err := io.ReadFull(r, s.ck[:]); err != nil {
		return fmt.Errorf("extracting ck: %w", err)
	}
	if _, err := io.ReadFull(r, s.k[:]); err != nil {
		return fmt.Errorf("extracting k: %w", err)
	}
	s.n = 0
	return nil
}

// EncryptAndHash encrypts plaintext into ciphertext (which must be
// the correct size to hold the encrypted plaintext) using the current
// s.k, mixes the ciphertext into s.h, and returns the ciphertext.
func (s *symmetricState) EncryptAndHash(ciphertext, plaintext []byte) {
	s.checkFinished()
	if s.n == invalidNonce {
		// Noise in general permits writing "ciphertext" without a
		// key, but in IK it cannot happen.
		panic("attempted encryption with uninitialized key")
	}
	if len(ciphertext) != len(plaintext)+poly1305.TagSize {
		panic("ciphertext is wrong size for given plaintext")
	}
	aead := newCHP(s.k)
	var nonce [chp.NonceSize]byte
	// chacha20poly1305 nonces are 96 bits, but we use a 64-bit
	// counter. Therefore, the leading 4 bytes are always zero.
	binary.BigEndian.PutUint64(nonce[4:], s.n)
	s.n++
	ret := aead.Seal(ciphertext[:0], nonce[:], plaintext, s.h[:])
	s.MixHash(ret)
}

// DecryptAndHash decrypts the given ciphertext into plaintext (which
// must be the correct size to hold the decrypted ciphertext) using
// the current s.k. If decryption is successful, it mixes the
// ciphertext into s.h.
func (s *symmetricState) DecryptAndHash(plaintext, ciphertext []byte) error {
	s.checkFinished()
	if s.n == invalidNonce {
		// Noise in general permits "ciphertext" without a key, but in
		// IK it cannot happen.
		panic("attempted encryption with uninitialized key")
	}
	if len(ciphertext) != len(plaintext)+poly1305.TagSize {
		panic("plaintext is wrong size for given ciphertext")
	}
	aead := newCHP(s.k)
	var nonce [chp.NonceSize]byte
	// chacha20poly1305 nonces are 96 bits, but we use a 64-bit
	// counter. Therefore, the leading 4 bytes are always zero.
	binary.BigEndian.PutUint64(nonce[4:], s.n)
	s.n++
	if _, err := aead.Open(plaintext[:0], nonce[:], ciphertext, s.h[:]); err != nil {
		return err
	}
	s.MixHash(ciphertext)
	return nil
}

// Split returns two ChaCha20Poly1305 ciphers with keys derived from
// the current handshake state. Methods on s cannot be used again
// after calling Split.
func (s *symmetricState) Split() (c1, c2 cipher.AEAD, err error) {
	s.finished = true

	var k1, k2 [chp.KeySize]byte
	r := hkdf.New(newBLAKE2s, nil, s.ck[:], nil)
	if _, err := io.ReadFull(r, k1[:]); err != nil {
		return nil, nil, fmt.Errorf("extracting k1: %w", err)
	}
	if _, err := io.ReadFull(r, k2[:]); err != nil {
		return nil, nil, fmt.Errorf("extracting k2: %w", err)
	}
	c1, err = chp.New(k1[:])
	if err != nil {
		return nil, nil, fmt.Errorf("constructing AEAD c1: %w", err)
	}
	c2, err = chp.New(k2[:])
	if err != nil {
		return nil, nil, fmt.Errorf("constructing AEAD c2: %w", err)
	}
	return c1, c2, nil
}

// newBLAKE2s returns a hash.Hash implementing BLAKE2s, or panics on
// error.
func newBLAKE2s() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		// Should never happen, errors only happen when using BLAKE2s
		// in MAC mode with a key.
		panic(err)
	}
	return h
}

// newCHP returns a cipher.AEAD implementing ChaCha20Poly1305, or
// panics on error.
func newCHP(key [chp.KeySize]byte) cipher.AEAD {
	aead, err := chp.New(key[:])
	if err != nil {
		// Can only happen if we passed a key of the wrong length. The
		// function signature prevents that.
		panic(err)
	}
	return aead
}
