// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlbase

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strconv"
	"time"

	"go4.org/mem"
	"golang.org/x/crypto/blake2s"
	chp "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"tailscale.com/types/key"
)

const (
	// protocolName is the name of the specific instantiation of Noise
	// that the control protocol uses. This string's value is fixed by
	// the Noise spec, and shouldn't be changed unless we're updating
	// the control protocol to use a different Noise instance.
	protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	// protocolVersion is the version of the control protocol that
	// Client will use when initiating a handshake.
	//protocolVersion uint16 = 1
	// protocolVersionPrefix is the name portion of the protocol
	// name+version string that gets mixed into the handshake as a
	// prologue.
	//
	// This mixing verifies that both clients agree that they're
	// executing the control protocol at a specific version that
	// matches the advertised version in the cleartext packet header.
	protocolVersionPrefix = "Tailscale Control Protocol v"
	invalidNonce          = ^uint64(0)
)

func protocolVersionPrologue(version uint16) []byte {
	ret := make([]byte, 0, len(protocolVersionPrefix)+5) // 5 bytes is enough to encode all possible version numbers.
	ret = append(ret, protocolVersionPrefix...)
	return strconv.AppendUint(ret, uint64(version), 10)
}

// HandshakeContinuation upgrades a net.Conn to a Conn. The net.Conn
// is assumed to have already sent the client>server handshake
// initiation message.
type HandshakeContinuation func(context.Context, net.Conn) (*Conn, error)

// ClientDeferred initiates a control client handshake, returning the
// initial message to send to the server and a continuation to
// finalize the handshake.
//
// ClientDeferred is split in this way for RTT reduction: we run this
// protocol after negotiating a protocol switch from HTTP/HTTPS. If we
// completely serialized the negotiation followed by the handshake,
// we'd pay an extra RTT to transmit the handshake initiation after
// protocol switching. By splitting the handshake into an initial
// message and a continuation, we can embed the handshake initiation
// into the HTTP protocol switching request and avoid a bit of delay.
func ClientDeferred(machineKey key.MachinePrivate, controlKey key.MachinePublic, protocolVersion uint16) (initialHandshake []byte, continueHandshake HandshakeContinuation, err error) {
	var s symmetricState
	s.Initialize()

	// prologue
	s.MixHash(protocolVersionPrologue(protocolVersion))

	// <- s
	// ...
	s.MixHash(controlKey.UntypedBytes())

	// -> e, es, s, ss
	init := mkInitiationMessage(protocolVersion)
	machineEphemeral := key.NewMachine()
	machineEphemeralPub := machineEphemeral.Public()
	copy(init.EphemeralPub(), machineEphemeralPub.UntypedBytes())
	s.MixHash(machineEphemeralPub.UntypedBytes())
	cipher, err := s.MixDH(machineEphemeral, controlKey)
	if err != nil {
		return nil, nil, fmt.Errorf("computing es: %w", err)
	}
	machineKeyPub := machineKey.Public()
	s.EncryptAndHash(cipher, init.MachinePub(), machineKeyPub.UntypedBytes())
	cipher, err = s.MixDH(machineKey, controlKey)
	if err != nil {
		return nil, nil, fmt.Errorf("computing ss: %w", err)
	}
	s.EncryptAndHash(cipher, init.Tag(), nil) // empty message payload

	cont := func(ctx context.Context, conn net.Conn) (*Conn, error) {
		return continueClientHandshake(ctx, conn, &s, machineKey, machineEphemeral, controlKey, protocolVersion)
	}
	return init[:], cont, nil
}

// Client wraps ClientDeferred and immediately invokes the returned
// continuation with conn.
//
// This is a helper for when you don't need the fancy
// continuation-style handshake, and just want to synchronously
// upgrade a net.Conn to a secure transport.
func Client(ctx context.Context, conn net.Conn, machineKey key.MachinePrivate, controlKey key.MachinePublic, protocolVersion uint16) (*Conn, error) {
	init, cont, err := ClientDeferred(machineKey, controlKey, protocolVersion)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(init); err != nil {
		return nil, err
	}
	return cont(ctx, conn)
}

func continueClientHandshake(ctx context.Context, conn net.Conn, s *symmetricState, machineKey, machineEphemeral key.MachinePrivate, controlKey key.MachinePublic, protocolVersion uint16) (*Conn, error) {
	// No matter what, this function can only run once per s. Ensure
	// attempted reuse causes a panic.
	defer func() {
		s.finished = true
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting conn deadline: %w", err)
		}
		defer func() {
			conn.SetDeadline(time.Time{})
		}()
	}

	// Read in the payload and look for errors/protocol violations from the server.
	var resp responseMessage
	if _, err := io.ReadFull(conn, resp.Header()); err != nil {
		return nil, fmt.Errorf("reading response header: %w", err)
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
	controlEphemeralPub := key.MachinePublicFromRaw32(mem.B(resp.EphemeralPub()))
	s.MixHash(controlEphemeralPub.UntypedBytes())
	if _, err := s.MixDH(machineEphemeral, controlEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing ee: %w", err)
	}
	cipher, err := s.MixDH(machineKey, controlEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("computing se: %w", err)
	}
	if err := s.DecryptAndHash(cipher, nil, resp.Tag()); err != nil {
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

// Server initiates a control server handshake, returning the resulting
// control connection.
//
// optionalInit can be the client's initial handshake message as
// returned by ClientDeferred, or nil in which case the initial
// message is read from conn.
//
// The context deadline, if any, covers the entire handshaking
// process.
func Server(ctx context.Context, conn net.Conn, controlKey key.MachinePrivate, optionalInit []byte) (*Conn, error) {
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
		hdr[0] = msgTypeError
		binary.BigEndian.PutUint16(hdr[1:3], uint16(len(msg)))
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
	if optionalInit != nil {
		if len(optionalInit) != len(init) {
			return nil, sendErr("wrong handshake initiation size")
		}
		copy(init[:], optionalInit)
	} else if _, err := io.ReadFull(conn, init.Header()); err != nil {
		return nil, err
	}
	// Just a rename to make it more obvious what the value is. In the
	// current implementation we don't need to block any protocol
	// versions at this layer, it's safe to let the handshake proceed
	// and then let the caller make decisions based on the agreed-upon
	// protocol version.
	clientVersion := init.Version()
	if init.Type() != msgTypeInitiation {
		return nil, sendErr("unexpected handshake message type")
	}
	if init.Length() != len(init.Payload()) {
		return nil, sendErr("wrong handshake initiation length")
	}
	// if optionalInit was provided, we have the payload already.
	if optionalInit == nil {
		if _, err := io.ReadFull(conn, init.Payload()); err != nil {
			return nil, err
		}
	}

	// prologue. Can only do this once we at least think the client is
	// handshaking using a supported version.
	s.MixHash(protocolVersionPrologue(clientVersion))

	// <- s
	// ...
	controlKeyPub := controlKey.Public()
	s.MixHash(controlKeyPub.UntypedBytes())

	// -> e, es, s, ss
	machineEphemeralPub := key.MachinePublicFromRaw32(mem.B(init.EphemeralPub()))
	s.MixHash(machineEphemeralPub.UntypedBytes())
	cipher, err := s.MixDH(controlKey, machineEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("computing es: %w", err)
	}
	var machineKeyBytes [32]byte
	if err := s.DecryptAndHash(cipher, machineKeyBytes[:], init.MachinePub()); err != nil {
		return nil, fmt.Errorf("decrypting machine key: %w", err)
	}
	machineKey := key.MachinePublicFromRaw32(mem.B(machineKeyBytes[:]))
	cipher, err = s.MixDH(controlKey, machineKey)
	if err != nil {
		return nil, fmt.Errorf("computing ss: %w", err)
	}
	if err := s.DecryptAndHash(cipher, nil, init.Tag()); err != nil {
		return nil, fmt.Errorf("decrypting initiation tag: %w", err)
	}

	// <- e, ee, se
	resp := mkResponseMessage()
	controlEphemeral := key.NewMachine()
	controlEphemeralPub := controlEphemeral.Public()
	copy(resp.EphemeralPub(), controlEphemeralPub.UntypedBytes())
	s.MixHash(controlEphemeralPub.UntypedBytes())
	if _, err := s.MixDH(controlEphemeral, machineEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing ee: %w", err)
	}
	cipher, err = s.MixDH(controlEphemeral, machineKey)
	if err != nil {
		return nil, fmt.Errorf("computing se: %w", err)
	}
	s.EncryptAndHash(cipher, resp.Tag(), nil) // empty message payload

	c1, c2, err := s.Split()
	if err != nil {
		return nil, fmt.Errorf("finalizing handshake: %w", err)
	}

	if _, err := conn.Write(resp[:]); err != nil {
		return nil, err
	}

	c := &Conn{
		conn:          conn,
		version:       clientVersion,
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

// symmetricState contains the state of an in-flight handshake.
type symmetricState struct {
	finished bool

	h  [blake2s.Size]byte // hash of currently-processed handshake state
	ck [blake2s.Size]byte // chaining key used to construct session keys at the end of the handshake
}

func (s *symmetricState) checkFinished() {
	if s.finished {
		panic("attempted to use symmetricState after Split was called")
	}
}

// Initialize sets s to the initial handshake state, prior to
// processing any handshake messages.
func (s *symmetricState) Initialize() {
	s.checkFinished()
	s.h = blake2s.Sum256([]byte(protocolName))
	s.ck = s.h
}

// MixHash updates s.h to be BLAKE2s(s.h || data), where || is
// concatenation.
func (s *symmetricState) MixHash(data []byte) {
	s.checkFinished()
	h := newBLAKE2s()
	h.Write(s.h[:])
	h.Write(data)
	h.Sum(s.h[:0])
}

// MixDH updates s.ck with the result of X25519(priv, pub) and returns
// a singleUseCHP that can be used to encrypt or decrypt handshake
// data.
//
// MixDH corresponds to MixKey(X25519(...))) in the spec. Implementing
// it as a single function allows for strongly-typed arguments that
// reduce the risk of error in the caller (e.g. invoking X25519 with
// two private keys, or two public keys), and thus producing the wrong
// calculation.
func (s *symmetricState) MixDH(priv key.MachinePrivate, pub key.MachinePublic) (*singleUseCHP, error) {
	s.checkFinished()
	keyData, err := curve25519.X25519(priv.UntypedBytes(), pub.UntypedBytes())
	if err != nil {
		return nil, fmt.Errorf("computing X25519: %w", err)
	}

	r := hkdf.New(newBLAKE2s, keyData, s.ck[:], nil)
	if _, err := io.ReadFull(r, s.ck[:]); err != nil {
		return nil, fmt.Errorf("extracting ck: %w", err)
	}
	var k [chp.KeySize]byte
	if _, err := io.ReadFull(r, k[:]); err != nil {
		return nil, fmt.Errorf("extracting k: %w", err)
	}
	return newSingleUseCHP(k), nil
}

// EncryptAndHash encrypts plaintext into ciphertext (which must be
// the correct size to hold the encrypted plaintext) using cipher,
// mixes the ciphertext into s.h, and returns the ciphertext.
func (s *symmetricState) EncryptAndHash(cipher *singleUseCHP, ciphertext, plaintext []byte) {
	s.checkFinished()
	if len(ciphertext) != len(plaintext)+chp.Overhead {
		panic("ciphertext is wrong size for given plaintext")
	}
	ret := cipher.Seal(ciphertext[:0], plaintext, s.h[:])
	s.MixHash(ret)
}

// DecryptAndHash decrypts the given ciphertext into plaintext (which
// must be the correct size to hold the decrypted ciphertext) using
// cipher. If decryption is successful, it mixes the ciphertext into
// s.h.
func (s *symmetricState) DecryptAndHash(cipher *singleUseCHP, plaintext, ciphertext []byte) error {
	s.checkFinished()
	if len(ciphertext) != len(plaintext)+chp.Overhead {
		return errors.New("plaintext is wrong size for given ciphertext")
	}
	if _, err := cipher.Open(plaintext[:0], ciphertext, s.h[:]); err != nil {
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

// singleUseCHP is an instance of ChaCha20Poly1305 that can be used
// only once, either for encrypting or decrypting, but not both. The
// chosen operation is always executed with an all-zeros
// nonce. Subsequent calls to either Seal or Open panic.
type singleUseCHP struct {
	c cipher.AEAD
}

func newSingleUseCHP(key [chp.KeySize]byte) *singleUseCHP {
	return &singleUseCHP{newCHP(key)}
}

func (c *singleUseCHP) Seal(dst, plaintext, additionalData []byte) []byte {
	if c.c == nil {
		panic("Attempted reuse of singleUseAEAD")
	}
	cipher := c.c
	c.c = nil
	var nonce [chp.NonceSize]byte
	return cipher.Seal(dst, nonce[:], plaintext, additionalData)
}

func (c *singleUseCHP) Open(dst, ciphertext, additionalData []byte) ([]byte, error) {
	if c.c == nil {
		panic("Attempted reuse of singleUseAEAD")
	}
	cipher := c.c
	c.c = nil
	var nonce [chp.NonceSize]byte
	return cipher.Open(dst, nonce[:], ciphertext, additionalData)
}
