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
	"time"

	"golang.org/x/crypto/blake2s"
	chp "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"tailscale.com/types/key"
)

const (
	protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	invalidNonce = ^uint64(0)
)

// Client initiates a Noise client handshake, returning the resulting
// Noise connection.
//
// The context deadline, if any, covers the entire handshaking
// process.
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

	// <- s
	// ...
	s.MixHash(controlKey[:])

	var init initiationMessage
	// -> e, es, s, ss
	machineEphemeral := key.NewPrivate()
	machineEphemeralPub := machineEphemeral.Public()
	copy(init.MachineEphemeralPub(), machineEphemeralPub[:])
	s.MixHash(machineEphemeralPub[:])
	if err := s.MixDH(machineEphemeral, controlKey); err != nil {
		return nil, fmt.Errorf("computing es: %w", err)
	}
	machineKeyPub := machineKey.Public()
	copy(init.MachinePub(), s.EncryptAndHash(machineKeyPub[:]))
	if err := s.MixDH(machineKey, controlKey); err != nil {
		return nil, fmt.Errorf("computing ss: %w", err)
	}
	copy(init.Tag(), s.EncryptAndHash(nil)) // empty message payload

	if _, err := conn.Write(init[:]); err != nil {
		return nil, fmt.Errorf("writing initiation: %w", err)
	}

	// <- e, ee, se
	var resp responseMessage
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var controlEphemeralPub key.Public
	copy(controlEphemeralPub[:], resp.ControlEphemeralPub())
	s.MixHash(controlEphemeralPub[:])
	if err := s.MixDH(machineEphemeral, controlEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing ee: %w", err)
	}
	if err := s.MixDH(machineKey, controlEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing se: %w", err)
	}
	if _, err := s.DecryptAndHash(resp.Tag()); err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}

	c1, c2, err := s.Split()
	if err != nil {
		return nil, fmt.Errorf("finalizing handshake: %w", err)
	}

	return &Conn{
		conn:          conn,
		peer:          controlKey,
		handshakeHash: s.h,
		tx: txState{
			cipher: c1,
		},
		rx: rxState{
			cipher: c2,
		},
	}, nil
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

	var s symmetricState
	s.Initialize()

	// <- s
	// ...
	controlKeyPub := controlKey.Public()
	s.MixHash(controlKeyPub[:])

	// -> e, es, s, ss
	var init initiationMessage
	if _, err := io.ReadFull(conn, init[:]); err != nil {
		return nil, fmt.Errorf("reading initiation: %w", err)
	}

	var machineEphemeralPub key.Public
	copy(machineEphemeralPub[:], init.MachineEphemeralPub())
	s.MixHash(machineEphemeralPub[:])
	if err := s.MixDH(controlKey, machineEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing es: %w", err)
	}
	var machineKey key.Public
	rs, err := s.DecryptAndHash(init.MachinePub())
	if err != nil {
		return nil, fmt.Errorf("decrypting machine key: %w", err)
	}
	copy(machineKey[:], rs)
	if err := s.MixDH(controlKey, machineKey); err != nil {
		return nil, fmt.Errorf("computing ss: %w", err)
	}
	if _, err := s.DecryptAndHash(init.Tag()); err != nil {
		return nil, fmt.Errorf("decrypting initiation tag: %w", err)
	}

	// <- e, ee, se
	var resp responseMessage
	controlEphemeral := key.NewPrivate()
	controlEphemeralPub := controlEphemeral.Public()
	copy(resp.ControlEphemeralPub(), controlEphemeralPub[:])
	s.MixHash(controlEphemeralPub[:])
	if err := s.MixDH(controlEphemeral, machineEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing ee: %w", err)
	}
	if err := s.MixDH(controlEphemeral, machineKey); err != nil {
		return nil, fmt.Errorf("computing se: %w", err)
	}
	copy(resp.Tag(), s.EncryptAndHash(nil)) // empty message payload

	c1, c2, err := s.Split()
	if err != nil {
		return nil, fmt.Errorf("finalizing handshake: %w", err)
	}

	if _, err := conn.Write(resp[:]); err != nil {
		return nil, err
	}

	return &Conn{
		conn:          conn,
		peer:          machineKey,
		handshakeHash: s.h,
		tx: txState{
			cipher: c2,
		},
		rx: rxState{
			cipher: c1,
		},
	}, nil
}

// initiationMessage is the Noise protocol message sent from a client
// machine to a control server.
type initiationMessage [96]byte

func (m *initiationMessage) MachineEphemeralPub() []byte { return m[:32] }
func (m *initiationMessage) MachinePub() []byte          { return m[32:80] }
func (m *initiationMessage) Tag() []byte                 { return m[80:] }

// responseMessage is the Noise protocol message sent from a control
// server to a client machine.
type responseMessage [48]byte

func (m *responseMessage) ControlEphemeralPub() []byte { return m[:32] }
func (m *responseMessage) Tag() []byte                 { return m[32:] }

// symmetricState is the SymmetricState object from the Noise protocol
// spec. It contains all the symmetric cipher state of an in-flight
// handshake. Field names match the variable names in the spec.
type symmetricState struct {
	h  [blake2s.Size]byte
	ck [blake2s.Size]byte

	k [chp.KeySize]byte
	n uint64

	mixer hash.Hash // for updating h
}

// Initialize sets s to the initial handshake state, prior to
// processing any Noise messages.
func (s *symmetricState) Initialize() {
	if s.mixer != nil {
		panic("symmetricState cannot be reused")
	}
	s.h = blake2s.Sum256([]byte(protocolName))
	s.ck = s.h
	s.k = [chp.KeySize]byte{}
	s.n = invalidNonce
	s.mixer = newBLAKE2s()
	// Mix in an empty prologue.
	s.MixHash(nil)
}

// MixHash updates s.h to be BLAKE2s(s.h || data), where || is
// concatenation.
func (s *symmetricState) MixHash(data []byte) {
	s.mixer.Reset()
	s.mixer.Write(s.h[:])
	s.mixer.Write(data)
	s.mixer.Sum(s.h[:0]) // TODO: check this actually updates s.h correctly...
}

// MixDH updates s.ck and s.k with the result of X25519(priv, pub).
//
// MixDH corresponds to MixKey(X25519(...))) in the spec. Implementing
// it as a single function allows for strongly-typed arguments that
// reduce the risk of error in the caller (e.g. invoking X25519 with
// two private keys, or two public keys), and thus producing the wrong
// calculation.
func (s *symmetricState) MixDH(priv key.Private, pub key.Public) error {
	// TODO(danderson): check that this operation is correct. The docs
	// for X25519 say that the 2nd arg must be either Basepoint or the
	// output of another X25519 call.
	//
	// I think this is correct, because pub is the result of a
	// ScalarBaseMult on the private key, and our private key
	// generation code clamps keys to avoid low order points. I
	// believe that makes pub equivalent to the output of
	// X25519(privateKey, Basepoint), and so the contract is
	// respected.
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

// EncryptAndHash encrypts the given plaintext using the current s.k,
// mixes the ciphertext into s.h, and returns the ciphertext.
func (s *symmetricState) EncryptAndHash(plaintext []byte) []byte {
	if s.n == invalidNonce {
		// Noise in general permits writing "ciphertext" without a
		// key, but in IK it cannot happen.
		panic("attempted encryption with uninitialized key")
	}
	aead := newCHP(s.k)
	var nonce [chp.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], s.n)
	s.n++
	ret := aead.Seal(nil, nonce[:], plaintext, s.h[:])
	s.MixHash(ret)
	return ret
}

// DecryptAndHash decrypts the given ciphertext using the current
// s.k. If decryption is successful, it mixes the ciphertext into s.h
// and returns the plaintext.
func (s *symmetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	if s.n == invalidNonce {
		// Noise in general permits "ciphertext" without a key, but in
		// IK it cannot happen.
		panic("attempted encryption with uninitialized key")
	}
	aead := newCHP(s.k)
	var nonce [chp.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], s.n)
	s.n++
	ret, err := aead.Open(nil, nonce[:], ciphertext, s.h[:])
	if err != nil {
		return nil, err
	}
	s.MixHash(ciphertext)
	return ret, nil
}

// Split returns two ChaCha20Poly1305 ciphers with keys derives from
// the current handshake state. Methods on s must not be used again
// after calling Split().
func (s *symmetricState) Split() (c1, c2 cipher.AEAD, err error) {
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
		panic(fmt.Sprintf("blake2s construction: %v", err))
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
		panic(fmt.Sprintf("chacha20poly1305 construction: %v", err))
	}
	return aead
}
