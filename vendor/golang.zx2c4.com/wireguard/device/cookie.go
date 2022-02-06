/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/hmac"
	"crypto/rand"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

type CookieChecker struct {
	sync.RWMutex
	mac1 struct {
		key [blake2s.Size]byte
	}
	mac2 struct {
		secret        [blake2s.Size]byte
		secretSet     time.Time
		encryptionKey [chacha20poly1305.KeySize]byte
	}
}

type CookieGenerator struct {
	sync.RWMutex
	mac1 struct {
		key [blake2s.Size]byte
	}
	mac2 struct {
		cookie        [blake2s.Size128]byte
		cookieSet     time.Time
		hasLastMAC1   bool
		lastMAC1      [blake2s.Size128]byte
		encryptionKey [chacha20poly1305.KeySize]byte
	}
}

func (st *CookieChecker) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	// mac1 state

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(WGLabelMAC1))
		hash.Write(pk[:])
		hash.Sum(st.mac1.key[:0])
	}()

	// mac2 state

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(WGLabelCookie))
		hash.Write(pk[:])
		hash.Sum(st.mac2.encryptionKey[:0])
	}()

	st.mac2.secretSet = time.Time{}
}

func (st *CookieChecker) CheckMAC1(msg []byte) bool {
	st.RLock()
	defer st.RUnlock()

	size := len(msg)
	smac2 := size - blake2s.Size128
	smac1 := smac2 - blake2s.Size128

	var mac1 [blake2s.Size128]byte

	mac, _ := blake2s.New128(st.mac1.key[:])
	mac.Write(msg[:smac1])
	mac.Sum(mac1[:0])

	return hmac.Equal(mac1[:], msg[smac1:smac2])
}

func (st *CookieChecker) CheckMAC2(msg []byte, src []byte) bool {
	st.RLock()
	defer st.RUnlock()

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		return false
	}

	// derive cookie key

	var cookie [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(st.mac2.secret[:])
		mac.Write(src)
		mac.Sum(cookie[:0])
	}()

	// calculate mac of packet (including mac1)

	smac2 := len(msg) - blake2s.Size128

	var mac2 [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(cookie[:])
		mac.Write(msg[:smac2])
		mac.Sum(mac2[:0])
	}()

	return hmac.Equal(mac2[:], msg[smac2:])
}

func (st *CookieChecker) CreateReply(
	msg []byte,
	recv uint32,
	src []byte,
) (*MessageCookieReply, error) {

	st.RLock()

	// refresh cookie secret

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		st.RUnlock()
		st.Lock()
		_, err := rand.Read(st.mac2.secret[:])
		if err != nil {
			st.Unlock()
			return nil, err
		}
		st.mac2.secretSet = time.Now()
		st.Unlock()
		st.RLock()
	}

	// derive cookie

	var cookie [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(st.mac2.secret[:])
		mac.Write(src)
		mac.Sum(cookie[:0])
	}()

	// encrypt cookie

	size := len(msg)

	smac2 := size - blake2s.Size128
	smac1 := smac2 - blake2s.Size128

	reply := new(MessageCookieReply)
	reply.Type = MessageCookieReplyType
	reply.Receiver = recv

	_, err := rand.Read(reply.Nonce[:])
	if err != nil {
		st.RUnlock()
		return nil, err
	}

	xchapoly, _ := chacha20poly1305.NewX(st.mac2.encryptionKey[:])
	xchapoly.Seal(reply.Cookie[:0], reply.Nonce[:], cookie[:], msg[smac1:smac2])

	st.RUnlock()

	return reply, nil
}

func (st *CookieGenerator) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(WGLabelMAC1))
		hash.Write(pk[:])
		hash.Sum(st.mac1.key[:0])
	}()

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(WGLabelCookie))
		hash.Write(pk[:])
		hash.Sum(st.mac2.encryptionKey[:0])
	}()

	st.mac2.cookieSet = time.Time{}
}

func (st *CookieGenerator) ConsumeReply(msg *MessageCookieReply) bool {
	st.Lock()
	defer st.Unlock()

	if !st.mac2.hasLastMAC1 {
		return false
	}

	var cookie [blake2s.Size128]byte

	xchapoly, _ := chacha20poly1305.NewX(st.mac2.encryptionKey[:])
	_, err := xchapoly.Open(cookie[:0], msg.Nonce[:], msg.Cookie[:], st.mac2.lastMAC1[:])

	if err != nil {
		return false
	}

	st.mac2.cookieSet = time.Now()
	st.mac2.cookie = cookie
	return true
}

func (st *CookieGenerator) AddMacs(msg []byte) {

	size := len(msg)

	smac2 := size - blake2s.Size128
	smac1 := smac2 - blake2s.Size128

	mac1 := msg[smac1:smac2]
	mac2 := msg[smac2:]

	st.Lock()
	defer st.Unlock()

	// set mac1

	func() {
		mac, _ := blake2s.New128(st.mac1.key[:])
		mac.Write(msg[:smac1])
		mac.Sum(mac1[:0])
	}()
	copy(st.mac2.lastMAC1[:], mac1)
	st.mac2.hasLastMAC1 = true

	// set mac2

	if time.Since(st.mac2.cookieSet) > CookieRefreshTime {
		return
	}

	func() {
		mac, _ := blake2s.New128(st.mac2.cookie[:])
		mac.Write(msg[:smac2])
		mac.Sum(mac2[:0])
	}()
}
