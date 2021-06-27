// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noise

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	tsnettest "tailscale.com/net/nettest"
	"tailscale.com/types/key"
)

// Can a reference Noise IK client talk to our server?
func TestInteropClient(t *testing.T) {
	var (
		s1, s2      = tsnettest.NewConn("noise", 128000)
		controlKey  = key.NewPrivate()
		machineKey  = key.NewPrivate()
		serverErr   = make(chan error, 2)
		serverBytes = make(chan []byte, 1)
		c2s         = "client>server"
		s2c         = "server>client"
	)

	go func() {
		server, err := Server(context.Background(), s2, controlKey)
		serverErr <- err
		if err != nil {
			return
		}
		var buf [1024]byte
		_, err = io.ReadFull(server, buf[:len(c2s)])
		serverBytes <- buf[:len(c2s)]
		if err != nil {
			serverErr <- err
			return
		}
		_, err = server.Write([]byte(s2c))
		serverErr <- err
	}()

	gotS2C, err := noiseExplorerClient(s1, controlKey.Public(), machineKey, []byte(c2s))
	if err != nil {
		t.Fatalf("failed client interop: %v", err)
	}
	if string(gotS2C) != s2c {
		t.Fatalf("server sent unexpected data %q, want %q", string(gotS2C), s2c)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server read/write failed: %v", err)
	}
	if got := string(<-serverBytes); got != c2s {
		t.Fatalf("server received %q, want %q", got, c2s)
	}
}

// Can our client talk to a reference Noise IK server?
func TestInteropServer(t *testing.T) {
	var (
		s1, s2      = tsnettest.NewConn("noise", 128000)
		controlKey  = key.NewPrivate()
		machineKey  = key.NewPrivate()
		clientErr   = make(chan error, 2)
		clientBytes = make(chan []byte, 1)
		c2s         = "client>server"
		s2c         = "server>client"
	)

	go func() {
		client, err := Client(context.Background(), s1, machineKey, controlKey.Public())
		clientErr <- err
		if err != nil {
			return
		}
		_, err = client.Write([]byte(c2s))
		if err != nil {
			clientErr <- err
			return
		}
		var buf [1024]byte
		_, err = io.ReadFull(client, buf[:len(s2c)])
		clientBytes <- buf[:len(s2c)]
		clientErr <- err
	}()

	gotC2S, err := noiseExplorerServer(s2, controlKey, machineKey.Public(), []byte(s2c))
	if err != nil {
		t.Fatalf("failed server interop: %v", err)
	}
	if string(gotC2S) != c2s {
		t.Fatalf("server sent unexpected data %q, want %q", string(gotC2S), c2s)
	}

	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("client read/write failed: %v", err)
	}
	if got := string(<-clientBytes); got != s2c {
		t.Fatalf("client received %q, want %q", got, s2c)
	}
}

// noiseExplorerClient uses the Noise Explorer implementation of Noise
// IK to handshake as a Noise client on conn, transmit payload, and
// read+return a payload from the peer.
func noiseExplorerClient(conn net.Conn, controlKey key.Public, machineKey key.Private, payload []byte) ([]byte, error) {
	mk := keypair{
		private_key: machineKey,
		public_key:  machineKey.Public(),
	}
	session := InitSession(true, nil, mk, controlKey)

	_, msg1 := SendMessage(&session, nil)
	if _, err := conn.Write(msg1.ne[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg1.ns); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg1.ciphertext); err != nil {
		return nil, err
	}

	var buf [1024]byte
	if _, err := io.ReadFull(conn, buf[:48]); err != nil {
		return nil, err
	}
	msg2 := messagebuffer{
		ciphertext: buf[32:48],
	}
	copy(msg2.ne[:], buf[:32])
	_, p, valid := RecvMessage(&session, &msg2)
	if !valid {
		return nil, errors.New("handshake failed")
	}
	if len(p) != 0 {
		return nil, errors.New("non-empty payload")
	}

	_, msg3 := SendMessage(&session, payload)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msg3.ciphertext)))
	if _, err := conn.Write(buf[:2]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg3.ciphertext); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, err
	}
	plen := int(binary.BigEndian.Uint16(buf[:2]))
	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return nil, err
	}

	msg4 := messagebuffer{
		ciphertext: buf[:plen],
	}
	_, p, valid = RecvMessage(&session, &msg4)
	if !valid {
		return nil, errors.New("transport message decryption failed")
	}

	return p, nil
}

func noiseExplorerServer(conn net.Conn, controlKey key.Private, wantMachineKey key.Public, payload []byte) ([]byte, error) {
	mk := keypair{
		private_key: controlKey,
		public_key:  controlKey.Public(),
	}
	session := InitSession(false, nil, mk, [32]byte{})

	var buf [1024]byte
	if _, err := io.ReadFull(conn, buf[:96]); err != nil {
		return nil, err
	}
	msg1 := messagebuffer{
		ns:         buf[32:80],
		ciphertext: buf[80:96],
	}
	copy(msg1.ne[:], buf[:32])
	_, p, valid := RecvMessage(&session, &msg1)
	if !valid {
		return nil, errors.New("handshake failed")
	}
	if len(p) != 0 {
		return nil, errors.New("non-empty payload")
	}

	_, msg2 := SendMessage(&session, nil)
	if _, err := conn.Write(msg2.ne[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg2.ciphertext[:]); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, err
	}
	plen := int(binary.BigEndian.Uint16(buf[:2]))
	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return nil, err
	}

	msg3 := messagebuffer{
		ciphertext: buf[:plen],
	}
	_, p, valid = RecvMessage(&session, &msg3)
	if !valid {
		return nil, errors.New("transport message decryption failed")
	}

	_, msg4 := SendMessage(&session, payload)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msg4.ciphertext)))
	if _, err := conn.Write(buf[:2]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg4.ciphertext); err != nil {
		return nil, err
	}

	return p, nil
}
