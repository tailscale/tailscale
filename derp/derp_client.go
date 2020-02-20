// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

import (
	"bufio"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/nacl/box"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type Client struct {
	serverKey  key.Public // of the DERP server; not a machine or node key
	privateKey key.Private
	publicKey  key.Public // of privateKey
	logf       logger.Logf
	nc         net.Conn
	br         *bufio.Reader
	bw         *bufio.Writer
	readErr    error // sticky read error
}

func NewClient(privateKey key.Private, nc net.Conn, brw *bufio.ReadWriter, logf logger.Logf) (*Client, error) {
	c := &Client{
		privateKey: privateKey,
		publicKey:  privateKey.Public(),
		logf:       logf,
		nc:         nc,
		br:         brw.Reader,
		bw:         brw.Writer,
	}

	if err := c.recvServerKey(); err != nil {
		return nil, fmt.Errorf("derp.Client: failed to receive server key: %v", err)
	}
	if err := c.sendClientKey(); err != nil {
		return nil, fmt.Errorf("derp.Client: failed to send client key: %v", err)
	}
	_, err := c.recvServerInfo()
	if err != nil {
		return nil, fmt.Errorf("derp.Client: failed to receive server info: %v", err)
	}

	return c, nil
}

func (c *Client) recvServerKey() error {
	var buf [40]byte
	t, flen, err := readFrame(c.br, 1<<10, buf[:])
	if err == io.ErrShortBuffer {
		// For future-proofing, allow server to send more in its greeting.
		err = nil
	}
	if err != nil {
		return err
	}
	if flen < uint32(len(buf)) || t != frameServerKey || string(buf[:len(magic)]) != magic {
		return errors.New("invalid server greeting")
	}
	copy(c.serverKey[:], buf[len(magic):])
	return nil
}

func (c *Client) recvServerInfo() (*serverInfo, error) {
	fl, err := readFrameTypeHeader(c.br, frameServerInfo)
	if err != nil {
		return nil, err
	}
	const maxLength = nonceLen + maxInfoLen
	if fl < nonceLen {
		return nil, fmt.Errorf("short serverInfo frame")
	}
	if fl > maxLength {
		return nil, fmt.Errorf("long serverInfo frame")
	}
	// TODO: add a read-nonce-and-box helper
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(c.br, nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce: %v", err)
	}
	msgLen := fl - nonceLen
	msgbox := make([]byte, msgLen)
	if _, err := io.ReadFull(c.br, msgbox); err != nil {
		return nil, fmt.Errorf("msgbox: %v", err)
	}
	msg, ok := box.Open(nil, msgbox, &nonce, c.serverKey.B32(), c.privateKey.B32())
	if !ok {
		return nil, fmt.Errorf("msgbox: cannot open len=%d with server key %x", msgLen, c.serverKey[:])
	}
	info := new(serverInfo)
	if err := json.Unmarshal(msg, info); err != nil {
		return nil, fmt.Errorf("msg: %v", err)
	}
	return info, nil
}

func (c *Client) sendClientKey() error {
	var nonce [nonceLen]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return err
	}
	msg := []byte("{}") // no clientInfo for now
	msgbox := box.Seal(nil, msg, &nonce, c.serverKey.B32(), c.privateKey.B32())

	buf := make([]byte, 0, nonceLen+keyLen+len(msgbox))
	buf = append(buf, c.publicKey[:]...)
	buf = append(buf, nonce[:]...)
	buf = append(buf, msgbox...)
	return writeFrame(c.bw, frameClientInfo, buf)
}

// Send sends a packet to the Tailscale node identified by dstKey.
//
// It is an error if the packet is larger than 64KB.
func (c *Client) Send(dstKey key.Public, pkt []byte) error { return c.send(dstKey, pkt) }

func (c *Client) send(dstKey key.Public, pkt []byte) (ret error) {
	defer func() {
		if ret != nil {
			ret = fmt.Errorf("derp.Send: %v", ret)
		}
	}()

	if len(pkt) > 64<<10 {
		return fmt.Errorf("packet too big: %d", len(pkt))
	}

	if err := writeFrameHeader(c.bw, frameSendPacket, uint32(len(dstKey)+len(pkt))); err != nil {
		return err
	}
	if _, err := c.bw.Write(dstKey[:]); err != nil {
		return err
	}
	if _, err := c.bw.Write(pkt); err != nil {
		return err
	}
	return c.bw.Flush()
}

// Recv reads a data packet from the DERP server.
// The provided buffer must be larger enough to receive a complete packet.
// Once Recv returns an error, the Client is dead forever.
func (c *Client) Recv(b []byte) (n int, err error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("derp.Recv: %v", err)
			c.readErr = err
		}
	}()

	for {
		c.nc.SetReadDeadline(time.Now().Add(120 * time.Second))
		t, n, err := readFrame(c.br, 1<<20, b)
		if err != nil {
			return 0, err
		}
		switch t {
		default:
			continue
		case frameKeepAlive:
			// TODO: eventually we'll have server->client pings that
			// require ack pongs.
			continue
		case frameRecvPacket:
			return int(n), nil
		}
	}
}
