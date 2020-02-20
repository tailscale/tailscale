// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

import (
	"bufio"
	crand "crypto/rand"
	"encoding/json"
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
	gotMagic, err := readUint32(c.br, 0xffffffff)
	if err != nil {
		return err
	}
	if gotMagic != magic {
		return fmt.Errorf("bad magic %x, want %x", gotMagic, magic)
	}
	if err := readType(c.br, typeServerKey); err != nil {
		return err
	}
	if _, err := io.ReadFull(c.br, c.serverKey[:]); err != nil {
		return err
	}
	return nil
}

func (c *Client) recvServerInfo() (*serverInfo, error) {
	if err := readType(c.br, typeServerInfo); err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err := io.ReadFull(c.br, nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce: %v", err)
	}
	msgLen, err := readUint32(c.br, oneMB)
	if err != nil {
		return nil, fmt.Errorf("msglen: %v", err)
	}
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
	var nonce [24]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return err
	}
	msg := []byte("{}") // no clientInfo for now
	msgbox := box.Seal(nil, msg, &nonce, c.serverKey.B32(), c.privateKey.B32())

	if _, err := c.bw.Write(c.publicKey[:]); err != nil {
		return err
	}
	if _, err := c.bw.Write(nonce[:]); err != nil {
		return err
	}
	if err := putUint32(c.bw, uint32(len(msgbox))); err != nil {
		return err
	}
	if _, err := c.bw.Write(msgbox); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *Client) Send(dstKey key.Public, msg []byte) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("derp.Send: %v", err)
		}
	}()

	if err := typeSendPacket.Write(c.bw); err != nil {
		return err
	}
	if _, err := c.bw.Write(dstKey[:]); err != nil {
		return err
	}
	msgLen := uint32(len(msg))
	if int(msgLen) != len(msg) {
		return fmt.Errorf("packet too big: %d", len(msg))
	}
	if err := putUint32(c.bw, msgLen); err != nil {
		return err
	}
	if _, err := c.bw.Write(msg); err != nil {
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

loop:
	for {
		c.nc.SetReadDeadline(time.Now().Add(120 * time.Second))
		typ, err := c.br.ReadByte()
		if err != nil {
			return 0, err
		}
		switch frameType(typ) {
		case typeKeepAlive:
			continue
		case typeRecvPacket:
			break loop
		default:
			return 0, fmt.Errorf("derp.Recv: unknown packet type 0x%X", typ)
		}
	}

	packetLen, err := readUint32(c.br, oneMB)
	if err != nil {
		return 0, err
	}
	if int(packetLen) > len(b) {
		// TODO(crawshaw): discard the packet
		return 0, io.ErrShortBuffer
	}
	b = b[:packetLen]
	if _, err := io.ReadFull(c.br, b); err != nil {
		return 0, err
	}
	return int(packetLen), nil
}
