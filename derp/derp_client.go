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
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type Client struct {
	serverKey    key.Public // of the DERP server; not a machine or node key
	privateKey   key.Private
	publicKey    key.Public // of privateKey
	protoVersion int        // min of server+client
	logf         logger.Logf
	nc           Conn
	br           *bufio.Reader

	wmu     sync.Mutex // hold while writing to bw
	bw      *bufio.Writer
	readErr error // sticky read error
}

func NewClient(privateKey key.Private, nc Conn, brw *bufio.ReadWriter, logf logger.Logf) (*Client, error) {
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
	info, err := c.recvServerInfo()
	if err != nil {
		return nil, fmt.Errorf("derp.Client: failed to receive server info: %v", err)
	}
	c.protoVersion = minInt(protocolVersion, info.Version)
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

type clientInfo struct {
	Version int // `json:"version,omitempty"`
}

func (c *Client) sendClientKey() error {
	var nonce [nonceLen]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return err
	}
	msg, err := json.Marshal(clientInfo{Version: protocolVersion})
	if err != nil {
		return err
	}
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
			ret = fmt.Errorf("derp.Send: %w", ret)
		}
	}()

	if len(pkt) > MaxPacketSize {
		return fmt.Errorf("packet too big: %d", len(pkt))
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()

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

// NotePreferred sends a packet that tells the server whether this
// client is the user's preferred server. This is only used in the
// server for stats.
func (c *Client) NotePreferred(preferred bool) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("derp.NotePreferred: %v", err)
		}
	}()

	c.wmu.Lock()
	defer c.wmu.Unlock()

	if err := writeFrameHeader(c.bw, frameNotePreferred, 1); err != nil {
		return err
	}
	var b byte = 0x00
	if preferred {
		b = 0x01
	}
	if err := c.bw.WriteByte(b); err != nil {
		return err
	}
	return c.bw.Flush()
}

// ReceivedMessage represents a type returned by Client.Recv. Unless
// otherwise documented, the returned message aliases the byte slice
// provided to Recv and thus the message is only as good as that
// buffer, which is up to the caller.
type ReceivedMessage interface {
	msg()
}

// ReceivedPacket is a ReceivedMessage representing an incoming packet.
type ReceivedPacket struct {
	Source key.Public
	// Data is the received packet bytes. It aliases the memory
	// passed to Client.Recv.
	Data []byte
}

func (ReceivedPacket) msg() {}

// Recv reads a message from the DERP server.
// The provided buffer must be large enough to receive a complete packet,
// which in practice are are 1.5-4 KB, but can be up to 64 KB.
// Once Recv returns an error, the Client is dead forever.
func (c *Client) Recv(b []byte) (m ReceivedMessage, err error) {
	if c.readErr != nil {
		return nil, c.readErr
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("derp.Recv: %w", err)
			c.readErr = err
		}
	}()

	for {
		c.nc.SetReadDeadline(time.Now().Add(120 * time.Second))
		t, n, err := readFrame(c.br, 1<<20, b)
		if err != nil {
			return nil, err
		}
		switch t {
		default:
			continue
		case frameKeepAlive:
			// TODO: eventually we'll have server->client pings that
			// require ack pongs.
			continue
		case frameRecvPacket:
			var rp ReceivedPacket
			if c.protoVersion < protocolSrcAddrs {
				rp.Data = b[:n]
			} else {
				if n < keyLen {
					c.logf("[unexpected] dropping short packet from DERP server")
					continue
				}
				copy(rp.Source[:], b[:keyLen])
				rp.Data = b[keyLen:n]
			}
			return rp, nil
		}
	}
}
