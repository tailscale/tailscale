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

// Client is a DERP client.
type Client struct {
	serverKey  key.Public // of the DERP server; not a machine or node key
	privateKey key.Private
	publicKey  key.Public // of privateKey
	logf       logger.Logf
	nc         Conn
	br         *bufio.Reader
	meshKey    string

	wmu sync.Mutex // hold while writing to bw
	bw  *bufio.Writer

	// Owned by Recv:
	peeked  int   // bytes to discard on next Recv
	readErr error // sticky read error
}

// ClientOpt is an option passed to NewClient.
type ClientOpt interface {
	update(*clientOpt)
}

type clientOptFunc func(*clientOpt)

func (f clientOptFunc) update(o *clientOpt) { f(o) }

// clientOpt are the options passed to newClient.
type clientOpt struct {
	MeshKey   string
	ServerPub key.Public
}

// MeshKey returns a ClientOpt to pass to the DERP server during connect to get
// access to join the mesh.
//
// An empty key means to not use a mesh key.
func MeshKey(key string) ClientOpt { return clientOptFunc(func(o *clientOpt) { o.MeshKey = key }) }

// ServerPublicKey returns a ClientOpt to declare that the server's DERP public key is known.
// If key is the zero value, the returned ClientOpt is a no-op.
func ServerPublicKey(key key.Public) ClientOpt {
	return clientOptFunc(func(o *clientOpt) { o.ServerPub = key })
}

func NewClient(privateKey key.Private, nc Conn, brw *bufio.ReadWriter, logf logger.Logf, opts ...ClientOpt) (*Client, error) {
	var opt clientOpt
	for _, o := range opts {
		if o == nil {
			return nil, errors.New("nil ClientOpt")
		}
		o.update(&opt)
	}
	return newClient(privateKey, nc, brw, logf, opt)
}

func newClient(privateKey key.Private, nc Conn, brw *bufio.ReadWriter, logf logger.Logf, opt clientOpt) (*Client, error) {
	c := &Client{
		privateKey: privateKey,
		publicKey:  privateKey.Public(),
		logf:       logf,
		nc:         nc,
		br:         brw.Reader,
		bw:         brw.Writer,
		meshKey:    opt.MeshKey,
	}
	if opt.ServerPub.IsZero() {
		if err := c.recvServerKey(); err != nil {
			return nil, fmt.Errorf("derp.Client: failed to receive server key: %v", err)
		}
	} else {
		c.serverKey = opt.ServerPub
	}
	if err := c.sendClientKey(); err != nil {
		return nil, fmt.Errorf("derp.Client: failed to send client key: %v", err)
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

func (c *Client) parseServerInfo(b []byte) (*serverInfo, error) {
	const maxLength = nonceLen + maxInfoLen
	fl := len(b)
	if fl < nonceLen {
		return nil, fmt.Errorf("short serverInfo frame")
	}
	if fl > maxLength {
		return nil, fmt.Errorf("long serverInfo frame")
	}
	// TODO: add a read-nonce-and-box helper
	var nonce [nonceLen]byte
	copy(nonce[:], b)
	msgbox := b[nonceLen:]
	msg, ok := box.Open(nil, msgbox, &nonce, c.serverKey.B32(), c.privateKey.B32())
	if !ok {
		return nil, fmt.Errorf("failed to open naclbox from server key %x", c.serverKey[:])
	}
	info := new(serverInfo)
	if err := json.Unmarshal(msg, info); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	return info, nil
}

type clientInfo struct {
	Version int `json:"version,omitempty"`

	// MeshKey optionally specifies a pre-shared key used by
	// trusted clients.  It's required to subscribe to the
	// connection list & forward packets. It's empty for regular
	// users.
	MeshKey string `json:"meshKey,omitempty"`
}

func (c *Client) sendClientKey() error {
	var nonce [nonceLen]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return err
	}
	msg, err := json.Marshal(clientInfo{
		Version: ProtocolVersion,
		MeshKey: c.meshKey,
	})
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

// ServerPublicKey returns the server's public key.
func (c *Client) ServerPublicKey() key.Public { return c.serverKey }

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

func (c *Client) ForwardPacket(srcKey, dstKey key.Public, pkt []byte) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("derp.ForwardPacket: %w", err)
		}
	}()

	if len(pkt) > MaxPacketSize {
		return fmt.Errorf("packet too big: %d", len(pkt))
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()

	timer := time.AfterFunc(5*time.Second, c.writeTimeoutFired)
	defer timer.Stop()

	if err := writeFrameHeader(c.bw, frameForwardPacket, uint32(keyLen*2+len(pkt))); err != nil {
		return err
	}
	if _, err := c.bw.Write(srcKey[:]); err != nil {
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

func (c *Client) writeTimeoutFired() { c.nc.Close() }

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

// WatchConnectionChanges sends a request to subscribe to the peer's connection list.
// It's a fatal error if the client wasn't created using MeshKey.
func (c *Client) WatchConnectionChanges() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := writeFrameHeader(c.bw, frameWatchConns, 0); err != nil {
		return err
	}
	return c.bw.Flush()
}

// ClosePeer asks the server to close target's TCP connection.
// It's a fatal error if the client wasn't created using MeshKey.
func (c *Client) ClosePeer(target key.Public) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return writeFrame(c.bw, frameClosePeer, target[:])
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

// PeerGoneMessage is a ReceivedMessage that indicates that the client
// identified by the underlying public key had previously sent you a
// packet but has now disconnected from the server.
type PeerGoneMessage key.Public

func (PeerGoneMessage) msg() {}

// PeerPresentMessage is a ReceivedMessage that indicates that the client
// is connected to the server. (Only used by trusted mesh clients)
type PeerPresentMessage key.Public

func (PeerPresentMessage) msg() {}

// ServerInfoMessage is sent by the server upon first connect.
type ServerInfoMessage struct{}

func (ServerInfoMessage) msg() {}

// Recv reads a message from the DERP server.
//
// The returned message may alias memory owned by the Client; it
// should only be accessed until the next call to Client.
//
// Once Recv returns an error, the Client is dead forever.
func (c *Client) Recv() (m ReceivedMessage, err error) {
	return c.recvTimeout(120 * time.Second)
}

func (c *Client) recvTimeout(timeout time.Duration) (m ReceivedMessage, err error) {
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
		c.nc.SetReadDeadline(time.Now().Add(timeout))

		// Discard any peeked bytes from a previous Recv call.
		if c.peeked != 0 {
			if n, err := c.br.Discard(c.peeked); err != nil || n != c.peeked {
				// Documented to never fail, but might as well check.
				return nil, fmt.Errorf("bufio.Reader.Discard(%d bytes): got %v, %v", c.peeked, n, err)
			}
			c.peeked = 0
		}

		t, n, err := readFrameHeader(c.br)
		if err != nil {
			return nil, err
		}
		if n > 1<<20 {
			return nil, fmt.Errorf("unexpectedly large frame of %d bytes returned", n)
		}

		var b []byte // frame payload (past the 5 byte header)

		// If the frame fits in our bufio.Reader buffer, just use it.
		// In practice it's 4KB (from derphttp.Client's bufio.NewReader(httpConn)) and
		// in practive, WireGuard packets (and thus DERP frames) are under 1.5KB.
		// So this is the common path.
		if int(n) <= c.br.Size() {
			b, err = c.br.Peek(int(n))
			c.peeked = int(n)
		} else {
			// But if for some reason we read a large DERP message (which isn't necessarily
			// a Wireguard packet), then just allocate memory for it.
			// TODO(bradfitz): use a pool if large frames ever happen in practice.
			b = make([]byte, n)
			_, err = io.ReadFull(c.br, b)
		}
		if err != nil {
			return nil, err
		}

		switch t {
		default:
			continue
		case frameServerInfo:
			// Server sends this at start-up. Currently unused.
			// Just has a JSON message saying "version: 2",
			// but the protocol seems extensible enough as-is without
			// needing to wait an RTT to discover the version at startup.
			// We'd prefer to give the connection to the client (magicsock)
			// to start writing as soon as possible.
			_, err := c.parseServerInfo(b)
			if err != nil {
				return nil, fmt.Errorf("invalid server info frame: %v", err)
			}
			// TODO: add the results of parseServerInfo to ServerInfoMessage if we ever need it.
			return ServerInfoMessage{}, nil
		case frameKeepAlive:
			// TODO: eventually we'll have server->client pings that
			// require ack pongs.
			continue
		case framePeerGone:
			if n < keyLen {
				c.logf("[unexpected] dropping short peerGone frame from DERP server")
				continue
			}
			var pg PeerGoneMessage
			copy(pg[:], b[:keyLen])
			return pg, nil

		case framePeerPresent:
			if n < keyLen {
				c.logf("[unexpected] dropping short peerPresent frame from DERP server")
				continue
			}
			var pg PeerPresentMessage
			copy(pg[:], b[:keyLen])
			return pg, nil

		case frameRecvPacket:
			var rp ReceivedPacket
			if n < keyLen {
				c.logf("[unexpected] dropping short packet from DERP server")
				continue
			}
			copy(rp.Source[:], b[:keyLen])
			rp.Data = b[keyLen:n]
			return rp, nil
		}
	}
}
