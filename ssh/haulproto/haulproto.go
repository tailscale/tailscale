// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package haulproto contains components for the SSH Session Hauling protocol.
package haulproto

// The SSH Session Hauling Protocol.
//
// The SSH Session Hauling Protocol transports SSH session logs from a source
// to a destination node within Tailscale.
//
// The protocol runs over an upgraded HTTP/1.1 connection. The upgrade is done
// using the "ts-ssh-haul" Upgrade header. The client must send the name of the
// session file to create as the SSH-Session-Name header.
//
// After the server has performed the upgrade, frames may be sent. The client
// begins by sending a Resume frame, the server replies with a Resume frame
// indicating the offset of the last byte it has persisted. If it hasn't
// persisted any bytes it returns 0. The client then begins sending Bytes
// frames, each of which includes an opaque seqence of bytes. The client should
// send an Ack frame with an ID of 0 after a batch of Bytes frames. The server
// will then send an Ack frame in reply with the offset of the last byte is has
// persisted. The client should only have a small number of unacknowledged
// Bytes frames. When the client is finished sending all of the bytes, it
// should send a final Ack frame to ensure that all bytes have been persisted.
// After a final Ack from the server is received, the client can close the
// connection.
//
// The server, upon completing the upgrade, waits for a Resume frame and
// replies with the offset of the last byte it has persisted, then it waits for
// the client to send Bytes frames. Upon receiving frames the server persists
// the bytes to disk. Upon receiving an Ack frame the server replies with the
// offset of the last byte it has persisted.
//
// A frame consists of a frame header followed by an optional frame payload. A
// frame header consists of a 4 byte uint32 length in network byte order,
// followed by a 1 byte type, followed by an 8 byte uint64 offset in network
// byte order. The offset in a Resume or Acknowledgement frame is the offset of
// the last persisted byte. The offset in a Bytes frame is the offset of the
// first byte in the payload.
import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"tailscale.com/types/logger"
)

var ErrIrreconcilable = errors.New("client and server state are irreconcilable")
var ErrClosed = errors.New("client is closed")

const UpgradeProto = "ts-ssh-log"

// FrameHeaderSize is the size of a frame header. 4 bytes for length, 1 byte
// for type, and 8 bytes for the offset.
const FrameHeaderSize = 13

// FrameType is used to identify the type of a given frame.
type FrameType uint8

// These are the types of frames:
const (
	FTUndefined FrameType = 0 // Invalid frame
	FTBytes     FrameType = 1 // Bytes
	FTAck       FrameType = 2 // Acknowledgement
	FTResume    FrameType = 3 // Resume Sending Logs
)

func (ft FrameType) String() string {
	switch ft {
	case FTUndefined:
		return "undefined"
	case FTBytes:
		return "bytes"
	case FTAck:
		return "acknowledgement"
	case FTResume:
		return "resume"
	default:
		return "unknown"
	}
}

// DecodeHeader reads the length, frame type, and offset from a slice of
// bytes representing the frame header.
func DecodeHeader(hdr [13]byte) (uint32, FrameType, uint64) {
	l := binary.BigEndian.Uint32(hdr[0:4])
	ft := FrameType(hdr[4])
	id := binary.BigEndian.Uint64(hdr[5:])
	return l, ft, id
}

type FrameBuilder struct{}

func (fb FrameBuilder) Bytes(id uint64, msg []byte) []byte {
	buf := make([]byte, 0, FrameHeaderSize)
	return fb.AppendBytes(buf, id, msg)
}

func (FrameBuilder) AppendBytes(dst []byte, id uint64, msg []byte) []byte {
	// 4 byte length + 1 byte type + 8 byte ID + msg length
	var l = uint32(13 + len(msg))
	dst = binary.BigEndian.AppendUint32(dst, l)
	dst = append(dst, byte(FTBytes))
	dst = binary.BigEndian.AppendUint64(dst, id)
	return append(dst, msg...)
}

// AddBytesHeader adds a Bytes frame header to dst. It expects the destination
// slice to be at least 13 bytes long and panics if it's not. This method assumes
// that the first 13 bytes are for the header and overwrites whatever is there.
func (FrameBuilder) AddBytesHeader(dst []byte, offset uint64) {
	// The buffer should already be allocated to have the first 13 bytes empty
	// so we can just use the length of dst.
	if len(dst) < 13 {
		panic("dst too small")
	}
	binary.BigEndian.PutUint32(dst[0:4], uint32(len(dst)))
	dst[4] = byte(FTBytes)
	binary.BigEndian.PutUint64(dst[5:13], offset)
}

func (fb FrameBuilder) Ack(ack uint64) []byte {
	return fb.AppendAck(make([]byte, 0, FrameHeaderSize), ack)
}

func (fb FrameBuilder) AppendAck(dst []byte, ack uint64) []byte {
	return fb.nopayload(dst, ack, FTAck)
}

func (fb FrameBuilder) AckArray(dst [13]byte, ack uint64) {
	binary.BigEndian.PutUint32(dst[0:4], uint32(FrameHeaderSize))
	dst[4] = byte(FTAck)
	binary.BigEndian.PutUint64(dst[5:13], ack)
}

func (fb FrameBuilder) Resume(maxAck uint64) []byte {
	return fb.AppendResume(make([]byte, 0, FrameHeaderSize), maxAck)
}

func (fb FrameBuilder) AppendResume(dst []byte, maxAck uint64) []byte {
	return fb.nopayload(dst, maxAck, FTResume)
}

func (FrameBuilder) nopayload(dst []byte, id uint64, ft FrameType) []byte {
	dst = binary.BigEndian.AppendUint32(dst, FrameHeaderSize)
	dst = append(dst, byte(ft))
	return binary.BigEndian.AppendUint64(dst, id)
}

type Client struct {
	fb   FrameBuilder
	logf logger.Logf

	src io.ReadSeekCloser // .cast file

	mu     sync.Mutex
	closed chan struct{}
	ping   chan struct{}
}

func NewClient(logf logger.Logf, src io.ReadSeekCloser) *Client {
	return &Client{
		logf:   logf,
		ping:   make(chan struct{}, 1),
		closed: make(chan struct{}, 1),
		src:    src,
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return nil
	default:
	}
	close(c.closed)
	return nil // We don't close the file here because we need to do some cleanup.
}

func (c *Client) Run(ctx context.Context, dst io.ReadWriter) error {
	// TODO(skriptble): When we've closed the client we don't want to exit immediately,
	// instead we want to attempt to finish sending the logs to the other end.
	// Alternatively we might want to have the server connect to this node and attempt
	// to pull any remaining log lines that might have been missed in the shutdown
	// process.
	select {
	case <-c.closed:
		return ErrClosed
	default:
	}
	const maxframes = 100           // arbitrary
	const maxbuf = 1 << 15          // read max of 32KB, arbitrary
	const ackRate = 5 * time.Second // How often we'll send acks.
	var fb FrameBuilder
	var hdr [13]byte

	// Get length of the file
	end, err := c.src.Seek(0, io.SeekEnd)
	if err != nil {
		c.logf("Couldn't seek to the end of src: %v", err)
		return fmt.Errorf("couldn't seek to the end of src: %v", err)
	}

	// First send a Resume frame to understand where to start sending from.
	resume := fb.Resume(0)
	_, err = dst.Write(resume)
	if err != nil {
		c.logf("Couldn't write resume frame: %v", err)
		return fmt.Errorf("couldn't write resume frame: %w", err)
	}
	_, err = io.ReadFull(dst, hdr[:])
	if err != nil {
		c.logf("Couldn't read response to resume frame: %v", err)
		return fmt.Errorf("couldn't read response resume frame: %w", err)
	}
	l, ft, off := DecodeHeader(hdr)
	if ft != FTResume || l != 13 {
		// TODO(skriptble): Is there any reason we shouldn't just accept
		// any frame and throw away incorrect ones?
		return fmt.Errorf("incorrect frame type %q or length %d", ft, l)
	}
	if off > uint64(end) {
		// The server has asked for an offset that is past the end of our current
		// file, maybe a file was renamed or something.
		return fmt.Errorf("server requesting resumption from invalid offset %d", off)
	}
	_, err = c.src.Seek(int64(off), io.SeekStart)
	if err != nil {
		c.logf("Couldn't seek to offset: %v", err)
		return fmt.Errorf("couldn't seek to offset: %v", err)
	}

	buf := make([]byte, maxbuf+FrameHeaderSize)
	var n int
	ticker := time.NewTicker(ackRate)

	// Send frames until we've caught up, and then wait for a notification that
	// there are more log lines to process and send.
	for {
		select {
		case <-ticker.C:
			c.fb.AckArray(hdr, 0)
			_, err = dst.Write(hdr[:])
			if err != nil {
				c.logf("couldn't write ack frame: %v", err)
				return fmt.Errorf("couldn't write ack frame: %w", err)
			}
			_, err = io.ReadFull(dst, hdr[:])
			if err != nil {
				c.logf("Couldn't read ack response: %v", err)
				return fmt.Errorf("couldn't read response ack response: %w", err)
			}
			// Not checking the actual offset returned here. In theory we could offset
			// and then seek to the next byte in the file, but the underlying transport
			// here assumes that it is ordered (e.g. TCP), so we should never have a difference
			// between the offset that we get back and our current offset.
			//
			// TOOD(skriptble): Think about this some more. Maybe it's worth putting the check
			// here anyway.
			l, ft, _ = DecodeHeader(hdr)
			if ft != FTAck || l != 13 {
				return fmt.Errorf("incorrect frame type %q or length %d", ft, l)
			}
		default:
		}
		buf = buf[:cap(buf)]
		n, err = c.src.Read(buf[FrameHeaderSize:]) // Leave room for the frame header.
		if err == io.EOF {
			// We've reached the end of the file, wait for more bytes to be written.
			select {
			case <-c.ping:
				continue
			case <-ctx.Done():
				// TODO(skriptble): Attempt to perform a clean shutdown?
				return ctx.Err()
			case <-c.closed:
				defer c.src.Close()
				return ErrClosed
			}
		}
		buf = buf[:n+FrameHeaderSize]

		c.fb.AddBytesHeader(buf, off)
		off += uint64(n)

		_, err = dst.Write(buf)
		if err != nil {
			c.logf("couldn't write frames: %v", err)
			return fmt.Errorf("couldn't write frames: %w", err)
		}
	}
}

func (c *Client) Notify() {
	if c == nil {
		return
	}
	select {
	case c.ping <- struct{}{}:
	default:
	}
}

type Server struct {
	dst  io.ReadWriteSeeker
	logf logger.Logf
}

func NewServer(dst io.ReadWriteSeeker, logf logger.Logf) *Server {
	return &Server{dst: dst, logf: logf}
}

func (s *Server) Run(ctx context.Context, src io.ReadWriteCloser) error {
	var fb FrameBuilder
	var hdr [13]byte

	// First read a Resume frame and reply with the current offset.
	_, err := io.ReadFull(src, hdr[:])
	if err != nil {
		return err
	}
	l, ft, srcOff := DecodeHeader(hdr)
	if ft != FTResume || l != 13 || srcOff != 0 {
		return fmt.Errorf("incorrect frame type %q or length %d", ft, l)
	}
	dstOff, err := s.dst.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	resume := fb.Resume(uint64(dstOff))
	_, err = src.Write(resume)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		// If we get a context cancel or timeout, just close the connection.
		<-ctx.Done()
		src.Close()
	}()
	for {
		_, err = io.ReadFull(src, hdr[:])
		if err != nil {
			return err
		}
		l, ft, srcOff = DecodeHeader(hdr)
		switch ft {
		case FTBytes:
			// Is the offset of the first byte in this payload equal to the offset of the next byte we want to write?
			if srcOff != uint64(dstOff) {
				s.logf("logoproto-server unexpected bytes message offset: expected=%d got=%d", dstOff, srcOff)
				return fmt.Errorf("incorrect bytes message offset: expected=%d got=%d", dstOff, srcOff)
			}
			n, err := io.CopyN(s.dst, src, int64(l-FrameHeaderSize))
			if err != nil {
				return err
			}
			s.logf("received Bytes Frame for offset=%d wrote %d bytes", srcOff, n)
			dstOff += n
		case FTAck:
			ack := fb.Ack(uint64(dstOff))
			_, err = src.Write(ack)
			if err != nil {
				s.logf("logproto-server couldn't send ack: %v", err)
				return err
			}
			s.logf("received ack request sending ack of offset=%d", dstOff)
		case FTResume, FTUndefined:
			return fmt.Errorf("incorrect frame type %q", ft)
		default:
			return fmt.Errorf("unknown frame type %q (%d)", ft, ft)
		}
	}
}
