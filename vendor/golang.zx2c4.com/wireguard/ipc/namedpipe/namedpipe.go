// Copyright 2021 The Go Authors. All rights reserved.
// Copyright 2015 Microsoft
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

// Package namedpipe implements a net.Conn and net.Listener around Windows named pipes.
package namedpipe

import (
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type pipe struct {
	*file
	path string
}

type messageBytePipe struct {
	pipe
	writeClosed int32
	readEOF     bool
}

type pipeAddress string

func (f *pipe) LocalAddr() net.Addr {
	return pipeAddress(f.path)
}

func (f *pipe) RemoteAddr() net.Addr {
	return pipeAddress(f.path)
}

func (f *pipe) SetDeadline(t time.Time) error {
	f.SetReadDeadline(t)
	f.SetWriteDeadline(t)
	return nil
}

// CloseWrite closes the write side of a message pipe in byte mode.
func (f *messageBytePipe) CloseWrite() error {
	if !atomic.CompareAndSwapInt32(&f.writeClosed, 0, 1) {
		return io.ErrClosedPipe
	}
	err := f.file.Flush()
	if err != nil {
		atomic.StoreInt32(&f.writeClosed, 0)
		return err
	}
	_, err = f.file.Write(nil)
	if err != nil {
		atomic.StoreInt32(&f.writeClosed, 0)
		return err
	}
	return nil
}

// Write writes bytes to a message pipe in byte mode. Zero-byte writes are ignored, since
// they are used to implement CloseWrite.
func (f *messageBytePipe) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&f.writeClosed) != 0 {
		return 0, io.ErrClosedPipe
	}
	if len(b) == 0 {
		return 0, nil
	}
	return f.file.Write(b)
}

// Read reads bytes from a message pipe in byte mode. A read of a zero-byte message on a message
// mode pipe will return io.EOF, as will all subsequent reads.
func (f *messageBytePipe) Read(b []byte) (int, error) {
	if f.readEOF {
		return 0, io.EOF
	}
	n, err := f.file.Read(b)
	if err == io.EOF {
		// If this was the result of a zero-byte read, then
		// it is possible that the read was due to a zero-size
		// message. Since we are simulating CloseWrite with a
		// zero-byte message, ensure that all future Read calls
		// also return EOF.
		f.readEOF = true
	} else if err == windows.ERROR_MORE_DATA {
		// ERROR_MORE_DATA indicates that the pipe's read mode is message mode
		// and the message still has more bytes. Treat this as a success, since
		// this package presents all named pipes as byte streams.
		err = nil
	}
	return n, err
}

func (f *pipe) Handle() windows.Handle {
	return f.handle
}

func (s pipeAddress) Network() string {
	return "pipe"
}

func (s pipeAddress) String() string {
	return string(s)
}

// tryDialPipe attempts to dial the specified pipe until cancellation or timeout.
func tryDialPipe(ctx context.Context, path *string) (windows.Handle, error) {
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			path16, err := windows.UTF16PtrFromString(*path)
			if err != nil {
				return 0, err
			}
			h, err := windows.CreateFile(path16, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS, 0)
			if err == nil {
				return h, nil
			}
			if err != windows.ERROR_PIPE_BUSY {
				return h, &os.PathError{Err: err, Op: "open", Path: *path}
			}
			// Wait 10 msec and try again. This is a rather simplistic
			// view, as we always try each 10 milliseconds.
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// DialConfig exposes various options for use in Dial and DialContext.
type DialConfig struct {
	ExpectedOwner *windows.SID // If non-nil, the pipe is verified to be owned by this SID.
}

// DialTimeout connects to the specified named pipe by path, timing out if the
// connection  takes longer than the specified duration. If timeout is zero, then
// we use a default timeout of 2 seconds.
func (config *DialConfig) DialTimeout(path string, timeout time.Duration) (net.Conn, error) {
	if timeout == 0 {
		timeout = time.Second * 2
	}
	absTimeout := time.Now().Add(timeout)
	ctx, _ := context.WithDeadline(context.Background(), absTimeout)
	conn, err := config.DialContext(ctx, path)
	if err == context.DeadlineExceeded {
		return nil, os.ErrDeadlineExceeded
	}
	return conn, err
}

// DialContext attempts to connect to the specified named pipe by path.
func (config *DialConfig) DialContext(ctx context.Context, path string) (net.Conn, error) {
	var err error
	var h windows.Handle
	h, err = tryDialPipe(ctx, &path)
	if err != nil {
		return nil, err
	}

	if config.ExpectedOwner != nil {
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			windows.Close(h)
			return nil, err
		}
		realOwner, _, err := sd.Owner()
		if err != nil {
			windows.Close(h)
			return nil, err
		}
		if !realOwner.Equals(config.ExpectedOwner) {
			windows.Close(h)
			return nil, windows.ERROR_ACCESS_DENIED
		}
	}

	var flags uint32
	err = windows.GetNamedPipeInfo(h, &flags, nil, nil, nil)
	if err != nil {
		windows.Close(h)
		return nil, err
	}

	f, err := makeFile(h)
	if err != nil {
		windows.Close(h)
		return nil, err
	}

	// If the pipe is in message mode, return a message byte pipe, which
	// supports CloseWrite.
	if flags&windows.PIPE_TYPE_MESSAGE != 0 {
		return &messageBytePipe{
			pipe: pipe{file: f, path: path},
		}, nil
	}
	return &pipe{file: f, path: path}, nil
}

var defaultDialer DialConfig

// DialTimeout calls DialConfig.DialTimeout using an empty configuration.
func DialTimeout(path string, timeout time.Duration) (net.Conn, error) {
	return defaultDialer.DialTimeout(path, timeout)
}

// DialContext calls DialConfig.DialContext using an empty configuration.
func DialContext(ctx context.Context, path string) (net.Conn, error) {
	return defaultDialer.DialContext(ctx, path)
}

type acceptResponse struct {
	f   *file
	err error
}

type pipeListener struct {
	firstHandle windows.Handle
	path        string
	config      ListenConfig
	acceptCh    chan chan acceptResponse
	closeCh     chan int
	doneCh      chan int
}

func makeServerPipeHandle(path string, sd *windows.SECURITY_DESCRIPTOR, c *ListenConfig, isFirstPipe bool) (windows.Handle, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var oa windows.OBJECT_ATTRIBUTES
	oa.Length = uint32(unsafe.Sizeof(oa))

	var ntPath windows.NTUnicodeString
	if err := windows.RtlDosPathNameToNtPathName(path16, &ntPath, nil, nil); err != nil {
		if ntstatus, ok := err.(windows.NTStatus); ok {
			err = ntstatus.Errno()
		}
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(ntPath.Buffer)))
	oa.ObjectName = &ntPath

	// The security descriptor is only needed for the first pipe.
	if isFirstPipe {
		if sd != nil {
			oa.SecurityDescriptor = sd
		} else {
			// Construct the default named pipe security descriptor.
			var acl *windows.ACL
			if err := windows.RtlDefaultNpAcl(&acl); err != nil {
				return 0, err
			}
			defer windows.LocalFree(windows.Handle(unsafe.Pointer(acl)))
			sd, err = windows.NewSecurityDescriptor()
			if err != nil {
				return 0, err
			}
			if err = sd.SetDACL(acl, true, false); err != nil {
				return 0, err
			}
			oa.SecurityDescriptor = sd
		}
	}

	typ := uint32(windows.FILE_PIPE_REJECT_REMOTE_CLIENTS)
	if c.MessageMode {
		typ |= windows.FILE_PIPE_MESSAGE_TYPE
	}

	disposition := uint32(windows.FILE_OPEN)
	access := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE | windows.SYNCHRONIZE)
	if isFirstPipe {
		disposition = windows.FILE_CREATE
		// By not asking for read or write access, the named pipe file system
		// will put this pipe into an initially disconnected state, blocking
		// client connections until the next call with isFirstPipe == false.
		access = windows.SYNCHRONIZE
	}

	timeout := int64(-50 * 10000) // 50ms

	var (
		h    windows.Handle
		iosb windows.IO_STATUS_BLOCK
	)
	err = windows.NtCreateNamedPipeFile(&h, access, &oa, &iosb, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, disposition, 0, typ, 0, 0, 0xffffffff, uint32(c.InputBufferSize), uint32(c.OutputBufferSize), &timeout)
	if err != nil {
		if ntstatus, ok := err.(windows.NTStatus); ok {
			err = ntstatus.Errno()
		}
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}

	runtime.KeepAlive(ntPath)
	return h, nil
}

func (l *pipeListener) makeServerPipe() (*file, error) {
	h, err := makeServerPipeHandle(l.path, nil, &l.config, false)
	if err != nil {
		return nil, err
	}
	f, err := makeFile(h)
	if err != nil {
		windows.Close(h)
		return nil, err
	}
	return f, nil
}

func (l *pipeListener) makeConnectedServerPipe() (*file, error) {
	p, err := l.makeServerPipe()
	if err != nil {
		return nil, err
	}

	// Wait for the client to connect.
	ch := make(chan error)
	go func(p *file) {
		ch <- connectPipe(p)
	}(p)

	select {
	case err = <-ch:
		if err != nil {
			p.Close()
			p = nil
		}
	case <-l.closeCh:
		// Abort the connect request by closing the handle.
		p.Close()
		p = nil
		err = <-ch
		if err == nil || err == os.ErrClosed {
			err = net.ErrClosed
		}
	}
	return p, err
}

func (l *pipeListener) listenerRoutine() {
	closed := false
	for !closed {
		select {
		case <-l.closeCh:
			closed = true
		case responseCh := <-l.acceptCh:
			var (
				p   *file
				err error
			)
			for {
				p, err = l.makeConnectedServerPipe()
				// If the connection was immediately closed by the client, try
				// again.
				if err != windows.ERROR_NO_DATA {
					break
				}
			}
			responseCh <- acceptResponse{p, err}
			closed = err == net.ErrClosed
		}
	}
	windows.Close(l.firstHandle)
	l.firstHandle = 0
	// Notify Close and Accept callers that the handle has been closed.
	close(l.doneCh)
}

// ListenConfig contains configuration for the pipe listener.
type ListenConfig struct {
	// SecurityDescriptor contains a Windows security descriptor. If nil, the default from RtlDefaultNpAcl is used.
	SecurityDescriptor *windows.SECURITY_DESCRIPTOR

	// MessageMode determines whether the pipe is in byte or message mode. In either
	// case the pipe is read in byte mode by default. The only practical difference in
	// this implementation is that CloseWrite is only supported for message mode pipes;
	// CloseWrite is implemented as a zero-byte write, but zero-byte writes are only
	// transferred to the reader (and returned as io.EOF in this implementation)
	// when the pipe is in message mode.
	MessageMode bool

	// InputBufferSize specifies the initial size of the input buffer, in bytes, which the OS will grow as needed.
	InputBufferSize int32

	// OutputBufferSize specifies the initial size of the output buffer, in bytes, which the OS will grow as needed.
	OutputBufferSize int32
}

// Listen creates a listener on a Windows named pipe path,such as \\.\pipe\mypipe.
// The pipe must not already exist.
func (c *ListenConfig) Listen(path string) (net.Listener, error) {
	h, err := makeServerPipeHandle(path, c.SecurityDescriptor, c, true)
	if err != nil {
		return nil, err
	}
	l := &pipeListener{
		firstHandle: h,
		path:        path,
		config:      *c,
		acceptCh:    make(chan chan acceptResponse),
		closeCh:     make(chan int),
		doneCh:      make(chan int),
	}
	// The first connection is swallowed on Windows 7 & 8, so synthesize it.
	if maj, min, _ := windows.RtlGetNtVersionNumbers(); maj < 6 || (maj == 6 && min < 4) {
		path16, err := windows.UTF16PtrFromString(path)
		if err == nil {
			h, err = windows.CreateFile(path16, 0, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS, 0)
			if err == nil {
				windows.CloseHandle(h)
			}
		}
	}
	go l.listenerRoutine()
	return l, nil
}

var defaultListener ListenConfig

// Listen calls ListenConfig.Listen using an empty configuration.
func Listen(path string) (net.Listener, error) {
	return defaultListener.Listen(path)
}

func connectPipe(p *file) error {
	c, err := p.prepareIo()
	if err != nil {
		return err
	}
	defer p.wg.Done()

	err = windows.ConnectNamedPipe(p.handle, &c.o)
	_, err = p.asyncIo(c, nil, 0, err)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return err
	}
	return nil
}

func (l *pipeListener) Accept() (net.Conn, error) {
	ch := make(chan acceptResponse)
	select {
	case l.acceptCh <- ch:
		response := <-ch
		err := response.err
		if err != nil {
			return nil, err
		}
		if l.config.MessageMode {
			return &messageBytePipe{
				pipe: pipe{file: response.f, path: l.path},
			}, nil
		}
		return &pipe{file: response.f, path: l.path}, nil
	case <-l.doneCh:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	select {
	case l.closeCh <- 1:
		<-l.doneCh
	case <-l.doneCh:
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return pipeAddress(l.path)
}
