// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/structs"
	"tailscale.com/version"
)

type readOnlyContextKey struct{}

// IsReadonlyContext reports whether ctx is a read-only context, as currently used
// by Unix non-root users running the "tailscale" CLI command. They can run "status",
// but not much else.
func IsReadonlyContext(ctx context.Context) bool {
	return ctx.Value(readOnlyContextKey{}) != nil
}

// ReadonlyContextOf returns ctx wrapped with a context value that
// will make IsReadonlyContext reports true.
func ReadonlyContextOf(ctx context.Context) context.Context {
	if IsReadonlyContext(ctx) {
		return ctx
	}
	return context.WithValue(ctx, readOnlyContextKey{}, readOnlyContextKey{})
}

var jsonEscapedZero = []byte(`\u0000`)

type NoArgs struct{}

type StartArgs struct {
	Opts Options
}

type SetPrefsArgs struct {
	New *Prefs
}

// Command is a command message that is JSON encoded and sent by a
// frontend to a backend.
type Command struct {
	_ structs.Incomparable

	// Version is the binary version of the frontend (the client).
	Version string

	// AllowVersionSkew controls whether it's permitted for the
	// client and server to have a different version. The default
	// (false) means to be strict.
	AllowVersionSkew bool

	// Exactly one of the following must be non-nil.
	Quit                  *NoArgs
	Start                 *StartArgs
	StartLoginInteractive *NoArgs
	Login                 *tailcfg.Oauth2Token
	Logout                *NoArgs
	SetPrefs              *SetPrefsArgs
	RequestEngineStatus   *NoArgs
	RequestStatus         *NoArgs
}

type BackendServer struct {
	logf          logger.Logf
	b             Backend      // the Backend we are serving up
	sendNotifyMsg func(Notify) // send a notification message
	GotQuit       bool         // a Quit command was received
}

// NewBackendServer creates a new BackendServer using b.
//
// If sendNotifyMsg is non-nil, it additionally sets the Backend's
// notification callback to call the func with ipn.Notify messages in
// JSON form. If nil, it does not change the notification callback.
func NewBackendServer(logf logger.Logf, b Backend, sendNotifyMsg func(Notify)) *BackendServer {
	bs := &BackendServer{
		logf:          logf,
		b:             b,
		sendNotifyMsg: sendNotifyMsg,
	}
	// b may be nil if the BackendServer is being created just to
	// encapsulate and send an error message.
	if sendNotifyMsg != nil && b != nil {
		b.SetNotifyCallback(bs.send)
	}
	return bs
}

func (bs *BackendServer) send(n Notify) {
	if bs.sendNotifyMsg == nil {
		return
	}
	n.Version = ipcVersion
	bs.sendNotifyMsg(n)
}

func (bs *BackendServer) SendErrorMessage(msg string) {
	bs.send(Notify{ErrMessage: &msg})
}

// SendInUseOtherUserErrorMessage sends a Notify message to the client that
// both sets the state to 'InUseOtherUser' and sets the associated reason
// to msg.
func (bs *BackendServer) SendInUseOtherUserErrorMessage(msg string) {
	inUse := InUseOtherUser
	bs.send(Notify{
		State:      &inUse,
		ErrMessage: &msg,
	})
}

// GotCommandMsg parses the incoming message b as a JSON Command and
// calls GotCommand with it.
func (bs *BackendServer) GotCommandMsg(ctx context.Context, b []byte) error {
	cmd := &Command{}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, cmd); err != nil {
		return err
	}
	return bs.GotCommand(ctx, cmd)
}

// ErrMsgPermissionDenied is the Notify.ErrMessage value used an
// operation was done from a user/context that didn't have permission.
const ErrMsgPermissionDenied = "permission denied"

func (bs *BackendServer) GotCommand(ctx context.Context, cmd *Command) error {
	if cmd.Version != ipcVersion && !cmd.AllowVersionSkew {
		vs := fmt.Sprintf("GotCommand: Version mismatch! frontend=%#v backend=%#v",
			cmd.Version, ipcVersion)
		bs.logf("%s", vs)
		// ignore the command, but send a message back to the
		// caller so it can realize the version mismatch too.
		// We don't want to exit because it might cause a crash
		// loop, and restarting won't fix the problem.
		bs.send(Notify{
			ErrMessage: &vs,
		})
		return nil
	}

	// TODO(bradfitz): finish plumbing context down to all the methods below;
	// currently we just check for read-only contexts in this method and
	// then never use contexts again.

	// Actions permitted with a read-only context:
	if c := cmd.RequestEngineStatus; c != nil {
		bs.b.RequestEngineStatus()
		return nil
	}

	if IsReadonlyContext(ctx) {
		msg := ErrMsgPermissionDenied
		bs.send(Notify{ErrMessage: &msg})
		return nil
	}

	if cmd.Quit != nil {
		bs.GotQuit = true
		return errors.New("Quit command received")
	} else if c := cmd.Start; c != nil {
		opts := c.Opts
		return bs.b.Start(opts)
	} else if c := cmd.StartLoginInteractive; c != nil {
		bs.b.StartLoginInteractive()
		return nil
	} else if c := cmd.Login; c != nil {
		bs.b.Login(c)
		return nil
	} else if c := cmd.Logout; c != nil {
		bs.b.Logout()
		return nil
	} else if c := cmd.SetPrefs; c != nil {
		bs.b.SetPrefs(c.New)
		return nil
	}
	return fmt.Errorf("BackendServer.Do: no command specified")
}

type BackendClient struct {
	logf           logger.Logf
	sendCommandMsg func(jsonb []byte)
	notify         func(Notify)

	// AllowVersionSkew controls whether to allow mismatched
	// frontend & backend versions.
	AllowVersionSkew bool
}

func NewBackendClient(logf logger.Logf, sendCommandMsg func(jsonb []byte)) *BackendClient {
	return &BackendClient{
		logf:           logf,
		sendCommandMsg: sendCommandMsg,
	}
}

// IPCVersion returns version.Long usually, unless TS_DEBUG_FAKE_IPC_VERSION is
// set, in which it contains that value. This is only used for weird development
// cases when testing mismatched versions and you want the client to act like it's
// compatible with the server.
func IPCVersion() string {
	if v := envknob.String("TS_DEBUG_FAKE_IPC_VERSION"); v != "" {
		return v
	}
	return version.Long
}

var ipcVersion = IPCVersion()

func (bc *BackendClient) GotNotifyMsg(b []byte) {
	if len(b) == 0 {
		// not interesting
		return
	}
	if bytes.Contains(b, jsonEscapedZero) {
		log.Printf("[unexpected] zero byte in BackendClient.GotNotifyMsg message: %q", b)
	}
	n := Notify{}
	if err := json.Unmarshal(b, &n); err != nil {
		log.Fatalf("BackendClient.Notify: cannot decode message (length=%d, %#q): %v", len(b), b, err)
	}
	if n.Version != ipcVersion && !bc.AllowVersionSkew {
		vs := fmt.Sprintf("GotNotify: Version mismatch! frontend=%#v backend=%#v",
			ipcVersion, n.Version)
		bc.logf("%s", vs)
		// delete anything in the notification except the version,
		// to prevent incorrect operation.
		n = Notify{
			Version:    n.Version,
			ErrMessage: &vs,
		}
	}
	if bc.notify != nil {
		bc.notify(n)
	}
}

func (bc *BackendClient) send(cmd Command) {
	cmd.Version = ipcVersion
	b, err := json.Marshal(cmd)
	if err != nil {
		log.Fatalf("Failed json.Marshal(cmd): %v\n", err)
	}
	if bytes.Contains(b, jsonEscapedZero) {
		log.Printf("[unexpected] zero byte in BackendClient.send command")
	}
	bc.sendCommandMsg(b)
}

func (bc *BackendClient) SetNotifyCallback(fn func(Notify)) {
	bc.notify = fn
}

func (bc *BackendClient) Quit() error {
	bc.send(Command{Quit: &NoArgs{}})
	return nil
}

func (bc *BackendClient) Start(opts Options) error {
	bc.send(Command{Start: &StartArgs{Opts: opts}})
	return nil // remote Start() errors must be handled remotely
}

func (bc *BackendClient) StartLoginInteractive() {
	bc.send(Command{StartLoginInteractive: &NoArgs{}})
}

func (bc *BackendClient) Login(token *tailcfg.Oauth2Token) {
	bc.send(Command{Login: token})
}

func (bc *BackendClient) Logout() {
	bc.send(Command{Logout: &NoArgs{}})
}

func (bc *BackendClient) SetPrefs(new *Prefs) {
	bc.send(Command{SetPrefs: &SetPrefsArgs{New: new}})
}

func (bc *BackendClient) RequestEngineStatus() {
	bc.send(Command{RequestEngineStatus: &NoArgs{}})
}

func (bc *BackendClient) RequestStatus() {
	bc.send(Command{AllowVersionSkew: true, RequestStatus: &NoArgs{}})
}

// MaxMessageSize is the maximum message size, in bytes.
const MaxMessageSize = 10 << 20

// TODO(apenwarr): incremental json decode? That would let us avoid
// storing the whole byte array uselessly in RAM.
func ReadMsg(r io.Reader) ([]byte, error) {
	cb := make([]byte, 4)
	_, err := io.ReadFull(r, cb)
	if err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(cb)
	if n > MaxMessageSize {
		return nil, fmt.Errorf("ipn.Read: message too large: %v bytes", n)
	}
	b := make([]byte, n)
	nn, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	if nn != int(n) {
		return nil, fmt.Errorf("ipn.Read: expected %v bytes, got %v", n, nn)
	}
	return b, nil
}

func WriteMsg(w io.Writer, b []byte) error {
	// TODO(apenwarr): incremental json encode? That would save RAM, at the
	// expense of having to encode once so that we can produce the initial byte
	// count.

	// TODO(bradfitz): this does two writes to w, which likely
	// does two writes on the wire, two frame generations, etc. We
	// should take a concrete buffered type, or use a sync.Pool to
	// allocate a buf and do one write.
	cb := make([]byte, 4)
	if len(b) > MaxMessageSize {
		return fmt.Errorf("ipn.Write: message too large: %v bytes", len(b))
	}
	binary.LittleEndian.PutUint32(cb, uint32(len(b)))
	n, err := w.Write(cb)
	if err != nil {
		return err
	}
	if n != 4 {
		return fmt.Errorf("ipn.Write: short write: %v bytes (wanted 4)", n)
	}
	n, err = w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("ipn.Write: short write: %v bytes (wanted %v)", n, len(b))
	}
	return nil
}
