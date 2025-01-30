package ssh

import (
	"crypto/subtle"
	"net"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
)

type Signal string

// POSIX signals as listed in RFC 4254 Section 6.10.
const (
	SIGABRT Signal = "ABRT"
	SIGALRM Signal = "ALRM"
	SIGFPE  Signal = "FPE"
	SIGHUP  Signal = "HUP"
	SIGILL  Signal = "ILL"
	SIGINT  Signal = "INT"
	SIGKILL Signal = "KILL"
	SIGPIPE Signal = "PIPE"
	SIGQUIT Signal = "QUIT"
	SIGSEGV Signal = "SEGV"
	SIGTERM Signal = "TERM"
	SIGUSR1 Signal = "USR1"
	SIGUSR2 Signal = "USR2"
)

// DefaultHandler is the default Handler used by Serve.
var DefaultHandler Handler

// Option is a functional option handler for Server.
type Option func(*Server) error

// Handler is a callback for handling established SSH sessions.
type Handler func(Session)

// PublicKeyHandler is a callback for performing public key authentication.
type PublicKeyHandler func(ctx Context, key PublicKey) error

type NoClientAuthHandler func(ctx Context) error

type BannerHandler func(ctx Context) string

// PasswordHandler is a callback for performing password authentication.
type PasswordHandler func(ctx Context, password string) bool

// KeyboardInteractiveHandler is a callback for performing keyboard-interactive authentication.
type KeyboardInteractiveHandler func(ctx Context, challenger gossh.KeyboardInteractiveChallenge) bool

// PtyCallback is a hook for allowing PTY sessions.
type PtyCallback func(ctx Context, pty Pty) bool

// SessionRequestCallback is a callback for allowing or denying SSH sessions.
type SessionRequestCallback func(sess Session, requestType string) bool

// ConnCallback is a hook for new connections before handling.
// It allows wrapping for timeouts and limiting by returning
// the net.Conn that will be used as the underlying connection.
type ConnCallback func(ctx Context, conn net.Conn) net.Conn

// LocalPortForwardingCallback is a hook for allowing port forwarding
type LocalPortForwardingCallback func(ctx Context, destinationHost string, destinationPort uint32) bool

// ReversePortForwardingCallback is a hook for allowing reverse port forwarding
type ReversePortForwardingCallback func(ctx Context, bindHost string, bindPort uint32) bool

// ServerConfigCallback is a hook for creating custom default server configs
type ServerConfigCallback func(ctx Context) *gossh.ServerConfig

// ConnectionFailedCallback is a hook for reporting failed connections
// Please note: the net.Conn is likely to be closed at this point
type ConnectionFailedCallback func(conn net.Conn, err error)

// Window represents the size of a PTY window.
//
// See https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
//
// Zero dimension parameters MUST be ignored. The character/row dimensions
// override the pixel dimensions (when nonzero).  Pixel dimensions refer
// to the drawable area of the window.
type Window struct {
	// Width is the number of columns.
	// It overrides WidthPixels.
	Width int
	// Height is the number of rows.
	// It overrides HeightPixels.
	Height int

	// WidthPixels is the drawable width of the window, in pixels.
	WidthPixels int
	// HeightPixels is the drawable height of the window, in pixels.
	HeightPixels int
}

// Pty represents a PTY request and configuration.
type Pty struct {
	// Term is the TERM environment variable value.
	Term string

	// Window is the Window sent as part of the pty-req.
	Window Window

	// Modes represent a mapping of Terminal Mode opcode to value as it was
	// requested by the client as part of the pty-req. These are outlined as
	// part of https://datatracker.ietf.org/doc/html/rfc4254#section-8.
	//
	// The opcodes are defined as constants in github.com/tailscale/golang-x-crypto/ssh (VINTR,VQUIT,etc.).
	// Boolean opcodes have values 0 or 1.
	Modes gossh.TerminalModes
}

// Serve accepts incoming SSH connections on the listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and
// then calls handler to handle sessions. Handler is typically nil, in which
// case the DefaultHandler is used.
func Serve(l net.Listener, handler Handler, options ...Option) error {
	srv := &Server{Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.Serve(l)
}

// ListenAndServe listens on the TCP network address addr and then calls Serve
// with handler to handle sessions on incoming connections. Handler is typically
// nil, in which case the DefaultHandler is used.
func ListenAndServe(addr string, handler Handler, options ...Option) error {
	srv := &Server{Addr: addr, Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.ListenAndServe()
}

// Handle registers the handler as the DefaultHandler.
func Handle(handler Handler) {
	DefaultHandler = handler
}

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk PublicKey) bool {

	//avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}
