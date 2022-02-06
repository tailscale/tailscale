package memconn

import (
	"context"
	"net"
)

const (
	// networkMemb is a buffered network connection. Write operations
	// do not block as they are are buffered instead of waiting on a
	// matching Read operation.
	networkMemb = "memb"

	// networkMemu is an unbuffered network connection. Write operations
	// block until they are matched by a Read operation on the other side
	// of the connected pipe.
	networkMemu = "memu"

	// addrLocalhost is a reserved address name. It is used when a
	// Listen variant omits the local address or a Dial variant omits
	// the remote address.
	addrLocalhost = "localhost"
)

// provider is the package's default provider instance. All of the
// package-level functions interact with this object.
var provider Provider

// MapNetwork enables mapping the network value provided to this Provider's
// Dial and Listen functions from the specified "from" value to the
// specified "to" value.
//
// For example, calling MapNetwork("tcp", "memu") means a subsequent
// Dial("tcp", "address") gets translated to Dial("memu", "address").
//
// Calling MapNetwork("tcp", "") removes any previous translation for
// the "tcp" network.
func MapNetwork(from, to string) {
	provider.MapNetwork(from, to)
}

// Listen begins listening at address for the specified network.
//
// Known networks are "memb" (memconn buffered) and "memu" (memconn unbuffered).
//
// When the specified address is already in use on the specified
// network an error is returned.
//
// When the provided network is unknown the operation defers to
// net.Dial.
func Listen(network, address string) (net.Listener, error) {
	return provider.Listen(network, address)
}

// ListenMem begins listening at laddr.
//
// Known networks are "memb" (memconn buffered) and "memu" (memconn unbuffered).
//
// If laddr is nil then ListenMem listens on "localhost" on the
// specified network.
func ListenMem(network string, laddr *Addr) (*Listener, error) {
	return provider.ListenMem(network, laddr)
}

// Dial dials a named connection.
//
// Known networks are "memb" (memconn buffered) and "memu" (memconn unbuffered).
//
// When the provided network is unknown the operation defers to
// net.Dial.
func Dial(network, address string) (net.Conn, error) {
	return provider.Dial(network, address)
}

// DialContext dials a named connection using a
// Go context to provide timeout behavior.
//
// Please see Dial for more information.
func DialContext(
	ctx context.Context,
	network, address string) (net.Conn, error) {

	return provider.DialContext(ctx, network, address)
}

// DialMem dials a named connection.
//
// Known networks are "memb" (memconn buffered) and "memu" (memconn unbuffered).
//
// If laddr is nil then a new address is generated using
// time.Now().UnixNano(). Please note that client addresses are
// not required to be unique.
//
// If raddr is nil then the "localhost" endpoint is used on the
// specified network.
func DialMem(network string, laddr, raddr *Addr) (*Conn, error) {
	return provider.DialMem(network, laddr, raddr)
}

// DialMemContext dials a named connection using a
// Go context to provide timeout behavior.
//
// Please see DialMem for more information.
func DialMemContext(
	ctx context.Context,
	network string,
	laddr, raddr *Addr) (*Conn, error) {

	return provider.DialMemContext(ctx, network, laddr, raddr)
}
