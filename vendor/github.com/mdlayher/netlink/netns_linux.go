//go:build linux
// +build linux

package netlink

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// errNetNSDisabled is returned when network namespaces are unavailable on
// a given system.
var errNetNSDisabled = errors.New("netlink: network namespaces are not enabled on this system")

// A netNS is a handle that can manipulate network namespaces.
//
// Operations performed on a netNS must use runtime.LockOSThread before
// manipulating any network namespaces.
type netNS struct {
	// The handle to a network namespace.
	f *os.File

	// Indicates if network namespaces are disabled on this system, and thus
	// operations should become a no-op or return errors.
	disabled bool
}

// threadNetNS constructs a netNS using the network namespace of the calling
// thread. If the namespace is not the default namespace, runtime.LockOSThread
// should be invoked first.
func threadNetNS() (*netNS, error) {
	return fileNetNS(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
}

// fileNetNS opens file and creates a netNS. fileNetNS should only be called
// directly in tests.
func fileNetNS(file string) (*netNS, error) {
	f, err := os.Open(file)
	switch {
	case err == nil:
		return &netNS{f: f}, nil
	case os.IsNotExist(err):
		// Network namespaces are not enabled on this system. Use this signal
		// to return errors elsewhere if the caller explicitly asks for a
		// network namespace to be set.
		return &netNS{disabled: true}, nil
	default:
		return nil, err
	}
}

// Close releases the handle to a network namespace.
func (n *netNS) Close() error {
	return n.do(func() error {
		return n.f.Close()
	})
}

// FD returns a file descriptor which represents the network namespace.
func (n *netNS) FD() int {
	if n.disabled {
		// No reasonable file descriptor value in this case, so specify a
		// non-existent one.
		return -1
	}

	return int(n.f.Fd())
}

// Restore restores the original network namespace for the calling thread.
func (n *netNS) Restore() error {
	return n.do(func() error {
		return n.Set(n.FD())
	})
}

// Set sets a new network namespace for the current thread using fd.
func (n *netNS) Set(fd int) error {
	return n.do(func() error {
		return os.NewSyscallError("setns", unix.Setns(fd, unix.CLONE_NEWNET))
	})
}

// do runs fn if network namespaces are enabled on this system.
func (n *netNS) do(fn func() error) error {
	if n.disabled {
		return errNetNSDisabled
	}

	return fn()
}
