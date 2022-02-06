// +build darwin

package interfaces

import (
	"net"

	"golang.org/x/sys/unix"
)

// BindToInterface emulates linux's SO_BINDTODEVICE option for a socket by using
// IP_BOUND_IF.
func BindToInterface(fd int, ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
}
