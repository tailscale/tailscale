// +build aix freebsd openbsd netbsd

package interfaces

import (
	"net"

	"golang.org/x/sys/unix"
)

// BindToInterface emulates linux's SO_BINDTODEVICE option for a socket by using
// IP_RECVIF.
func BindToInterface(fd int, ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVIF, iface.Index)
}
