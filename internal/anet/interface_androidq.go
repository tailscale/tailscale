package anet

import (
	"bytes"
	"errors"
	"net"
	"os"
	"syscall"
	"unsafe"
)

var (
	errNoSuchInterface = errors.New("no such network interface")
)

type ifReq [40]byte

// Interfaces returns a list of the system's network interfaces.
func Interfaces() ([]net.Interface, error) {
	ift, err := interfaceTable(0)
	if err != nil {
		return nil, &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: err}
	}
	// TODO: zoneCache implementation
	return ift, nil
}

// InterfaceAddrs returns a list of the system's unicast interface
// addresses.
//
// The returned list does not identify the associated interface; use
// Interfaces and Interface.Addrs for more detail.
func InterfaceAddrs() ([]net.Addr, error) {
	ifat, err := InterfaceAddrTable(nil)
	if err != nil {
		err = &net.OpError{Op: "route", Net: "ip+net", Source: nil, Addr: nil, Err: err}
	}
	return ifat, err
}

// If the ifindex is zero, interfaceTable returns mappings of all
// network interfaces. Otherwise it returns a mapping of a specific
// interface.
func interfaceTable(ifindex int) ([]net.Interface, error) {
	tab, err := NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, os.NewSyscallError("netlinkrib", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, os.NewSyscallError("parsenetlinkmessage", err)
	}

	var ift []net.Interface
	im := make(map[uint32]struct{})
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWADDR:
			ifam := (*syscall.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))
			if _, ok := im[ifam.Index]; ok {
				continue
			} else {
				im[ifam.Index] = struct{}{}
			}

			if ifindex == 0 || ifindex == int(ifam.Index) {
				ifi := newLink(ifam)
				if ifi != nil {
					ift = append(ift, *ifi)
				}
				if ifindex == int(ifam.Index) {
					break loop
				}
			}
		}
	}

	return ift, nil
}

func newLink(ifam *syscall.IfAddrmsg) *net.Interface {
	ift := &net.Interface{Index: int(ifam.Index)}

	name, err := indexToName(ifam.Index)
	if err != nil {
		return nil
	}
	ift.Name = name

	mtu, err := nameToMTU(name)
	if err != nil {
		return nil
	}
	ift.MTU = mtu

	flags, err := nameToFlags(name)
	if err != nil {
		return nil
	}
	ift.Flags = flags
	return ift
}

func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&syscall.IFF_UP != 0 {
		f |= net.FlagUp
	}
	if rawFlags&syscall.IFF_RUNNING != 0 {
		f |= net.FlagRunning
	}
	if rawFlags&syscall.IFF_BROADCAST != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&syscall.IFF_LOOPBACK != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&syscall.IFF_POINTOPOINT != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&syscall.IFF_MULTICAST != 0 {
		f |= net.FlagMulticast
	}
	return f
}

// If the ifi is nil, InterfaceAddrTable returns addresses for all
// network interfaces. Otherwise it returns addresses for a specific
// interface.
func InterfaceAddrTable(ifi *net.Interface) ([]net.Addr, error) {
	tab, err := NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, os.NewSyscallError("netlinkrib", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, os.NewSyscallError("parsenetlinkmessage", err)
	}

	var ift []net.Interface
	if ifi == nil {
		var err error
		ift, err = interfaceTable(0)
		if err != nil {
			return nil, err
		}
	}
	ifat, err := addrTable(ift, ifi, msgs)
	if err != nil {
		return nil, err
	}
	return ifat, nil
}

func addrTable(ift []net.Interface, ifi *net.Interface, msgs []syscall.NetlinkMessage) ([]net.Addr, error) {
	var ifat []net.Addr
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWADDR:
			ifam := (*syscall.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))
			if len(ift) != 0 || ifi.Index == int(ifam.Index) {
				if len(ift) != 0 {
					var err error
					ifi, err = interfaceByIndex(ift, int(ifam.Index))
					if err != nil {
						return nil, err
					}
				}
				attrs, err := syscall.ParseNetlinkRouteAttr(&m)
				if err != nil {
					return nil, os.NewSyscallError("parsenetlinkrouteattr", err)
				}
				ifa := newAddr(ifam, attrs)
				if ifa != nil {
					ifat = append(ifat, ifa)
				}
			}
		}
	}
	return ifat, nil
}

func newAddr(ifam *syscall.IfAddrmsg, attrs []syscall.NetlinkRouteAttr) net.Addr {
	var ipPointToPoint bool
	// Seems like we need to make sure whether the IP interface
	// stack consists of IP point-to-point numbered or unnumbered
	// addressing.
	for _, a := range attrs {
		if a.Attr.Type == syscall.IFA_LOCAL {
			ipPointToPoint = true
			break
		}
	}
	for _, a := range attrs {
		if ipPointToPoint && a.Attr.Type == syscall.IFA_ADDRESS {
			continue
		}
		switch ifam.Family {
		case syscall.AF_INET:
			return &net.IPNet{IP: net.IPv4(a.Value[0], a.Value[1], a.Value[2], a.Value[3]), Mask: net.CIDRMask(int(ifam.Prefixlen), 8*net.IPv4len)}
		case syscall.AF_INET6:
			ifa := &net.IPNet{IP: make(net.IP, net.IPv6len), Mask: net.CIDRMask(int(ifam.Prefixlen), 8*net.IPv6len)}
			copy(ifa.IP, a.Value[:])
			return ifa
		}
	}
	return nil
}

func interfaceByIndex(ift []net.Interface, index int) (*net.Interface, error) {
	for _, ifi := range ift {
		if index == ifi.Index {
			return &ifi, nil
		}
	}
	return nil, errNoSuchInterface
}

func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, e1 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if e1 != 0 {
		return e1
	}
	return nil
}

func indexToName(index uint32) (string, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(fd)

	var ifr ifReq
	*(*uint32)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ])) = index
	err = ioctl(fd, syscall.SIOCGIFNAME, unsafe.Pointer(&ifr[0]))
	if err != nil {
		return "", err
	}

	return string(bytes.Trim(ifr[:syscall.IFNAMSIZ], "\x00")), nil
}

func nameToMTU(name string) (int, error) {
	// Leave room for terminating NULL byte.
	if len(name) >= syscall.IFNAMSIZ {
		return -1, syscall.EINVAL
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(fd)

	var ifr ifReq
	copy(ifr[:], name)
	err = ioctl(fd, syscall.SIOCGIFMTU, unsafe.Pointer(&ifr[0]))
	if err != nil {
		return -1, err
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ]))), nil
}

func nameToFlags(name string) (net.Flags, error) {
	// Leave room for terminating NULL byte.
	if len(name) >= syscall.IFNAMSIZ {
		return 0, syscall.EINVAL
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	var ifr ifReq
	copy(ifr[:], name)
	err = ioctl(fd, syscall.SIOCGIFFLAGS, unsafe.Pointer(&ifr[0]))
	if err != nil {
		return 0, err
	}

	return linkFlags(*(*uint32)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ]))), nil
}
