// Package rtnetlink allows the kernel's routing tables to be read and altered.
// Network routes, IP addresses, Link parameters, Neighbor setups, Queueing disciplines,
// Traffic classes and Packet classifiers may all be controlled.
// It is based on netlink messages.
//
// A convenient, high-level API wrapper is available using package rtnl:
// https://godoc.org/github.com/jsimonetti/rtnetlink/rtnl.
//
// The base rtnetlink library xplicitly only exposes a limited low-level API to rtnetlink.
// It is not the intention (nor wish) to create an iproute2 replacement.
//
// When in doubt about your message structure it can always be useful to look at the
// message send by iproute2 using 'strace -f -esendmsg' or similar.
//
// Another (and possibly even more flexible) way would be using 'nlmon' and wireshark.
// nlmod is a special kernel module which allows you to capture all (not just rtnetlink)
// netlink traffic inside the kernel. Be aware that this might be overwhelming on a system
// with a lot of netlink traffic.
//
//  # modprobe nlmon
//  # ip link add type nlmon
//  # ip link set nlmon0 up
//
// At this point use wireshark or tcpdump on the nlmon0 interface to view all netlink traffic.
//
// Have a look at the examples for common uses of rtnetlink.
package rtnetlink
