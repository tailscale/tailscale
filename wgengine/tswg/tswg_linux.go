// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tswg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"go4.org/mem"
	"golang.org/x/sys/unix"
	"tailscale.com/types/key"
)

// FamilyName is the generic netlink family name registered by tswg.ko.
const FamilyName = "tswg"

// Constants from tswg's uapi header (src/include/uapi/linux/tswg.h in the
// tswg module tree), which match upstream WireGuard's.
const (
	genlVersion = 1

	cmdGetDevice = 0
	cmdSetDevice = 1

	deviceFlagReplacePeers = 1

	peerFlagRemoveMe          = 1
	peerFlagReplaceAllowedIPs = 2
	peerFlagUpdateOnly        = 4

	deviceAIfindex    = 1
	deviceAIfname     = 2
	deviceAPrivateKey = 3
	deviceAPublicKey  = 4
	deviceAFlags      = 5
	deviceAListenPort = 6
	deviceAFwmark     = 7
	deviceAPeers      = 8

	peerAPublicKey                   = 1
	peerAPresharedKey                = 2
	peerAFlags                       = 3
	peerAEndpoint                    = 4
	peerAPersistentKeepaliveInterval = 5
	peerALastHandshakeTime           = 6
	peerARxBytes                     = 7
	peerATxBytes                     = 8
	peerAAllowedIPs                  = 9
	peerAProtocolVersion             = 10

	allowedIPAFamily   = 1
	allowedIPAIPAddr   = 2
	allowedIPACidrMask = 3

	// tswg additions, nested in deviceATSWG.
	deviceATSWG = 64

	tswgDeviceASockFD4 = 1
	tswgDeviceASockFD6 = 2
	tswgDeviceAFlags   = 3

	tswgDeviceFlagUserSock4 = 1
	tswgDeviceFlagUserSock6 = 2

	// tswg additions, nested in peerATSWG.
	peerATSWG = 64

	tswgPeerAFlags        = 1
	tswgPeerAClearSession = 2

	tswgPeerFlagNoRoam = 1
)

// Client is a connection to the tswg generic netlink family.
type Client struct {
	c   *genetlink.Conn
	fam genetlink.Family
}

// Open opens a Client. It fails if the tswg module isn't loaded.
func Open() (*Client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	fam, err := c.GetFamily(FamilyName)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("tswg: getting genetlink family %q (is tswg.ko loaded?): %w", FamilyName, err)
	}
	return &Client{c: c, fam: fam}, nil
}

// Close closes the Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// ConfigureDevice applies cfg to the tswg device named ifname.
//
// TODO(bradfitz): split large peer lists across multiple messages, as
// wgctrl does, so that a single message can't exceed the socket buffer.
func (c *Client) ConfigureDevice(ifname string, cfg Config) error {
	ae := netlink.NewAttributeEncoder()
	ae.String(deviceAIfname, ifname)
	if cfg.PrivateKey != nil {
		k := cfg.PrivateKey.Raw32()
		ae.Bytes(deviceAPrivateKey, k[:])
	}
	if cfg.ListenPort != nil {
		ae.Uint16(deviceAListenPort, *cfg.ListenPort)
	}
	if cfg.FirewallMark != nil {
		ae.Uint32(deviceAFwmark, *cfg.FirewallMark)
	}
	if cfg.ReplacePeers {
		ae.Uint32(deviceAFlags, deviceFlagReplacePeers)
	}
	if cfg.SocketFD4 != nil || cfg.SocketFD6 != nil {
		ae.Nested(deviceATSWG, func(nae *netlink.AttributeEncoder) error {
			if cfg.SocketFD4 != nil {
				nae.Int32(tswgDeviceASockFD4, int32(*cfg.SocketFD4))
			}
			if cfg.SocketFD6 != nil {
				nae.Int32(tswgDeviceASockFD6, int32(*cfg.SocketFD6))
			}
			return nil
		})
	}
	if len(cfg.Peers) > 0 {
		ae.Nested(deviceAPeers, func(nae *netlink.AttributeEncoder) error {
			for i, p := range cfg.Peers {
				nae.Nested(uint16(i), func(pae *netlink.AttributeEncoder) error {
					return encodePeer(pae, p)
				})
			}
			return nil
		})
	}
	b, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = c.c.Execute(genetlink.Message{
		Header: genetlink.Header{Command: cmdSetDevice, Version: genlVersion},
		Data:   b,
	}, c.fam.ID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return fmt.Errorf("tswg: configuring %q: %w", ifname, err)
	}
	return nil
}

func encodePeer(ae *netlink.AttributeEncoder, p PeerConfig) error {
	pub := p.PublicKey.Raw32()
	ae.Bytes(peerAPublicKey, pub[:])
	var flags uint32
	if p.Remove {
		flags |= peerFlagRemoveMe
	}
	if p.UpdateOnly {
		flags |= peerFlagUpdateOnly
	}
	if p.ReplaceAllowedIPs {
		flags |= peerFlagReplaceAllowedIPs
	}
	if flags != 0 {
		ae.Uint32(peerAFlags, flags)
	}
	if p.PresharedKey != nil {
		ae.Bytes(peerAPresharedKey, p.PresharedKey[:])
	}
	if p.NoRoam != nil || p.ClearSession {
		ae.Nested(peerATSWG, func(nae *netlink.AttributeEncoder) error {
			if p.NoRoam != nil {
				var flags uint32
				if *p.NoRoam {
					flags |= tswgPeerFlagNoRoam
				}
				nae.Uint32(tswgPeerAFlags, flags)
			}
			if p.ClearSession {
				nae.Flag(tswgPeerAClearSession, true)
			}
			return nil
		})
	}
	if p.Endpoint.IsValid() {
		ae.Bytes(peerAEndpoint, encodeSockaddr(p.Endpoint))
	}
	if p.PersistentKeepalive != nil {
		ae.Uint16(peerAPersistentKeepaliveInterval, uint16(*p.PersistentKeepalive/time.Second))
	}
	if len(p.AllowedIPs) > 0 {
		ae.Nested(peerAAllowedIPs, func(nae *netlink.AttributeEncoder) error {
			for i, pfx := range p.AllowedIPs {
				nae.Nested(uint16(i), func(aae *netlink.AttributeEncoder) error {
					pfx = pfx.Masked()
					if pfx.Addr().Is4() {
						aae.Uint16(allowedIPAFamily, unix.AF_INET)
					} else {
						aae.Uint16(allowedIPAFamily, unix.AF_INET6)
					}
					aae.Bytes(allowedIPAIPAddr, pfx.Addr().AsSlice())
					aae.Uint8(allowedIPACidrMask, uint8(pfx.Bits()))
					return nil
				})
			}
			return nil
		})
	}
	return nil
}

// encodeSockaddr encodes ap as a struct sockaddr_in or sockaddr_in6.
func encodeSockaddr(ap netip.AddrPort) []byte {
	addr := ap.Addr()
	if addr.Is4() || addr.Is4In6() {
		b := make([]byte, unix.SizeofSockaddrInet4)
		binary.NativeEndian.PutUint16(b[0:], unix.AF_INET)
		binary.BigEndian.PutUint16(b[2:], ap.Port())
		a4 := addr.Unmap().As4()
		copy(b[4:], a4[:])
		return b
	}
	b := make([]byte, unix.SizeofSockaddrInet6)
	binary.NativeEndian.PutUint16(b[0:], unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:], ap.Port())
	a16 := addr.As16()
	copy(b[8:], a16[:])
	// TODO(bradfitz): scope ID (b[24:28]) for link-local addresses.
	return b
}

func decodeSockaddr(b []byte) (netip.AddrPort, error) {
	if len(b) < 2 {
		return netip.AddrPort{}, errors.New("short sockaddr")
	}
	switch binary.NativeEndian.Uint16(b) {
	case unix.AF_INET:
		if len(b) < unix.SizeofSockaddrInet4 {
			return netip.AddrPort{}, errors.New("short sockaddr_in")
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), binary.BigEndian.Uint16(b[2:])), nil
	case unix.AF_INET6:
		if len(b) < unix.SizeofSockaddrInet6 {
			return netip.AddrPort{}, errors.New("short sockaddr_in6")
		}
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])), binary.BigEndian.Uint16(b[2:])), nil
	case unix.AF_UNSPEC:
		return netip.AddrPort{}, nil
	}
	return netip.AddrPort{}, fmt.Errorf("unknown sockaddr family %d", binary.NativeEndian.Uint16(b))
}

// Device returns the current state of the tswg device named ifname.
func (c *Client) Device(ifname string) (*Device, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(deviceAIfname, ifname)
	b, err := ae.Encode()
	if err != nil {
		return nil, err
	}
	msgs, err := c.c.Execute(genetlink.Message{
		Header: genetlink.Header{Command: cmdGetDevice, Version: genlVersion},
		Data:   b,
	}, c.fam.ID, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, fmt.Errorf("tswg: getting %q: %w", ifname, err)
	}

	// The kernel splits large devices across several messages. Each repeats
	// the device attributes and carries the next batch of peers; a peer's
	// allowed IPs may also continue into the next message.
	d := new(Device)
	for _, m := range msgs {
		if err := d.decode(m.Data); err != nil {
			return nil, fmt.Errorf("tswg: decoding %q: %w", ifname, err)
		}
	}
	return d, nil
}

func (d *Device) decode(b []byte) error {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case deviceAIfindex:
			d.Index = int(ad.Uint32())
		case deviceAIfname:
			d.Name = ad.String()
		case deviceAPrivateKey:
			d.PrivateKey = key.NodePrivateFromRaw32(mem.B(ad.Bytes()))
		case deviceAPublicKey:
			d.PublicKey = key.NodePublicFromRaw32(mem.B(ad.Bytes()))
		case deviceAListenPort:
			d.ListenPort = ad.Uint16()
		case deviceAFwmark:
			d.FirewallMark = ad.Uint32()
		case deviceATSWG:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					if nad.Type() == tswgDeviceAFlags {
						flags := nad.Uint32()
						d.UserSocket4 = flags&tswgDeviceFlagUserSock4 != 0
						d.UserSocket6 = flags&tswgDeviceFlagUserSock6 != 0
					}
				}
				return nil
			})
		case deviceAPeers:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					var p Peer
					nad.Nested(func(pad *netlink.AttributeDecoder) error {
						return p.decode(pad)
					})
					d.addPeer(p)
				}
				return nil
			})
		}
	}
	return ad.Err()
}

// addPeer appends p to d.Peers, or merges it into the last peer if the
// kernel split that peer's allowed IPs across messages.
func (d *Device) addPeer(p Peer) {
	if n := len(d.Peers); n > 0 && d.Peers[n-1].PublicKey == p.PublicKey {
		d.Peers[n-1].AllowedIPs = append(d.Peers[n-1].AllowedIPs, p.AllowedIPs...)
		return
	}
	d.Peers = append(d.Peers, p)
}

func (p *Peer) decode(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ad.Type() {
		case peerAPublicKey:
			p.PublicKey = key.NodePublicFromRaw32(mem.B(ad.Bytes()))
		case peerAEndpoint:
			ep, err := decodeSockaddr(ad.Bytes())
			if err != nil {
				return err
			}
			p.Endpoint = ep
		case peerAPersistentKeepaliveInterval:
			p.PersistentKeepalive = time.Duration(ad.Uint16()) * time.Second
		case peerALastHandshakeTime:
			// struct __kernel_timespec: two int64s.
			b := ad.Bytes()
			if len(b) == 16 {
				sec := int64(binary.NativeEndian.Uint64(b[0:]))
				nsec := int64(binary.NativeEndian.Uint64(b[8:]))
				if sec != 0 || nsec != 0 {
					p.LastHandshake = time.Unix(sec, nsec)
				}
			}
		case peerARxBytes:
			p.RxBytes = ad.Uint64()
		case peerATxBytes:
			p.TxBytes = ad.Uint64()
		case peerAProtocolVersion:
			p.ProtocolVersion = int(ad.Uint32())
		case peerATSWG:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					if nad.Type() == tswgPeerAFlags {
						p.NoRoam = nad.Uint32()&tswgPeerFlagNoRoam != 0
					}
				}
				return nil
			})
		case peerAAllowedIPs:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					nad.Nested(func(aad *netlink.AttributeDecoder) error {
						var ip []byte
						var bits int
						for aad.Next() {
							switch aad.Type() {
							case allowedIPAIPAddr:
								ip = aad.Bytes()
							case allowedIPACidrMask:
								bits = int(aad.Uint8())
							}
						}
						if addr, ok := netip.AddrFromSlice(ip); ok {
							p.AllowedIPs = append(p.AllowedIPs, netip.PrefixFrom(addr, bits))
						}
						return nil
					})
				}
				return nil
			})
		}
	}
	return nil
}
