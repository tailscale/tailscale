// Package dhcpv4 provides encoding and decoding of DHCPv4 packets and options.
//
// Example Usage:
//
//   p, err := dhcpv4.New(
//     dhcpv4.WithClientIP(net.IP{192, 168, 0, 1}),
//     dhcpv4.WithMessageType(dhcpv4.MessageTypeInform),
//   )
//   p.UpdateOption(dhcpv4.OptServerIdentifier(net.IP{192, 110, 110, 110}))
//
//   // Retrieve the DHCP Message Type option.
//   m := p.MessageType()
//
//   bytesOnTheWire := p.ToBytes()
//   longSummary := p.Summary()
package dhcpv4

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/u-root/uio/rand"
	"github.com/u-root/uio/uio"
)

const (
	// minPacketLen is the minimum DHCP header length.
	minPacketLen = 236

	// MaxHWAddrLen is the maximum hardware address length of the ClientHWAddr
	// (client hardware address) according to RFC 2131, Section 2. This is the
	// link-layer destination a server must send responses to.
	MaxHWAddrLen = 16

	// MaxMessageSize is the maximum size in bytes that a DHCPv4 packet can hold.
	MaxMessageSize = 576

	// Per RFC 951, the minimum length of a packet is 300 bytes.
	bootpMinLen = 300
)

// RandomTimeout is the amount of time to wait until random number generation
// is canceled.
var RandomTimeout = 2 * time.Minute

// magicCookie is the magic 4-byte value at the beginning of the list of options
// in a DHCPv4 packet.
var magicCookie = [4]byte{99, 130, 83, 99}

// DHCPv4 represents a DHCPv4 packet header and options. See the New* functions
// to build DHCPv4 packets.
type DHCPv4 struct {
	OpCode         OpcodeType
	HWType         iana.HWType
	HopCount       uint8
	TransactionID  TransactionID
	NumSeconds     uint16
	Flags          uint16
	ClientIPAddr   net.IP
	YourIPAddr     net.IP
	ServerIPAddr   net.IP
	GatewayIPAddr  net.IP
	ClientHWAddr   net.HardwareAddr
	ServerHostName string
	BootFileName   string
	Options        Options
}

// Modifier defines the signature for functions that can modify DHCPv4
// structures. This is used to simplify packet manipulation
type Modifier func(d *DHCPv4)

// IPv4AddrsForInterface obtains the currently-configured, non-loopback IPv4
// addresses for iface.
func IPv4AddrsForInterface(iface *net.Interface) ([]net.IP, error) {
	if iface == nil {
		return nil, errors.New("IPv4AddrsForInterface: iface cannot be nil")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	return GetExternalIPv4Addrs(addrs)
}

// GetExternalIPv4Addrs obtains the currently-configured, non-loopback IPv4
// addresses from `addrs` coming from a particular interface (e.g.
// net.Interface.Addrs).
func GetExternalIPv4Addrs(addrs []net.Addr) ([]net.IP, error) {
	var v4addrs []net.IP
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPAddr:
			ip = v.IP
		case *net.IPNet:
			ip = v.IP
		}

		if ip == nil || ip.IsLoopback() {
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}
		v4addrs = append(v4addrs, ip)
	}
	return v4addrs, nil
}

// GenerateTransactionID generates a random 32-bits number suitable for use as
// TransactionID
func GenerateTransactionID() (TransactionID, error) {
	var xid TransactionID
	ctx, cancel := context.WithTimeout(context.Background(), RandomTimeout)
	defer cancel()
	n, err := rand.ReadContext(ctx, xid[:])
	if err != nil {
		return xid, fmt.Errorf("could not get random number: %v", err)
	}
	if n != 4 {
		return xid, errors.New("invalid random sequence for transaction ID: smaller than 32 bits")
	}
	return xid, err
}

// New creates a new DHCPv4 structure and fill it up with default values. It
// won't be a valid DHCPv4 message so you will need to adjust its fields.
// See also NewDiscovery, NewRequest, NewAcknowledge, NewInform and NewRelease.
func New(modifiers ...Modifier) (*DHCPv4, error) {
	xid, err := GenerateTransactionID()
	if err != nil {
		return nil, err
	}
	d := DHCPv4{
		OpCode:        OpcodeBootRequest,
		HWType:        iana.HWTypeEthernet,
		ClientHWAddr:  make(net.HardwareAddr, 6),
		HopCount:      0,
		TransactionID: xid,
		NumSeconds:    0,
		Flags:         0,
		ClientIPAddr:  net.IPv4zero,
		YourIPAddr:    net.IPv4zero,
		ServerIPAddr:  net.IPv4zero,
		GatewayIPAddr: net.IPv4zero,
		Options:       make(Options),
	}
	for _, mod := range modifiers {
		mod(&d)
	}
	return &d, nil
}

// NewDiscoveryForInterface builds a new DHCPv4 Discovery message, with a default
// Ethernet HW type and the hardware address obtained from the specified
// interface.
func NewDiscoveryForInterface(ifname string, modifiers ...Modifier) (*DHCPv4, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	return NewDiscovery(iface.HardwareAddr, modifiers...)
}

// NewDiscovery builds a new DHCPv4 Discovery message, with a default Ethernet
// HW type and specified hardware address.
func NewDiscovery(hwaddr net.HardwareAddr, modifiers ...Modifier) (*DHCPv4, error) {
	return New(PrependModifiers(modifiers,
		WithHwAddr(hwaddr),
		WithRequestedOptions(
			OptionSubnetMask,
			OptionRouter,
			OptionDomainName,
			OptionDomainNameServer,
		),
		WithMessageType(MessageTypeDiscover),
	)...)
}

// NewInformForInterface builds a new DHCPv4 Informational message with default
// Ethernet HW type and the hardware address obtained from the specified
// interface.
func NewInformForInterface(ifname string, needsBroadcast bool) (*DHCPv4, error) {
	// get hw addr
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}

	// Set Client IP as iface's currently-configured IP.
	localIPs, err := IPv4AddrsForInterface(iface)
	if err != nil || len(localIPs) == 0 {
		return nil, fmt.Errorf("could not get local IPs for iface %s", ifname)
	}
	pkt, err := NewInform(iface.HardwareAddr, localIPs[0])
	if err != nil {
		return nil, err
	}

	if needsBroadcast {
		pkt.SetBroadcast()
	} else {
		pkt.SetUnicast()
	}
	return pkt, nil
}

// PrependModifiers prepends other to m.
func PrependModifiers(m []Modifier, other ...Modifier) []Modifier {
	return append(other, m...)
}

// NewInform builds a new DHCPv4 Informational message with the specified
// hardware address.
func NewInform(hwaddr net.HardwareAddr, localIP net.IP, modifiers ...Modifier) (*DHCPv4, error) {
	return New(PrependModifiers(
		modifiers,
		WithHwAddr(hwaddr),
		WithMessageType(MessageTypeInform),
		WithClientIP(localIP),
	)...)
}

// NewRequestFromOffer builds a DHCPv4 request from an offer.
func NewRequestFromOffer(offer *DHCPv4, modifiers ...Modifier) (*DHCPv4, error) {
	// find server IP address
	serverIP := offer.ServerIdentifier()
	if serverIP == nil {
		if offer.ServerIPAddr == nil || offer.ServerIPAddr.IsUnspecified() {
			return nil, fmt.Errorf("missing Server IP Address in DHCP Offer")
		}
		serverIP = offer.ServerIPAddr
	}

	return New(PrependModifiers(modifiers,
		WithReply(offer),
		WithMessageType(MessageTypeRequest),
		WithServerIP(serverIP),
		WithClientIP(offer.ClientIPAddr),
		WithOption(OptRequestedIPAddress(offer.YourIPAddr)),
		WithOption(OptServerIdentifier(serverIP)),
		WithRequestedOptions(
			OptionSubnetMask,
			OptionRouter,
			OptionDomainName,
			OptionDomainNameServer,
		),
	)...)
}

// NewReplyFromRequest builds a DHCPv4 reply from a request.
func NewReplyFromRequest(request *DHCPv4, modifiers ...Modifier) (*DHCPv4, error) {
	return New(PrependModifiers(modifiers,
		WithReply(request),
		WithGatewayIP(request.GatewayIPAddr),
		WithOptionCopied(request, OptionRelayAgentInformation),

		// RFC 6842 states the Client Identifier option must be copied
		// from the request if a client specified it.
		WithOptionCopied(request, OptionClientIdentifier),
	)...)
}

// NewReleaseFromACK creates a DHCPv4 Release message from ACK.
// default Release message without any Modifer is created as following:
//  - option Message Type is Release
//  - ClientIP is set to ack.YourIPAddr
//  - ClientHWAddr is set to ack.ClientHWAddr
//  - Unicast
//  - option Server Identifier is set to ack's ServerIdentifier
func NewReleaseFromACK(ack *DHCPv4, modifiers ...Modifier) (*DHCPv4, error) {
	return New(PrependModifiers(modifiers,
		WithMessageType(MessageTypeRelease),
		WithClientIP(ack.YourIPAddr),
		WithHwAddr(ack.ClientHWAddr),
		WithBroadcast(false),
		WithOptionCopied(ack, OptionServerIdentifier),
	)...)
}

// FromBytes encodes the DHCPv4 packet into a sequence of bytes, and returns an
// error if the packet is not valid.
func FromBytes(q []byte) (*DHCPv4, error) {
	var p DHCPv4
	buf := uio.NewBigEndianBuffer(q)

	p.OpCode = OpcodeType(buf.Read8())
	p.HWType = iana.HWType(buf.Read8())

	hwAddrLen := buf.Read8()

	p.HopCount = buf.Read8()
	buf.ReadBytes(p.TransactionID[:])
	p.NumSeconds = buf.Read16()
	p.Flags = buf.Read16()

	p.ClientIPAddr = net.IP(buf.CopyN(net.IPv4len))
	p.YourIPAddr = net.IP(buf.CopyN(net.IPv4len))
	p.ServerIPAddr = net.IP(buf.CopyN(net.IPv4len))
	p.GatewayIPAddr = net.IP(buf.CopyN(net.IPv4len))

	if hwAddrLen > 16 {
		hwAddrLen = 16
	}
	// Always read 16 bytes, but only use hwaddrlen of them.
	p.ClientHWAddr = make(net.HardwareAddr, 16)
	buf.ReadBytes(p.ClientHWAddr)
	p.ClientHWAddr = p.ClientHWAddr[:hwAddrLen]

	var sname [64]byte
	buf.ReadBytes(sname[:])
	length := strings.Index(string(sname[:]), "\x00")
	if length == -1 {
		length = 64
	}
	p.ServerHostName = string(sname[:length])

	var file [128]byte
	buf.ReadBytes(file[:])
	length = strings.Index(string(file[:]), "\x00")
	if length == -1 {
		length = 128
	}
	p.BootFileName = string(file[:length])

	var cookie [4]byte
	buf.ReadBytes(cookie[:])

	if err := buf.Error(); err != nil {
		return nil, err
	}
	if cookie != magicCookie {
		return nil, fmt.Errorf("malformed DHCP packet: got magic cookie %v, want %v", cookie[:], magicCookie[:])
	}

	p.Options = make(Options)
	if err := p.Options.fromBytesCheckEnd(buf.Data(), true); err != nil {
		return nil, err
	}
	return &p, nil
}

// FlagsToString returns a human-readable representation of the flags field.
func (d *DHCPv4) FlagsToString() string {
	flags := ""
	if d.IsBroadcast() {
		flags += "Broadcast"
	} else {
		flags += "Unicast"
	}
	if d.Flags&0xfe != 0 {
		flags += " (reserved bits not zeroed)"
	}
	return flags
}

// IsBroadcast indicates whether the packet is a broadcast packet.
func (d *DHCPv4) IsBroadcast() bool {
	return d.Flags&0x8000 == 0x8000
}

// SetBroadcast sets the packet to be a broadcast packet.
func (d *DHCPv4) SetBroadcast() {
	d.Flags |= 0x8000
}

// IsUnicast indicates whether the packet is a unicast packet.
func (d *DHCPv4) IsUnicast() bool {
	return d.Flags&0x8000 == 0
}

// SetUnicast sets the packet to be a unicast packet.
func (d *DHCPv4) SetUnicast() {
	d.Flags &= ^uint16(0x8000)
}

// GetOneOption returns the option that matches the given option code.
//
// According to RFC 3396, options that are specified more than once are
// concatenated, and hence this should always just return one option.
func (d *DHCPv4) GetOneOption(code OptionCode) []byte {
	return d.Options.Get(code)
}

// UpdateOption replaces an existing option with the same option code with the
// given one, adding it if not already present.
func (d *DHCPv4) UpdateOption(opt Option) {
	if d.Options == nil {
		d.Options = make(Options)
	}
	d.Options.Update(opt)
}

// String implements fmt.Stringer.
func (d *DHCPv4) String() string {
	return fmt.Sprintf("DHCPv4(xid=%s hwaddr=%s msg_type=%s, your_ip=%s, server_ip=%s)",
		d.TransactionID, d.ClientHWAddr, d.MessageType(), d.YourIPAddr, d.ServerIPAddr)
}

// SummaryWithVendor prints a summary of the packet, interpreting the
// vendor-specific info option using the given parser (can be nil).
func (d *DHCPv4) SummaryWithVendor(vendorDecoder OptionDecoder) string {
	ret := fmt.Sprintf(
		"DHCPv4 Message\n"+
			"  opcode: %s\n"+
			"  hwtype: %s\n"+
			"  hopcount: %v\n"+
			"  transaction ID: %s\n"+
			"  num seconds: %v\n"+
			"  flags: %v (0x%02x)\n"+
			"  client IP: %s\n"+
			"  your IP: %s\n"+
			"  server IP: %s\n"+
			"  gateway IP: %s\n"+
			"  client MAC: %s\n"+
			"  server hostname: %s\n"+
			"  bootfile name: %s\n",
		d.OpCode,
		d.HWType,
		d.HopCount,
		d.TransactionID,
		d.NumSeconds,
		d.FlagsToString(),
		d.Flags,
		d.ClientIPAddr,
		d.YourIPAddr,
		d.ServerIPAddr,
		d.GatewayIPAddr,
		d.ClientHWAddr,
		d.ServerHostName,
		d.BootFileName,
	)
	ret += "  options:\n"
	ret += d.Options.Summary(vendorDecoder)
	return ret
}

// Summary prints detailed information about the packet.
func (d *DHCPv4) Summary() string {
	return d.SummaryWithVendor(nil)
}

// IsOptionRequested returns true if that option is within the requested
// options of the DHCPv4 message.
func (d *DHCPv4) IsOptionRequested(requested OptionCode) bool {
	rq := d.ParameterRequestList()
	if rq == nil {
		// RFC2131§3.5
		// Not all clients require initialization of all parameters [...]
		// Two techniques are used to reduce the number of parameters transmitted from
		// the server to the client. [...] Second, in its initial DHCPDISCOVER or
		// DHCPREQUEST message, a client may provide the server with a list of specific
		// parameters the client is interested in.
		// We interpret this to say that all available parameters should be sent if
		// the parameter request list is not sent at all.
		return true
	}

	for _, o := range rq {
		if o == requested {
			return true
		}
	}
	return false
}

// In case somebody forgets to set an IP, just write 0s as default values.
func writeIP(b *uio.Lexer, ip net.IP) {
	var zeros [net.IPv4len]byte
	if ip == nil {
		b.WriteBytes(zeros[:])
	} else {
		// Converting IP to 4 byte format
		ip = ip.To4()
		b.WriteBytes(ip[:net.IPv4len])
	}
}

// ToBytes writes the packet to binary.
func (d *DHCPv4) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(make([]byte, 0, minPacketLen))
	buf.Write8(uint8(d.OpCode))
	buf.Write8(uint8(d.HWType))

	// HwAddrLen
	hlen := uint8(len(d.ClientHWAddr))
	buf.Write8(hlen)
	buf.Write8(d.HopCount)
	buf.WriteBytes(d.TransactionID[:])
	buf.Write16(d.NumSeconds)
	buf.Write16(d.Flags)

	writeIP(buf, d.ClientIPAddr)
	writeIP(buf, d.YourIPAddr)
	writeIP(buf, d.ServerIPAddr)
	writeIP(buf, d.GatewayIPAddr)
	copy(buf.WriteN(16), d.ClientHWAddr)

	var sname [64]byte
	copy(sname[:63], []byte(d.ServerHostName))
	buf.WriteBytes(sname[:])

	var file [128]byte
	copy(file[:127], []byte(d.BootFileName))
	buf.WriteBytes(file[:])

	// The magic cookie.
	buf.WriteBytes(magicCookie[:])

	// Write all options.
	d.Options.Marshal(buf)

	// Finish the options.
	buf.Write8(OptionEnd.Code())

	// DHCP is based on BOOTP, and BOOTP messages have a minimum length of
	// 300 bytes per RFC 951. This not stated explicitly, but if you sum up
	// all the bytes in the message layout, you'll get 300 bytes.
	//
	// Some DHCP servers and relay agents care about this BOOTP legacy B.S.
	// and "conveniently" drop messages that are less than 300 bytes long.
	if buf.Len() < bootpMinLen {
		buf.WriteBytes(bytes.Repeat([]byte{OptionPad.Code()}, bootpMinLen-buf.Len()))
	}

	return buf.Data()
}

// GetBroadcastAddress returns the DHCPv4 Broadcast Address value in d.
//
// The broadcast address option is described in RFC 2132, Section 5.3.
func (d *DHCPv4) BroadcastAddress() net.IP {
	return GetIP(OptionBroadcastAddress, d.Options)
}

// RequestedIPAddress returns the DHCPv4 Requested IP Address value in d.
//
// The requested IP address option is described by RFC 2132, Section 9.1.
func (d *DHCPv4) RequestedIPAddress() net.IP {
	return GetIP(OptionRequestedIPAddress, d.Options)
}

// ServerIdentifier returns the DHCPv4 Server Identifier value in d.
//
// The server identifier option is described by RFC 2132, Section 9.7.
func (d *DHCPv4) ServerIdentifier() net.IP {
	return GetIP(OptionServerIdentifier, d.Options)
}

// Router parses the DHCPv4 Router option if present.
//
// The Router option is described by RFC 2132, Section 3.5.
func (d *DHCPv4) Router() []net.IP {
	return GetIPs(OptionRouter, d.Options)
}

// ClasslessStaticRoute parses the DHCPv4 Classless Static Route option if present.
//
// The Classless Static Route option is described by RFC 3442.
func (d *DHCPv4) ClasslessStaticRoute() []*Route {
	v := d.Options.Get(OptionClasslessStaticRoute)
	if v == nil {
		return nil
	}
	var routes Routes
	if err := routes.FromBytes(v); err != nil {
		return nil
	}
	return routes
}

// NTPServers parses the DHCPv4 NTP Servers option if present.
//
// The NTP servers option is described by RFC 2132, Section 8.3.
func (d *DHCPv4) NTPServers() []net.IP {
	return GetIPs(OptionNTPServers, d.Options)
}

// DNS parses the DHCPv4 Domain Name Server option if present.
//
// The DNS server option is described by RFC 2132, Section 3.8.
func (d *DHCPv4) DNS() []net.IP {
	return GetIPs(OptionDomainNameServer, d.Options)
}

// DomainName parses the DHCPv4 Domain Name option if present.
//
// The Domain Name option is described by RFC 2132, Section 3.17.
func (d *DHCPv4) DomainName() string {
	return GetString(OptionDomainName, d.Options)
}

// HostName parses the DHCPv4 Host Name option if present.
//
// The Host Name option is described by RFC 2132, Section 3.14.
func (d *DHCPv4) HostName() string {
	name := GetString(OptionHostName, d.Options)
	return strings.TrimRight(name, "\x00")
}

// RootPath parses the DHCPv4 Root Path option if present.
//
// The Root Path option is described by RFC 2132, Section 3.19.
func (d *DHCPv4) RootPath() string {
	return GetString(OptionRootPath, d.Options)
}

// BootFileNameOption parses the DHCPv4 Bootfile Name option if present.
//
// The Bootfile Name option is described by RFC 2132, Section 9.5.
func (d *DHCPv4) BootFileNameOption() string {
	name := GetString(OptionBootfileName, d.Options)
	return strings.TrimRight(name, "\x00")
}

// TFTPServerName parses the DHCPv4 TFTP Server Name option if present.
//
// The TFTP Server Name option is described by RFC 2132, Section 9.4.
func (d *DHCPv4) TFTPServerName() string {
	name := GetString(OptionTFTPServerName, d.Options)
	return strings.TrimRight(name, "\x00")
}

// ClassIdentifier parses the DHCPv4 Class Identifier option if present.
//
// The Vendor Class Identifier option is described by RFC 2132, Section 9.13.
func (d *DHCPv4) ClassIdentifier() string {
	return GetString(OptionClassIdentifier, d.Options)
}

// ClientArch returns the Client System Architecture Type option.
func (d *DHCPv4) ClientArch() []iana.Arch {
	v := d.Options.Get(OptionClientSystemArchitectureType)
	if v == nil {
		return nil
	}
	var archs iana.Archs
	if err := archs.FromBytes(v); err != nil {
		return nil
	}
	return archs
}

// DomainSearch returns the domain search list if present.
//
// The domain search option is described by RFC 3397, Section 2.
func (d *DHCPv4) DomainSearch() *rfc1035label.Labels {
	v := d.Options.Get(OptionDNSDomainSearchList)
	if v == nil {
		return nil
	}
	labels, err := rfc1035label.FromBytes(v)
	if err != nil {
		return nil
	}
	return labels
}

// IPAddressLeaseTime returns the IP address lease time or the given
// default duration if not present.
//
// The IP address lease time option is described by RFC 2132, Section 9.2.
func (d *DHCPv4) IPAddressLeaseTime(def time.Duration) time.Duration {
	v := d.Options.Get(OptionIPAddressLeaseTime)
	if v == nil {
		return def
	}
	var dur Duration
	if err := dur.FromBytes(v); err != nil {
		return def
	}
	return time.Duration(dur)
}

// IPAddressRenewalTime returns the IP address renewal time or the given
// default duration if not present.
//
// The IP address renewal time option is described by RFC 2132, Section 9.11.
func (d *DHCPv4) IPAddressRenewalTime(def time.Duration) time.Duration {
	v := d.Options.Get(OptionRenewTimeValue)
	if v == nil {
		return def
	}
	var dur Duration
	if err := dur.FromBytes(v); err != nil {
		return def
	}
	return time.Duration(dur)
}

// IPAddressRebindingTime returns the IP address rebinding time or the given
// default duration if not present.
//
// The IP address rebinding time option is described by RFC 2132, Section 9.12.
func (d *DHCPv4) IPAddressRebindingTime(def time.Duration) time.Duration {
	v := d.Options.Get(OptionRebindingTimeValue)
	if v == nil {
		return def
	}
	var dur Duration
	if err := dur.FromBytes(v); err != nil {
		return def
	}
	return time.Duration(dur)
}

// MaxMessageSize returns the DHCP Maximum Message Size if present.
//
// The Maximum DHCP Message Size option is described by RFC 2132, Section 9.10.
func (d *DHCPv4) MaxMessageSize() (uint16, error) {
	return GetUint16(OptionMaximumDHCPMessageSize, d.Options)
}

// MessageType returns the DHCPv4 Message Type option.
func (d *DHCPv4) MessageType() MessageType {
	v := d.Options.Get(OptionDHCPMessageType)
	if v == nil {
		return MessageTypeNone
	}
	var m MessageType
	if err := m.FromBytes(v); err != nil {
		return MessageTypeNone
	}
	return m
}

// Message returns the DHCPv4 (Error) Message option.
//
// The message options is described in RFC 2132, Section 9.9.
func (d *DHCPv4) Message() string {
	return GetString(OptionMessage, d.Options)
}

// ParameterRequestList returns the DHCPv4 Parameter Request List.
//
// The parameter request list option is described by RFC 2132, Section 9.8.
func (d *DHCPv4) ParameterRequestList() OptionCodeList {
	v := d.Options.Get(OptionParameterRequestList)
	if v == nil {
		return nil
	}
	var codes OptionCodeList
	if err := codes.FromBytes(v); err != nil {
		return nil
	}
	return codes
}

// RelayAgentInfo returns options embedded by the relay agent.
//
// The relay agent info option is described by RFC 3046.
func (d *DHCPv4) RelayAgentInfo() *RelayOptions {
	v := d.Options.Get(OptionRelayAgentInformation)
	if v == nil {
		return nil
	}
	var relayOptions RelayOptions
	if err := relayOptions.FromBytes(v); err != nil {
		return nil
	}
	return &relayOptions
}

// SubnetMask returns a subnet mask option contained if present.
//
// The subnet mask option is described by RFC 2132, Section 3.3.
func (d *DHCPv4) SubnetMask() net.IPMask {
	v := d.Options.Get(OptionSubnetMask)
	if v == nil {
		return nil
	}
	var im IPMask
	if err := im.FromBytes(v); err != nil {
		return nil
	}
	return net.IPMask(im)
}

// UserClass returns the user class if present.
//
// The user class information option is defined by RFC 3004.
func (d *DHCPv4) UserClass() []string {
	v := d.Options.Get(OptionUserClassInformation)
	if v == nil {
		return nil
	}
	var uc Strings
	if err := uc.FromBytes(v); err != nil {
		return []string{GetString(OptionUserClassInformation, d.Options)}
	}
	return uc
}

// VIVC returns the vendor-identifying vendor class option if present.
func (d *DHCPv4) VIVC() VIVCIdentifiers {
	v := d.Options.Get(OptionVendorIdentifyingVendorClass)
	if v == nil {
		return nil
	}
	var ids VIVCIdentifiers
	if err := ids.FromBytes(v); err != nil {
		return nil
	}
	return ids
}
