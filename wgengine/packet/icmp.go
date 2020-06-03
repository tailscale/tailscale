package packet

type ICMPType uint8

const (
	ICMPEchoReply    = 0x00
	ICMPEchoRequest  = 0x08
	ICMPUnreachable  = 0x03
	ICMPTimeExceeded = 0x0b
)

func (t ICMPType) String() string {
	switch t {
	case ICMPEchoReply:
		return "EchoReply"
	case ICMPEchoRequest:
		return "EchoRequest"
	case ICMPUnreachable:
		return "Unreachable"
	case ICMPTimeExceeded:
		return "TimeExceeded"
	default:
		return "Unknown"
	}
}

type ICMPCode uint8

const (
	NoCode ICMPCode = 0
)

// ICMPHeader represents an ICMP packet header.
type ICMPHeader struct {
	IPHeader
	Type ICMPType
	Code ICMPCode
}

const (
	icmpHeaderLength = 4
	// icmpTotalHeaderLength is the length of all headers in a ICMP packet.
	icmpAllHeadersLength = ipHeaderLength + icmpHeaderLength
)

func (h *ICMPHeader) Length() int {
	return icmpAllHeadersLength
}

func (h *ICMPHeader) Marshal(buf []byte) error {
	if len(buf) < icmpAllHeadersLength {
		return errSmallBuffer
	}
	// The caller does not need to set this.
	h.IPProto = ICMP

	buf[20] = uint8(h.Type)
	buf[21] = uint8(h.Code)

	h.IPHeader.Marshal(buf)

	put16(buf[22:24], ipChecksum(buf))

	return nil
}

func (h *ICMPHeader) NewPacketWithPayload(payload []byte) []byte {
	headerLength := h.Length()
	packetLength := headerLength + len(payload)
	buf := make([]byte, packetLength)

	copy(buf[headerLength:], payload)
	h.Marshal(buf)

	return buf
}

func (h *ICMPHeader) ToResponse() {
	h.Type = ICMPEchoReply
	h.Code = NoCode
	h.IPHeader.ToResponse()
}
