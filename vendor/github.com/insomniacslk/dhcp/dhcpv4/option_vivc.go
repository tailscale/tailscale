package dhcpv4

import (
	"bytes"
	"fmt"

	"github.com/insomniacslk/dhcp/iana"
	"github.com/u-root/uio/uio"
)

// VIVCIdentifier implements the vendor-identifying vendor class option
// described by RFC 3925.
type VIVCIdentifier struct {
	// EntID is the enterprise ID.
	EntID iana.EnterpriseID
	Data  []byte
}

// OptVIVC returns a new vendor-identifying vendor class option.
//
// The option is described by RFC 3925.
func OptVIVC(identifiers ...VIVCIdentifier) Option {
	return Option{
		Code:  OptionVendorIdentifyingVendorClass,
		Value: VIVCIdentifiers(identifiers),
	}
}

// VIVCIdentifiers implements encoding and decoding methods for a DHCP option
// described in RFC 3925.
type VIVCIdentifiers []VIVCIdentifier

// FromBytes parses data into ids per RFC 3925.
func (ids *VIVCIdentifiers) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	for buf.Has(5) {
		entID := iana.EnterpriseID(buf.Read32())
		idLen := int(buf.Read8())
		*ids = append(*ids, VIVCIdentifier{EntID: entID, Data: buf.CopyN(idLen)})
	}
	return buf.FinError()
}

// ToBytes returns a serialized stream of bytes for this option.
func (ids VIVCIdentifiers) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(nil)
	for _, id := range ids {
		buf.Write32(uint32(id.EntID))
		buf.Write8(uint8(len(id.Data)))
		buf.WriteBytes(id.Data)
	}
	return buf.Data()
}

// String returns a human-readable string for this option.
func (ids VIVCIdentifiers) String() string {
	if len(ids) == 0 {
		return ""
	}
	buf := bytes.Buffer{}
	for _, id := range ids {
		fmt.Fprintf(&buf, " %d:'%s',", id.EntID, id.Data)
	}
	return buf.String()[1 : buf.Len()-1]
}
