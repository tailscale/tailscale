package dhcpv4

import (
	"fmt"
	"strings"

	"github.com/u-root/uio/uio"
)

// Strings represents an option encapsulating a list of strings in IPv4 DHCP as
// specified in RFC 3004
//
// Strings implements the OptionValue type.
type Strings []string

// FromBytes parses Strings from a DHCP packet as specified by RFC 3004.
func (o *Strings) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	if buf.Len() == 0 {
		return fmt.Errorf("Strings DHCP option must always list at least one String")
	}

	*o = make(Strings, 0)
	for buf.Has(1) {
		ucLen := buf.Read8()
		if ucLen == 0 {
			return fmt.Errorf("DHCP Strings must have length greater than 0")
		}
		*o = append(*o, string(buf.CopyN(int(ucLen))))
	}
	return buf.FinError()
}

// ToBytes marshals Strings to a DHCP packet as specified by RFC 3004.
func (o Strings) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(nil)
	for _, uc := range o {
		buf.Write8(uint8(len(uc)))
		buf.WriteBytes([]byte(uc))
	}
	return buf.Data()
}

// String returns a human-readable representation of a list of Strings.
func (o Strings) String() string {
	return strings.Join(o, ", ")
}

// OptRFC3004UserClass returns a new user class option according to RFC 3004.
func OptRFC3004UserClass(v []string) Option {
	return Option{
		Code:  OptionUserClassInformation,
		Value: Strings(v),
	}
}
