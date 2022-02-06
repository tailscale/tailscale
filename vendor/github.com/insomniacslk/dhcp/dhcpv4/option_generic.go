package dhcpv4

import (
	"fmt"
)

// OptionGeneric is an option that only contains the option code and associated
// data. Every option that does not have a specific implementation will fall
// back to this option.
type OptionGeneric struct {
	Data []byte
}

// ToBytes returns a serialized generic option as a slice of bytes.
func (o OptionGeneric) ToBytes() []byte {
	return o.Data
}

// String returns a human-readable representation of a generic option.
func (o OptionGeneric) String() string {
	return fmt.Sprintf("%v", o.Data)
}

// OptGeneric returns a generic option.
func OptGeneric(code OptionCode, value []byte) Option {
	return Option{Code: code, Value: OptionGeneric{value}}
}
