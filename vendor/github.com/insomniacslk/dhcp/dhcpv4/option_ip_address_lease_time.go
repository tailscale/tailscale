package dhcpv4

import (
	"math"
	"time"

	"github.com/u-root/uio/uio"
)

// MaxLeaseTime is the maximum lease time that can be encoded.
var MaxLeaseTime = math.MaxUint32 * time.Second

// Duration implements the IP address lease time option described by RFC 2132,
// Section 9.2.
type Duration time.Duration

// FromBytes parses a duration from a byte stream according to RFC 2132, Section 9.2.
func (d *Duration) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	*d = Duration(time.Duration(buf.Read32()) * time.Second)
	return buf.FinError()
}

// ToBytes returns a serialized stream of bytes for this option.
func (d Duration) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(nil)
	buf.Write32(uint32(time.Duration(d) / time.Second))
	return buf.Data()
}

// String returns a human-readable string for this option.
func (d Duration) String() string {
	return time.Duration(d).String()
}

// OptIPAddressLeaseTime returns a new IP address lease time option.
//
// The IP address lease time option is described by RFC 2132, Section 9.2.
func OptIPAddressLeaseTime(d time.Duration) Option {
	return Option{Code: OptionIPAddressLeaseTime, Value: Duration(d)}
}
