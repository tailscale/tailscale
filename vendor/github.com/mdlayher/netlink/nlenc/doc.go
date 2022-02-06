// Package nlenc implements encoding and decoding functions for netlink
// messages and attributes.
package nlenc

import (
	"encoding/binary"

	"github.com/josharian/native"
)

// NativeEndian returns the native byte order of this system.
func NativeEndian() binary.ByteOrder {
	// TODO(mdlayher): consider deprecating and removing this function for v2.
	return native.Endian
}
