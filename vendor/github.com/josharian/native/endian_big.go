// +build mips mips64 ppc64 s390x

package native

import "encoding/binary"

var Endian = binary.BigEndian
