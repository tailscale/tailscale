package rtnetlink

import (
	"encoding/binary"

	"github.com/mdlayher/netlink/nlenc"
)

var nativeEndian binary.ByteOrder

func init() {
	nativeEndian = nlenc.NativeEndian()
}
