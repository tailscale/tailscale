package endian

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestNtoh16(t *testing.T) {
	raw := uint16(0xABCD)
	rawBytes := toNativeBytes16(raw)
	big := binary.BigEndian.Uint16(rawBytes[:])
	if raw != Ntoh16(big) {
		t.Errorf("ntohs failed, want %v, got %v", raw, Ntoh16(big))
	}
}

func toNativeBytes32(v uint32) [4]byte {
	return *(*[4]byte)(unsafe.Pointer(&v))
}

func TestHton32(t *testing.T) {
	raw := uint32(0xDEADBEEF)

	networkOrder := Hton32(raw)
	bytes := toNativeBytes32(networkOrder)
	fromBig := binary.BigEndian.Uint32(bytes[:])

	if fromBig != raw {
		t.Errorf("htonl failed, want %v, got %v", raw, fromBig)
	}
}

func toNativeBytes16(v uint16) [2]byte {
	return *(*[2]byte)(unsafe.Pointer(&v))
}

func TestHton16(t *testing.T) {
	raw := uint16(0xBEEF)

	networkOrder := Hton16(raw)
	bytes := toNativeBytes16(networkOrder)
	fromBig := binary.BigEndian.Uint16(bytes[:])

	if fromBig != raw {
		t.Errorf("htonl failed, want %v, got %v", raw, fromBig)
	}
}
