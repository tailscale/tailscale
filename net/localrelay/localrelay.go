package localrelay

import (
	"encoding/binary"
	"fmt"

	"go4.org/mem"
	"tailscale.com/types/key"
)

const (
	advertisementLen = 8 + key.DiscoPublicRawLen
)

var magic = [4]byte{'T', 'S', 'L', 'R'}

func MarshalAdvertisement(disco key.DiscoPublic, port uint16) []byte {
	b := make([]byte, advertisementLen)
	copy(b[:4], magic[:])
	b[4] = 1
	b[5] = 1
	binary.BigEndian.PutUint16(b[6:8], port)
	return disco.AppendTo(b[:8])
}

func ParseAdvertisement(b []byte) (key.DiscoPublic, uint16, error) {
	if len(b) != advertisementLen {
		return key.DiscoPublic{}, 0, fmt.Errorf("invalid advertisement length %d", len(b))
	}
	if string(b[:4]) != string(magic[:]) || b[4] != 1 || b[5] != 1 {
		return key.DiscoPublic{}, 0, fmt.Errorf("invalid advertisement header")
	}
	port := binary.BigEndian.Uint16(b[6:8])
	if port == 0 {
		return key.DiscoPublic{}, 0, fmt.Errorf("invalid advertisement port")
	}
	return key.DiscoPublicFromRaw32(mem.B(b[8:])), port, nil
}
