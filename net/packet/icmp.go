// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	crand "crypto/rand"

	"encoding/binary"
)

// ICMPEchoPayload generates a new random ID/Sequence pair, and returns a uint32
// derived from them, along with the id, sequence and given payload in a buffer.
// It returns an error if the random source could not be read.
func ICMPEchoPayload(payload []byte) (idSeq uint32, buf []byte) {
	buf = make([]byte, len(payload)+4)

	// make a completely random id/sequence combo, which is very unlikely to
	// collide with a running ping sequence on the host system. Errors are
	// ignored, that would result in collisions, but errors reading from the
	// random device are rare, and will cause this process universe to soon end.
	crand.Read(buf[:4])

	idSeq = binary.LittleEndian.Uint32(buf)
	copy(buf[4:], payload)

	return
}
