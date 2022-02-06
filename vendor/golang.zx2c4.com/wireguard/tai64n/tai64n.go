/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package tai64n

import (
	"bytes"
	"encoding/binary"
	"time"
)

const TimestampSize = 12
const base = uint64(0x400000000000000a)
const whitenerMask = uint32(0x1000000 - 1)

type Timestamp [TimestampSize]byte

func stamp(t time.Time) Timestamp {
	var tai64n Timestamp
	secs := base + uint64(t.Unix())
	nano := uint32(t.Nanosecond()) &^ whitenerMask
	binary.BigEndian.PutUint64(tai64n[:], secs)
	binary.BigEndian.PutUint32(tai64n[8:], nano)
	return tai64n
}

func Now() Timestamp {
	return stamp(time.Now())
}

func (t1 Timestamp) After(t2 Timestamp) bool {
	return bytes.Compare(t1[:], t2[:]) > 0
}

func (t Timestamp) String() string {
	return time.Unix(int64(binary.BigEndian.Uint64(t[:8])-base), int64(binary.BigEndian.Uint32(t[8:12]))).String()
}
