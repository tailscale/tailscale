// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build mips mips64 ppc64 s390x

package ubinary

import (
	"encoding/binary"
)

// NativeEndian is $GOARCH's implementation of byte order.
var NativeEndian = binary.BigEndian
