/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net"
)

const (
	IPv4offsetTotalLength = 2
	IPv4offsetSrc         = 12
	IPv4offsetDst         = IPv4offsetSrc + net.IPv4len
)

const (
	IPv6offsetPayloadLength = 4
	IPv6offsetSrc           = 8
	IPv6offsetDst           = IPv6offsetSrc + net.IPv6len
)
