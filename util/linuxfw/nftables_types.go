// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO(#8502): add support for more architectures
//go:build linux && (arm64 || amd64)

package linuxfw

import (
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

var metaKeyNames = map[expr.MetaKey]string{
	expr.MetaKeyLEN:        "LEN",
	expr.MetaKeyPROTOCOL:   "PROTOCOL",
	expr.MetaKeyPRIORITY:   "PRIORITY",
	expr.MetaKeyMARK:       "MARK",
	expr.MetaKeyIIF:        "IIF",
	expr.MetaKeyOIF:        "OIF",
	expr.MetaKeyIIFNAME:    "IIFNAME",
	expr.MetaKeyOIFNAME:    "OIFNAME",
	expr.MetaKeyIIFTYPE:    "IIFTYPE",
	expr.MetaKeyOIFTYPE:    "OIFTYPE",
	expr.MetaKeySKUID:      "SKUID",
	expr.MetaKeySKGID:      "SKGID",
	expr.MetaKeyNFTRACE:    "NFTRACE",
	expr.MetaKeyRTCLASSID:  "RTCLASSID",
	expr.MetaKeySECMARK:    "SECMARK",
	expr.MetaKeyNFPROTO:    "NFPROTO",
	expr.MetaKeyL4PROTO:    "L4PROTO",
	expr.MetaKeyBRIIIFNAME: "BRIIIFNAME",
	expr.MetaKeyBRIOIFNAME: "BRIOIFNAME",
	expr.MetaKeyPKTTYPE:    "PKTTYPE",
	expr.MetaKeyCPU:        "CPU",
	expr.MetaKeyIIFGROUP:   "IIFGROUP",
	expr.MetaKeyOIFGROUP:   "OIFGROUP",
	expr.MetaKeyCGROUP:     "CGROUP",
	expr.MetaKeyPRANDOM:    "PRANDOM",
}

var cmpOpNames = map[expr.CmpOp]string{
	expr.CmpOpEq:  "EQ",
	expr.CmpOpNeq: "NEQ",
	expr.CmpOpLt:  "LT",
	expr.CmpOpLte: "LTE",
	expr.CmpOpGt:  "GT",
	expr.CmpOpGte: "GTE",
}

var verdictNames = map[expr.VerdictKind]string{
	expr.VerdictReturn:   "RETURN",
	expr.VerdictGoto:     "GOTO",
	expr.VerdictJump:     "JUMP",
	expr.VerdictBreak:    "BREAK",
	expr.VerdictContinue: "CONTINUE",
	expr.VerdictDrop:     "DROP",
	expr.VerdictAccept:   "ACCEPT",
	expr.VerdictStolen:   "STOLEN",
	expr.VerdictQueue:    "QUEUE",
	expr.VerdictRepeat:   "REPEAT",
	expr.VerdictStop:     "STOP",
}

var payloadOperationTypeNames = map[expr.PayloadOperationType]string{
	expr.PayloadLoad:  "LOAD",
	expr.PayloadWrite: "WRITE",
}

var payloadBaseNames = map[expr.PayloadBase]string{
	expr.PayloadBaseLLHeader:        "ll-header",
	expr.PayloadBaseNetworkHeader:   "network-header",
	expr.PayloadBaseTransportHeader: "transport-header",
}

var packetTypeNames = map[int]string{
	0 /* PACKET_HOST */ :      "unicast",
	1 /* PACKET_BROADCAST */ : "broadcast",
	2 /* PACKET_MULTICAST */ : "multicast",
}

var addrTypeFlagNames = map[xt.AddrTypeFlags]string{
	xt.AddrTypeUnspec:      "unspec",
	xt.AddrTypeUnicast:     "unicast",
	xt.AddrTypeLocal:       "local",
	xt.AddrTypeBroadcast:   "broadcast",
	xt.AddrTypeAnycast:     "anycast",
	xt.AddrTypeMulticast:   "multicast",
	xt.AddrTypeBlackhole:   "blackhole",
	xt.AddrTypeUnreachable: "unreachable",
	xt.AddrTypeProhibit:    "prohibit",
	xt.AddrTypeThrow:       "throw",
	xt.AddrTypeNat:         "nat",
	xt.AddrTypeXresolve:    "xresolve",
}
