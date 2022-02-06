package netlink

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Rule represents a netlink rule.
type Rule struct {
	Priority          int
	Family            int
	Table             int
	Mark              int
	Mask              int
	Tos               uint
	TunID             uint
	Goto              int
	Src               *net.IPNet
	Dst               *net.IPNet
	Flow              int
	IifName           string
	OifName           string
	SuppressIfgroup   int
	SuppressPrefixlen int
	Invert            bool
	Dport             *RulePortRange
	Sport             *RulePortRange

	// Type is the unix.RTN_* rule type, such as RTN_UNICAST
	// or RTN_UNREACHABLE.
	// When adding a new rule, zero means automatic.
	Type uint8
}

func (r Rule) String() string {
	from := "all"
	if r.Src != nil && r.Src.String() != "<nil>" {
		from = r.Src.String()
	}

	to := "all"
	if r.Dst != nil && r.Dst.String() != "<nil>" {
		to = r.Dst.String()
	}

	var typ string
	switch r.Type {
	case unix.RTN_UNSPEC: // zero
		typ = ""
	case unix.RTN_UNICAST:
		typ = ""
	case unix.RTN_LOCAL:
		typ = " local"
	case unix.RTN_BROADCAST:
		typ = " broadcast"
	case unix.RTN_ANYCAST:
		typ = " anycast"
	case unix.RTN_MULTICAST:
		typ = " multicast"
	case unix.RTN_BLACKHOLE:
		typ = " blackhole"
	case unix.RTN_UNREACHABLE:
		typ = " unreachable"
	case unix.RTN_PROHIBIT:
		typ = " prohibit"
	case unix.RTN_THROW:
		typ = " throw"
	case unix.RTN_NAT:
		typ = " nat"
	case unix.RTN_XRESOLVE:
		typ = " xresolve"
	default:
		typ = fmt.Sprintf(" type(0x%x)", r.Type)
	}
	return fmt.Sprintf("ip rule %d: from %s to %s table %d%s",
		r.Priority, from, to, r.Table, typ)
}

// NewRule return empty rules.
func NewRule() *Rule {
	return &Rule{
		SuppressIfgroup:   -1,
		SuppressPrefixlen: -1,
		Priority:          -1,
		Mark:              -1,
		Mask:              -1,
		Goto:              -1,
		Flow:              -1,
	}
}

// NewRulePortRange creates rule sport/dport range.
func NewRulePortRange(start, end uint16) *RulePortRange {
	return &RulePortRange{Start: start, End: end}
}

// RulePortRange represents rule sport/dport range.
type RulePortRange struct {
	Start uint16
	End   uint16
}
