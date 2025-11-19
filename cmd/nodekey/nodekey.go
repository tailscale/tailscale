package main

import (
	"fmt"
	"log"
	"os"

	"go4.org/mem"
	"tailscale.com/types/key"
)

func main() {
	for _, arg := range os.Args[1:] {
		k, err := key.ParseNodePublicUntyped(mem.B([]byte(arg)))
		if err != nil {
			log.Printf("invalid node key %q: %v", arg, err)
		}
		b, err := parseDebug32(arg)
		if err != nil {
			log.Printf("invalid debug32 format for %q: %v", arg, err)
		}
		k = key.NodePublicFromRaw32(mem.B(b[:]))
		log.Printf("node key: %s", k.ShortString())
		log.Printf("node key: %s", k.String())
	}
}

// parseDebug32 attempts to reconstruct the first 4 bytes of a key
// from the Tailscale debug representation like "[abcde]".
// The remaining bytes will be zero.
func parseDebug32(s string) ([32]byte, error) {
	var k [32]byte

	if s == "" {
		return k, nil
	}
	if len(s) != 7 || s[0] != '[' || s[6] != ']' {
		return k, fmt.Errorf("invalid debug32 format %q", s)
	}

	decode64 := func(c byte) (byte, bool) {
		switch {
		case 'A' <= c && c <= 'Z':
			return c - 'A', true
		case 'a' <= c && c <= 'z':
			return c - 'a' + 26, true
		case '0' <= c && c <= '9':
			return c - '0' + 52, true
		case c == '+':
			return 62, true
		case c == '/':
			return 63, true
		default:
			return 0, false
		}
	}

	v0, ok := decode64(s[1])
	if !ok {
		return k, fmt.Errorf("invalid debug32 format %q", s)
	}
	v1, ok := decode64(s[2])
	if !ok {
		return k, fmt.Errorf("invalid debug32 format %q", s)
	}
	v2, ok := decode64(s[3])
	if !ok {
		return k, fmt.Errorf("invalid debug32 format %q", s)
	}
	v3, ok := decode64(s[4])
	if !ok {
		return k, fmt.Errorf("invalid debug32 format %q", s)
	}
	v4, ok := decode64(s[5])
	if !ok {
		return k, fmt.Errorf("invalid debug32 format %q", s)
	}

	k[0] = v0<<2 | v1>>4
	k[1] = v1<<4 | v2>>2
	k[2] = v2<<6 | v3
	k[3] = v4 << 2 // low 2 bits were discarded by debug32

	return k, nil
}
