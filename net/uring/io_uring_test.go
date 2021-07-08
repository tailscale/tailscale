// +build linux

package uring

import (
	"testing"
)

func TestCapabilities(t *testing.T) {
	// just checks that running doesn't segfault
	checkCapability(opNop)
}

func TestURingAvailable(t *testing.T) {
	uringOnSystem()
}
