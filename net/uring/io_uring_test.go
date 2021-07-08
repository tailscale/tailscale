// +build linux

package uring

import (
	"testing"
)

func TestUringAvailable(t *testing.T) {
	uringSupported()
}
