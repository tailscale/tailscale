//go:build ts_omit_nftables

package linuxfw

import (
	"errors"

	"tailscale.com/types/logger"
)

// ErrUnsupported is the error returned from all functions on non-Linux
// platforms.
var ErrUnsupported = errors.New("linuxfw:unsupported")

// DetectNetfilter is not supported on non-Linux platforms.
func detectNetfilter() (int, error) {
	return 0, ErrUnsupported
}

func NfTablesCleanUp(logf logger.Logf) {}

func New(any, any) (NetfilterRunner, error) {
	return nil, ErrUnsupported
}
