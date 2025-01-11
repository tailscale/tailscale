//go:build ts_omit_netstack

package main

import (
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
)

func newNetstack(logf logger.Logf, sys *tsd.System, onlyNetstack, handleSubnetsInNetstack bool) (start func(localBackend any) error, err error) {
	return func(any) error { return nil }, nil
}
