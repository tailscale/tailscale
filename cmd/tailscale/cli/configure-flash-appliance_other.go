// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_flashappliance && !linux && !darwin

package cli

import (
	"context"
	"errors"
	"os"
	"runtime"
)

var errFlashUnsupported = errors.New("flash-appliance is only supported on linux and darwin (got " + runtime.GOOS + ")")

func discoverExternalDisks(_ context.Context) ([]diskCandidate, error) {
	return nil, errFlashUnsupported
}

func validateDiskPath(_ string) error {
	return errFlashUnsupported
}

func unmountDisk(_ context.Context, _ string) error {
	return errFlashUnsupported
}

func openBlockDevice(_ string) (*os.File, error) {
	return nil, errFlashUnsupported
}

func rereadPartitionTable(_ *os.File) error { return nil }

func blockDeviceSize(_ *os.File) (int64, error) { return 0, errFlashUnsupported }

func syncBlockDevice(_ *os.File) error { return errFlashUnsupported }

func ejectDisk(_ context.Context, _ string) (bool, error) { return false, errFlashUnsupported }
