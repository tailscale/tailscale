// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package clientupdate

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-systemd/v22/dbus"
)

func restartSystemdUnit(ctx context.Context) error {
	c, err := dbus.NewWithContext(ctx)
	if err != nil {
		// Likely not a systemd-managed distro.
		return errors.ErrUnsupported
	}
	defer c.Close()
	if err := c.ReloadContext(ctx); err != nil {
		return fmt.Errorf("failed to reload tailscaled.service: %w", err)
	}
	ch := make(chan string, 1)
	if _, err := c.RestartUnitContext(ctx, "tailscaled.service", "replace", ch); err != nil {
		return fmt.Errorf("failed to restart tailscaled.service: %w", err)
	}
	select {
	case res := <-ch:
		if res != "done" {
			return fmt.Errorf("systemd service restart failed with result %q", res)
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
