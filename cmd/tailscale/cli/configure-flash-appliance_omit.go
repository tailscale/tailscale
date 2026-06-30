// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_flashappliance

package cli

import "github.com/peterbourgon/ff/v3/ffcli"

func flashApplianceCmd() *ffcli.Command {
	// Omitted from the build when the ts_omit_flashappliance build tag is set.
	return nil
}
