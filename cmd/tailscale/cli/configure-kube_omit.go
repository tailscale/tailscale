// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_kube

package cli

import "github.com/peterbourgon/ff/v3/ffcli"

func configureKubeconfigCmd() *ffcli.Command {
	// omitted from the build when the ts_omit_kube build tag is set
	return nil
}
