// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_syspolicy

package tsd

import (
	"tailscale.com/util/syspolicy/policyclient"
)

func getPolicyClient() policyclient.Client { return policyclient.NoPolicyClient{} }
