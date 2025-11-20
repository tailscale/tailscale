// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_appconnectors

package appc

func (e *AppConnector) ObserveDNSResponse(res []byte) error { return nil }
