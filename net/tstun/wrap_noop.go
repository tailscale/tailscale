// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || ts_omit_gro

package tstun

func (t *Wrapper) SetLinkFeaturesPostUp() {}
