// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || ts_omit_gro

package tstun

import "tailscale.com/control/controlknobs"

func (t *Wrapper) SetLinkFeaturesPostUp(_ *controlknobs.Knobs) {}

func (t *Wrapper) ApplyGROKnobs(_ *controlknobs.Knobs) {}
