// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux || ts_omit_tap

package tstun

func (*Wrapper) handleTAPFrame([]byte) bool        { panic("unreachable") }
func (*Wrapper) tapWrite([]byte, int) (int, error) { panic("unreachable") }
