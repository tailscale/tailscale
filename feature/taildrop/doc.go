// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package taildrop contains the implementation of the Taildrop
// functionality including sending and retrieving files.
// This package does not validate permissions, the caller should
// be responsible for ensuring correct authorization.
//
// For related documentation see: http://go/taildrop-how-does-it-work
package taildrop
