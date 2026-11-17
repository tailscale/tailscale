// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build experiment.reco

package testcontrol

import "github.com/bradfitz/reco/recotestcontrol"

// Re-export the test server API so callers can select either implementation
// using only a build tag. The reco implementation supports capability 109+.
type Server = recotestcontrol.Server
type AuthPath = recotestcontrol.AuthPath
type MasqueradePair = recotestcontrol.MasqueradePair
type AltMapStreamFunc = recotestcontrol.AltMapStreamFunc
type MapStreamWriter = recotestcontrol.MapStreamWriter

var RejectRequestForPath = recotestcontrol.RejectRequestForPath
