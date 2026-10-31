// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package guivisibility

import (
	"tailscale.com/feature"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
)

func init() {
	if feature.Register("guivisibility") {
		ipnext.RegisterExtension("guivisibility", func(logger.Logf, ipnext.SafeBackend) (ipnext.Extension, error) {
			return extension{}, nil
		})
	}
}

type extension struct{}

func (extension) Name() string           { return "guivisibility" }
func (extension) Init(ipnext.Host) error { return nil }
func (extension) Shutdown() error        { return nil }

func (extension) ForPolicy(snapshot *policyclient.PolicySnapshot) ipnext.GUIVisibilityFilter {
	f := visibilityFilter{}
	for _, value := range policyclient.GetStringArrayFromSnapshot(snapshot, pkey.HiddenNetworkDevices) {
		switch value {
		case "current-user":
			f.currentUser = true
		case "other-users":
			f.otherUsers = true
		case "tagged-devices":
			f.taggedDevices = true
		}
	}
	if !f.currentUser && !f.otherUsers && !f.taggedDevices {
		return nil
	}
	return f
}

type visibilityFilter struct{ currentUser, otherUsers, taggedDevices bool }

func (f visibilityFilter) Hide(peer, self tailcfg.NodeView) bool {
	if !peer.Valid() || !self.Valid() || peer.ID() == self.ID() {
		return false
	}
	if peer.IsTagged() {
		return f.taggedDevices
	}
	if peer.SharerOrUser() == self.User() {
		return f.currentUser
	}
	return f.otherUsers
}
