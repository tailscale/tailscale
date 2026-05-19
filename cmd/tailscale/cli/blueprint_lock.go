// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"

	"tailscale.com/ipn"
	"tailscale.com/util/clientmetric"
)

// metricBlueprintSetRejected counts `tailscale set` invocations that
// were rejected because the node is blueprint-bound and the set
// touches a blueprint-owned field. See checkBlueprintSetLocked.
var metricBlueprintSetRejected = clientmetric.NewCounter("cli_blueprint_set_rejected")

// blueprintLockedField names a single Prefs field that is locked
// when a node is blueprint-bound. The flag is the CLI flag name used
// in the user-visible error message; the maskField is the matching
// MaskedPrefs bool that, when true, indicates the user attempted to
// set the underlying Prefs field. Plural is the noun form used in
// the spec's "X are managed by the blueprint" sentence.
type blueprintLockedField struct {
	flag      string
	plural    string
	maskField func(*ipn.MaskedPrefs) bool
}

// blueprintLockedFields enumerates every Prefs field that
// `tailscale set` refuses to edit on a blueprint-bound node. The
// list is sourced from spec §11; if you add or remove a locked field
// here, update the spec and BLUEPRINTS.md.
//
// Spec v2 excludes node-local concerns (hostname, operator) and the
// v1.1-era node-level toggles shields-up and webclient. AdvertiseRoutes
// also covers advertise-exit-node, since exit-node advertisement is
// stored as the v4+v6 default routes in Prefs.AdvertiseRoutes.
//
// The order matters: the first matching field in this slice is the
// one named in the user-visible error message. Ordering follows the
// spec's prose listing so the error is predictable for operators.
var blueprintLockedFields = []blueprintLockedField{
	{
		flag:      "advertise-tags",
		plural:    "Advertised tags",
		maskField: func(m *ipn.MaskedPrefs) bool { return m.AdvertiseTagsSet },
	},
	{
		flag:      "advertise-routes",
		plural:    "Routes",
		maskField: func(m *ipn.MaskedPrefs) bool { return m.AdvertiseRoutesSet },
	},
	{
		flag:      "advertise-connector",
		plural:    "App connector advertisement",
		maskField: func(m *ipn.MaskedPrefs) bool { return m.AppConnectorSet },
	},
	{
		flag:      "ssh",
		plural:    "SSH",
		maskField: func(m *ipn.MaskedPrefs) bool { return m.RunSSHSet },
	},
	{
		flag:      "accept-dns",
		plural:    "DNS acceptance",
		maskField: func(m *ipn.MaskedPrefs) bool { return m.CorpDNSSet },
	},
	{
		flag:      "accept-routes",
		plural:    "Route acceptance",
		maskField: func(m *ipn.MaskedPrefs) bool { return m.RouteAllSet },
	},
}

// checkBlueprintSetLocked returns a non-nil error if curPrefs is
// blueprint-bound and mp touches any field the blueprint owns. The
// error message is the verbatim spec text:
//
//	this node is bound to bp:<id>. <Field> are managed by
//	the blueprint. Edit the blueprint in the ACL to change what this node
//	serves, or run 'tailscale leave' to detach.
//
// The "Error: " prefix shown in the spec output is appended by the
// CLI's top-level error printer; this function returns only the body.
//
// When the error fires, the cli_blueprint_set_rejected counter is
// incremented so we can observe attempted rejections in the field.
func checkBlueprintSetLocked(curPrefs *ipn.Prefs, mp *ipn.MaskedPrefs) error {
	if !curPrefs.IsBlueprintBound() {
		return nil
	}
	if mp == nil {
		return nil
	}
	for _, f := range blueprintLockedFields {
		if f.maskField(mp) {
			metricBlueprintSetRejected.Add(1)
			return fmt.Errorf("this node is bound to bp:%s. %s are managed by\nthe blueprint. Edit the blueprint in the ACL to change what this node\nserves, or run 'tailscale leave' to detach.",
				curPrefs.BlueprintID, f.plural)
		}
	}
	return nil
}
