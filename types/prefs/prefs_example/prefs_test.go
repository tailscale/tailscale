// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs_example

import (
	"fmt"
	"net/netip"

	"tailscale.com/ipn"
	"tailscale.com/types/prefs"
)

func ExamplePrefs_AdvertiseRoutes_setValue() {
	p := &Prefs{}

	// Initially, preferences are not configured.
	fmt.Println("IsSet:", p.AdvertiseRoutes.IsSet()) // prints false
	// And the Value method returns the default (or zero) value.
	fmt.Println("Initial:", p.AdvertiseRoutes.Value()) // prints []

	// Preferences can be configured with user-provided values using the
	// SetValue method. It may fail if the preference is managed via syspolicy
	// or is otherwise read-only.
	routes := []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}
	if err := p.AdvertiseRoutes.SetValue(routes); err != nil {
		// This block is never executed in the example because the
		// AdvertiseRoutes preference is neither managed nor read-only.
		fmt.Println("SetValue:", err)
	}
	fmt.Println("IsSet:", p.AdvertiseRoutes.IsSet()) // prints true
	fmt.Println("Value:", p.AdvertiseRoutes.Value()) // prints 192.168.1.1/24

	// Preference values are copied on use; you cannot not modify them after they are set.
	routes[0] = netip.MustParsePrefix("10.10.10.0/24")   // this has no effect
	fmt.Println("Unchanged:", p.AdvertiseRoutes.Value()) // still prints 192.168.1.1/24
	// If necessary, the value can be changed by calling the SetValue method again.
	p.AdvertiseRoutes.SetValue(routes)
	fmt.Println("Changed:", p.AdvertiseRoutes.Value()) // prints 10.10.10.0/24

	// The following code is fine when defining default or baseline prefs, or
	// in tests. However, assigning to a preference field directly overwrites
	// syspolicy-managed values and metadata, so it should generally be avoided
	// when working with the actual profile or device preferences.
	// It is caller's responsibility to use the mutable Prefs struct correctly.
	defaults := &Prefs{WantRunning: prefs.ItemOf(true)}
	defaults.CorpDNS = prefs.Item[bool]{}
	defaults.ExitNodeAllowLANAccess = prefs.ItemOf(true)
	_, _, _ = defaults.WantRunning, defaults.CorpDNS, defaults.ExitNodeAllowLANAccess

	// In most contexts, preferences should only be read and never mutated.
	// To make it easier to enforce this guarantee, a view type generated with
	// [tailscale.com/cmd/viewer] can be used instead of the mutable Prefs struct.
	// Preferences accessed via a view have the same set of non-mutating
	// methods as the underlying preferences but do not expose [prefs.Item.SetValue] or
	// other methods that modify the preference's value or state.
	v := p.View()
	// Additionally, non-mutating methods like [prefs.ItemView.Value] and [prefs.ItemView.ValueOk]
	// return read-only views of the underlying values instead of the actual potentially mutable values.
	// For example, on the next line Value() returns a views.Slice[netip.Prefix], not a []netip.Prefix.
	_ = v.AdvertiseRoutes().Value()
	fmt.Println("Via View:", v.AdvertiseRoutes().Value().At(0))  // prints 10.10.10.0/24
	fmt.Println("IsSet:", v.AdvertiseRoutes().IsSet())           // prints true
	fmt.Println("IsManaged:", v.AdvertiseRoutes().IsManaged())   // prints false
	fmt.Println("IsReadOnly:", v.AdvertiseRoutes().IsReadOnly()) // prints false

	// Output:
	// IsSet: false
	// Initial: []
	// IsSet: true
	// Value: [192.168.1.1/24]
	// Unchanged: [192.168.1.1/24]
	// Changed: [10.10.10.0/24]
	// Via View: 10.10.10.0/24
	// IsSet: true
	// IsManaged: false
	// IsReadOnly: false
}

func ExamplePrefs_ControlURL_setDefaultValue() {
	p := &Prefs{}
	v := p.View()

	// We can set default values for preferences when their default values
	// should differ from the zero values of the corresponding Go types.
	//
	// Note that in this example, we configure preferences via a mutable
	// [Prefs] struct but fetch values via a read-only [PrefsView].
	// Typically, we set and get preference values in different parts
	// of the codebase.
	p.ControlURL.SetDefaultValue(ipn.DefaultControlURL)
	// The default value is used if the preference is not configured...
	fmt.Println("Default:", v.ControlURL().Value())
	p.ControlURL.SetValue("https://control.example.com")
	fmt.Println("User Set:", v.ControlURL().Value())
	// ...including when it has been reset.
	p.ControlURL.ClearValue()
	fmt.Println("Reset to Default:", v.ControlURL().Value())

	// Output:
	// Default: https://controlplane.tailscale.com
	// User Set: https://control.example.com
	// Reset to Default: https://controlplane.tailscale.com
}

func ExamplePrefs_ExitNodeID_setManagedValue() {
	p := &Prefs{}
	v := p.View()

	// We can mark preferences as being managed via syspolicy (e.g., via GP/MDM)
	// by setting its managed value.
	//
	// Note that in this example, we enforce syspolicy-managed values
	// via a mutable [Prefs] struct but fetch values via a read-only [PrefsView].
	// This is typically spread throughout the codebase.
	p.ExitNodeID.SetManagedValue("ManagedExitNode")
	// Marking a preference as managed prevents it from being changed by the user.
	if err := p.ExitNodeID.SetValue("CustomExitNode"); err != nil {
		fmt.Println("SetValue:", err) // reports an error
	}
	fmt.Println("Exit Node:", v.ExitNodeID().Value()) // prints ManagedExitNode

	// Clients can hide or disable preferences that are managed or read-only.
	fmt.Println("IsManaged:", v.ExitNodeID().IsManaged())   // prints true
	fmt.Println("IsReadOnly:", v.ExitNodeID().IsReadOnly()) // prints true; managed preferences are always read-only.

	// ClearManaged is called when the preference is no longer managed,
	// allowing the user to change it.
	p.ExitNodeID.ClearManaged()
	fmt.Println("IsManaged:", v.ExitNodeID().IsManaged())   // prints false
	fmt.Println("IsReadOnly:", v.ExitNodeID().IsReadOnly()) // prints false

	// Output:
	// SetValue: cannot modify a managed preference
	// Exit Node: ManagedExitNode
	// IsManaged: true
	// IsReadOnly: true
	// IsManaged: false
	// IsReadOnly: false
}
