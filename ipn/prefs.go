// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/atomicfile"
	"tailscale.com/control/controlclient"
)

// Prefs are the user modifiable settings of the Tailscale node agent.
type Prefs struct {
	// ControlURL is the URL of the control server to use.
	ControlURL string
	// RouteAll specifies whether to accept subnet and default routes
	// advertised by other nodes on the Tailscale network.
	RouteAll bool
	// AllowSingleHosts specifies whether to install routes for each
	// node IP on the tailscale network, in addition to a route for
	// the whole network.
	//
	// TODO(danderson): why do we have this? It dumps a lot of stuff
	// into the routing table, and a single network route _should_ be
	// all that we need. But when I turn this off in my tailscaled,
	// packets stop flowing. What's up with that?
	AllowSingleHosts bool
	// CorpDNS specifies whether to install the Tailscale network's
	// DNS configuration, if it exists.
	CorpDNS bool
	// WantRunning indicates whether networking should be active on
	// this node.
	WantRunning bool
	// UsePacketFilter indicates whether to enforce centralized ACLs
	// on this node. If false, all traffic in and out of this node is
	// allowed.
	UsePacketFilter bool
	// AdvertiseRoutes specifies CIDR prefixes to advertise into the
	// Tailscale network as reachable through the current node.
	AdvertiseRoutes []wgcfg.CIDR

	// NotepadURLs is a debugging setting that opens OAuth URLs in
	// notepad.exe on Windows, rather than loading them in a browser.
	//
	// TODO(danderson): remove?
	NotepadURLs bool

	// DisableDERP prevents DERP from being used.
	DisableDERP bool

	// The Persist field is named 'Config' in the file for backward
	// compatibility with earlier versions.
	// TODO(apenwarr): We should move this out of here, it's not a pref.
	//  We can maybe do that once we're sure which module should persist
	//  it (backend or frontend?)
	Persist *controlclient.Persist `json:"Config"`
}

// IsEmpty reports whether p is nil or pointing to a Prefs zero value.
func (p *Prefs) IsEmpty() bool { return p == nil || p.Equals(&Prefs{}) }

func (p *Prefs) Pretty() string {
	var pp string
	if p.Persist != nil {
		pp = p.Persist.Pretty()
	} else {
		pp = "Persist=nil"
	}
	return fmt.Sprintf("Prefs{ra=%v mesh=%v dns=%v want=%v notepad=%v pf=%v routes=%v %v}",
		p.RouteAll, p.AllowSingleHosts, p.CorpDNS, p.WantRunning,
		p.NotepadURLs, p.UsePacketFilter, p.AdvertiseRoutes, pp)
}

func (p *Prefs) ToBytes() []byte {
	data, err := json.MarshalIndent(p, "", "\t")
	if err != nil {
		log.Fatalf("Prefs marshal: %v\n", err)
	}
	return data
}

func (p *Prefs) Equals(p2 *Prefs) bool {
	if p == nil && p2 == nil {
		return true
	}
	if p == nil || p2 == nil {
		return false
	}

	return p != nil && p2 != nil &&
		p.ControlURL == p2.ControlURL &&
		p.RouteAll == p2.RouteAll &&
		p.AllowSingleHosts == p2.AllowSingleHosts &&
		p.CorpDNS == p2.CorpDNS &&
		p.WantRunning == p2.WantRunning &&
		p.NotepadURLs == p2.NotepadURLs &&
		p.DisableDERP == p2.DisableDERP &&
		p.UsePacketFilter == p2.UsePacketFilter &&
		compareIPNets(p.AdvertiseRoutes, p2.AdvertiseRoutes) &&
		p.Persist.Equals(p2.Persist)
}

func compareIPNets(a, b []wgcfg.CIDR) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].IP.Equal(&b[i].IP) || a[i].Mask != b[i].Mask {
			return false
		}
	}
	return true
}

func NewPrefs() *Prefs {
	return &Prefs{
		// Provide default values for options which might be missing
		// from the json data for any reason. The json can still
		// override them to false.
		ControlURL:       "https://login.tailscale.com",
		RouteAll:         true,
		AllowSingleHosts: true,
		CorpDNS:          true,
		WantRunning:      true,
		UsePacketFilter:  true,
	}
}

// PrefsFromBytes deserializes Prefs from a JSON blob. If
// enforceDefaults is true, Prefs.RouteAll and Prefs.AllowSingleHosts
// are forced on.
func PrefsFromBytes(b []byte, enforceDefaults bool) (*Prefs, error) {
	p := NewPrefs()
	if len(b) == 0 {
		return p, nil
	}
	persist := &controlclient.Persist{}
	err := json.Unmarshal(b, persist)
	if err == nil && (persist.Provider != "" || persist.LoginName != "") {
		// old-style relaynode config; import it
		p.Persist = persist
	} else {
		err = json.Unmarshal(b, &p)
		if err != nil {
			log.Printf("Prefs parse: %v: %v\n", err, b)
		}
	}
	if enforceDefaults {
		p.RouteAll = true
		p.AllowSingleHosts = true
	}
	return p, err
}

// Clone returns a deep copy of p.
func (p *Prefs) Clone() *Prefs {
	// TODO: write a faster/non-Fatal-y Clone implementation?
	p2, err := PrefsFromBytes(p.ToBytes(), false)
	if err != nil {
		log.Fatalf("Prefs was uncopyable: %v\n", err)
	}
	return p2
}

// LoadLegacyPrefs loads a legacy relaynode config file into Prefs
// with sensible migration defaults set. If enforceDefaults is true,
// Prefs.RouteAll and Prefs.AllowSingleHosts are forced on.
func LoadPrefs(filename string, enforceDefaults bool) (*Prefs, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("loading prefs from %q: %v", filename, err)
	}
	p, err := PrefsFromBytes(data, false)
	if err != nil {
		return nil, fmt.Errorf("decoding prefs in %q: %v", filename, err)
	}
	return p, nil
}

func SavePrefs(filename string, p *Prefs) {
	log.Printf("Saving prefs %v %v\n", filename, p.Pretty())
	data := p.ToBytes()
	os.MkdirAll(filepath.Dir(filename), 0700)
	if err := atomicfile.WriteFile(filename, data, 0666); err != nil {
		log.Printf("SavePrefs: %v\n", err)
	}
}
