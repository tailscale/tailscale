// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"tailscale.com/atomicfile"
	"tailscale.com/control/controlclient"
)

type Prefs struct {
	RouteAll         bool
	AllowSingleHosts bool
	CorpDNS          bool
	WantRunning      bool
	NotepadURLs      bool
	UsePacketFilter  bool

	// The Persist field is named 'Config' in the file for backward
	// compatibility with earlier versions.
	// TODO(apenwarr): We should move this out of here, it's not a pref.
	//  We can maybe do that once we're sure which module should persist
	//  it (backend or frontend?)
	Persist *controlclient.Persist `json:"Config"`
}

// IsEmpty reports whether p is nil or pointing to a Prefs zero value.
func (uc *Prefs) IsEmpty() bool { return uc == nil || *uc == Prefs{} }

func (uc *Prefs) Pretty() string {
	var ucp string
	if uc.Persist != nil {
		ucp = uc.Persist.Pretty()
	} else {
		ucp = "Persist=nil"
	}
	return fmt.Sprintf("Prefs{ra=%v mesh=%v dns=%v want=%v notepad=%v pf=%v %v}",
		uc.RouteAll, uc.AllowSingleHosts, uc.CorpDNS, uc.WantRunning,
		uc.NotepadURLs, uc.UsePacketFilter, ucp)
}

func (uc *Prefs) ToBytes() []byte {
	data, err := json.MarshalIndent(uc, "", "\t")
	if err != nil {
		log.Fatalf("Prefs marshal: %v\n", err)
	}
	return data
}

func (uc *Prefs) Equals(uc2 *Prefs) bool {
	b1 := uc.ToBytes()
	b2 := uc2.ToBytes()
	return bytes.Equal(b1, b2)
}

func NewPrefs() Prefs {
	return Prefs{
		// Provide default values for options which are normally
		// true, but might be missing from the json data for any
		// reason. The json can still override them to false.
		RouteAll:         true,
		AllowSingleHosts: true,
		CorpDNS:          true,
		WantRunning:      true,
		UsePacketFilter:  true,
	}
}

func PrefsFromBytes(b []byte, enforceDefaults bool) (Prefs, error) {
	uc := NewPrefs()
	if len(b) == 0 {
		return uc, nil
	}
	persist := &controlclient.Persist{}
	err := json.Unmarshal(b, persist)
	if err == nil && (persist.Provider != "" || persist.LoginName != "") {
		// old-style relaynode config; import it
		uc.Persist = persist
	} else {
		err = json.Unmarshal(b, &uc)
		if err != nil {
			log.Printf("Prefs parse: %v: %v\n", err, b)
		}
	}
	if enforceDefaults {
		uc.RouteAll = true
		uc.AllowSingleHosts = true
	}
	return uc, err
}

func (uc *Prefs) Copy() *Prefs {
	uc2, err := PrefsFromBytes(uc.ToBytes(), false)
	if err != nil {
		log.Fatalf("Prefs was uncopyable: %v\n", err)
	}
	return &uc2
}

func LoadPrefs(filename string, enforceDefaults bool) *Prefs {
	log.Printf("Loading prefs %v\n", filename)
	data, err := ioutil.ReadFile(filename)
	uc := NewPrefs()
	if err != nil {
		log.Printf("Read: %v: %v\n", filename, err)
		goto fail
	}
	uc, err = PrefsFromBytes(data, enforceDefaults)
	if err != nil {
		log.Printf("Parse: %v: %v\n", filename, err)
		goto fail
	}
	goto post
fail:
	log.Printf("failed to load config. Generating a new one.\n")
	uc = NewPrefs()
	uc.WantRunning = true
post:
	// Update: we changed our minds :)
	// Versabank would like to persist the setting across reboots, for now,
	// because they don't fully trust the system and want to be able to
	// leave it turned off when not in use. Eventually we need to make
	// all motivation for this go away.
	if false {
		// Usability note: we always want WantRunning = true on startup.
		// That way, if someone accidentally disables their VPN and doesn't
		// know how, rebooting will fix it.
		// We still persist WantRunning just in case we change our minds on
		// this topic.
		uc.WantRunning = true
	}
	log.Printf("Loaded prefs %v %v\n", filename, uc.Pretty())
	return &uc
}

func SavePrefs(filename string, uc *Prefs) {
	log.Printf("Saving prefs %v %v\n", filename, uc.Pretty())
	data := uc.ToBytes()
	os.MkdirAll(filepath.Dir(filename), 0700)
	if err := atomicfile.WriteFile(filename, data, 0666); err != nil {
		log.Printf("SavePrefs: %v\n", err)
	}
}
