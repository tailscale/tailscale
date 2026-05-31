// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/safchain/ethtool"
)

type netdevFeatureReport struct {
	Name     string          `json:"name"`
	Flags    net.Flags       `json:"flags"`
	Driver   string          `json:"driver,omitempty"`
	BusInfo  string          `json:"busInfo,omitempty"`
	Features map[string]bool `json:"features,omitempty"`
	Error    string          `json:"error,omitempty"`
}

func handleNetdevFeatures(w http.ResponseWriter, r *http.Request) {
	eth, err := ethtool.NewEthtool()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer eth.Close()

	ifaces, err := net.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var out []netdevFeatureReport
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		rep := netdevFeatureReport{
			Name:  iface.Name,
			Flags: iface.Flags,
		}
		if di, err := eth.DriverInfo(iface.Name); err == nil {
			rep.Driver = di.Driver
			rep.BusInfo = di.BusInfo
		}
		if features, err := eth.Features(iface.Name); err == nil {
			rep.Features = features
		} else {
			rep.Error = err.Error()
		}
		out = append(out, rep)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
