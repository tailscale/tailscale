// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"fmt"
	"log"
	"os"
)

type apiServerProxyMode int

func (a apiServerProxyMode) String() string {
	switch a {
	case apiServerProxyModeDisabled:
		return "disabled"
	case apiServerProxyModeEnabled:
		return "auth"
	case apiServerProxyModeNoAuth:
		return "noauth"
	default:
		return "unknown"
	}
}

const (
	apiServerProxyModeDisabled apiServerProxyMode = iota
	apiServerProxyModeEnabled
	apiServerProxyModeNoAuth
)

func parseAPIProxyMode() apiServerProxyMode {
	haveAuthProxyEnv := os.Getenv("AUTH_PROXY") != ""
	haveAPIProxyEnv := os.Getenv("APISERVER_PROXY") != ""
	switch {
	case haveAPIProxyEnv && haveAuthProxyEnv:
		log.Fatal("AUTH_PROXY (deprecated) and APISERVER_PROXY are mutually exclusive, please unset AUTH_PROXY")
	case haveAuthProxyEnv:
		var authProxyEnv = defaultBool("AUTH_PROXY", false) // deprecated
		if authProxyEnv {
			return apiServerProxyModeEnabled
		}
		return apiServerProxyModeDisabled
	case haveAPIProxyEnv:
		var apiProxyEnv = defaultEnv("APISERVER_PROXY", "") // true, false or "noauth"
		switch apiProxyEnv {
		case "true":
			return apiServerProxyModeEnabled
		case "false", "":
			return apiServerProxyModeDisabled
		case "noauth":
			return apiServerProxyModeNoAuth
		default:
			panic(fmt.Sprintf("unknown APISERVER_PROXY value %q", apiProxyEnv))
		}
	}
	return apiServerProxyModeDisabled
}
