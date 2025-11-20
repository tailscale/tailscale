// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"fmt"
	"log"
	"os"

	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/ptr"
)

func parseAPIProxyMode() *kubetypes.APIServerProxyMode {
	haveAuthProxyEnv := os.Getenv("AUTH_PROXY") != ""
	haveAPIProxyEnv := os.Getenv("APISERVER_PROXY") != ""
	switch {
	case haveAPIProxyEnv && haveAuthProxyEnv:
		log.Fatal("AUTH_PROXY (deprecated) and APISERVER_PROXY are mutually exclusive, please unset AUTH_PROXY")
	case haveAuthProxyEnv:
		var authProxyEnv = defaultBool("AUTH_PROXY", false) // deprecated
		if authProxyEnv {
			return ptr.To(kubetypes.APIServerProxyModeAuth)
		}
		return nil
	case haveAPIProxyEnv:
		var apiProxyEnv = defaultEnv("APISERVER_PROXY", "") // true, false or "noauth"
		switch apiProxyEnv {
		case "true":
			return ptr.To(kubetypes.APIServerProxyModeAuth)
		case "false", "":
			return nil
		case "noauth":
			return ptr.To(kubetypes.APIServerProxyModeNoAuth)
		default:
			panic(fmt.Sprintf("unknown APISERVER_PROXY value %q", apiProxyEnv))
		}
	}
	return nil
}
