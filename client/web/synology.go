// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// synology.go contains handlers and logic, such as authentication,
// that is specific to running the web client on Synology.

package web

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"tailscale.com/util/groupmember"
)

// authorizeSynology authenticates the logged-in Synology user and verifies
// that they are authorized to use the web client.
// If the user is authenticated, but not authorized to use the client, an error is returned.
func authorizeSynology(r *http.Request) (authorized bool, err error) {
	if !hasSynoToken(r) {
		return false, nil
	}

	// authenticate the Synology user
	cmd := exec.Command("/usr/syno/synoman/webman/modules/authenticate.cgi")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("auth: %v: %s", err, out)
	}
	user := strings.TrimSpace(string(out))

	// check if the user is in the administrators group
	isAdmin, err := groupmember.IsMemberOfGroup("administrators", user)
	if err != nil {
		return false, err
	}
	if !isAdmin {
		return false, errors.New("not a member of administrators group")
	}

	return true, nil
}

// hasSynoToken returns true if the request include a SynoToken used for synology auth.
func hasSynoToken(r *http.Request) bool {
	if r.Header.Get("X-Syno-Token") != "" {
		return true
	}
	if r.URL.Query().Get("SynoToken") != "" {
		return true
	}
	if r.Method == "POST" && r.FormValue("SynoToken") != "" {
		return true
	}
	return false
}
