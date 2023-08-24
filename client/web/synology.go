// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// synology.go contains handlers and logic, such as authentication,
// that is specific to running the web client on Synology.

package web

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"tailscale.com/util/groupmember"
)

const synologyPrefix = "/webman/3rdparty/Tailscale/index.cgi/"

// authorizeSynology authenticates the logged-in Synology user and verifies
// that they are authorized to use the web client.  It returns true if the
// request was handled and no further processing is required.
func authorizeSynology(w http.ResponseWriter, r *http.Request) (handled bool) {
	if synoTokenRedirect(w, r) {
		return true
	}

	// authenticate the Synology user
	cmd := exec.Command("/usr/syno/synoman/webman/modules/authenticate.cgi")
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("auth: %v: %s", err, out), http.StatusUnauthorized)
		return true
	}
	user := strings.TrimSpace(string(out))

	// check if the user is in the administrators group
	isAdmin, err := groupmember.IsMemberOfGroup("administrators", user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return true
	}
	if !isAdmin {
		http.Error(w, "not a member of administrators group", http.StatusForbidden)
		return true
	}

	return false
}

func synoTokenRedirect(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Syno-Token") != "" {
		return false
	}
	if r.URL.Query().Get("SynoToken") != "" {
		return false
	}
	if r.Method == "POST" && r.FormValue("SynoToken") != "" {
		return false
	}
	// We need a SynoToken for authenticate.cgi.
	// So we tell the client to get one.
	_, _ = fmt.Fprint(w, synoTokenRedirectHTML)
	return true
}

const synoTokenRedirectHTML = `<html>
Redirecting with session token...
<script>
  fetch("/webman/login.cgi")
    .then(r => r.json())
    .then(data => {
	u = new URL(window.location)
	u.searchParams.set("SynoToken", data.SynoToken)
	document.location = u
    })
</script>
`
