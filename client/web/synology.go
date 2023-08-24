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

const synoTokenRedirectHTML = `<html><body>
Redirecting with session token...
<script>
var serverURL = window.location.protocol + "//" + window.location.host;
var req = new XMLHttpRequest();
req.overrideMimeType("application/json");
req.open("GET", serverURL + "/webman/login.cgi", true);
req.onload = function() {
	var jsonResponse = JSON.parse(req.responseText);
	var token = jsonResponse["SynoToken"];
	document.location.href = serverURL + "/webman/3rdparty/Tailscale/?SynoToken=" + token;
};
req.send(null);
</script>
</body></html>
`

func synoAuthn() (string, error) {
	cmd := exec.Command("/usr/syno/synoman/webman/modules/authenticate.cgi")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("auth: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// authorizeSynology checks whether the provided user has access to the web UI
// by consulting the membership of the "administrators" group.
func authorizeSynology(name string) error {
	yes, err := groupmember.IsMemberOfGroup("administrators", name)
	if err != nil {
		return err
	}
	if !yes {
		return fmt.Errorf("not a member of administrators group")
	}
	return nil
}
