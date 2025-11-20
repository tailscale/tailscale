// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_syspolicy

package localapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"tailscale.com/util/httpm"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
)

func init() {
	Register("policy/", (*Handler).servePolicy)
}

func (h *Handler) servePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "policy access denied", http.StatusForbidden)
		return
	}

	suffix, ok := strings.CutPrefix(r.URL.EscapedPath(), "/localapi/v0/policy/")
	if !ok {
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}

	var scope setting.PolicyScope
	if suffix == "" {
		scope = setting.DefaultScope()
	} else if err := scope.UnmarshalText([]byte(suffix)); err != nil {
		http.Error(w, fmt.Sprintf("%q is not a valid scope", suffix), http.StatusBadRequest)
		return
	}

	policy, err := rsop.PolicyFor(scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var effectivePolicy *setting.Snapshot
	switch r.Method {
	case httpm.GET:
		effectivePolicy = policy.Get()
	case httpm.POST:
		effectivePolicy, err = policy.Reload()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "\t")
	e.Encode(effectivePolicy)
}
