// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"reflect"
	"testing"
	"time"
)

func TestServicePrefsClone(t *testing.T) {
	now := time.Now()
	src := ServicePrefs{
		"svc:db:5432": {Client: "psql", DatabaseName: "prod", LastUsed: now},
		"svc:ssh:22":  {Client: "terminal", Username: "rollie", LastUsed: now},
	}
	dst := src.Clone()
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("Clone result not equal to source")
	}
	// Mutating dst must not affect src.
	dst["svc:db:5432"] = ServicePref{Client: "pgcli"}
	if src["svc:db:5432"].Client != "psql" {
		t.Errorf("mutating clone leaked into source: %v", src["svc:db:5432"])
	}
	// Nil clone returns nil.
	if got := ServicePrefs(nil).Clone(); got != nil {
		t.Errorf("(nil).Clone() = %v, want nil", got)
	}
}
