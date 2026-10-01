// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"testing"

	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
)

func TestDisableHostsFileUpdatesLocal(t *testing.T) {
	for _, tt := range []struct {
		name, local            string
		policy, nilKnobs, want bool
	}{
		{"default", "", false, false, false},
		{"local", "true", false, false, true},
		{"localWithNilKnobs", "true", false, true, true},
		{"defaultWithNilKnobs", "", false, true, false},
		{"explicitFalse", "false", false, false, false},
		{"policy", "", true, false, true},
		{"localFalseCannotOverridePolicy", "false", true, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			envknob.SetenvForTest(t, "TS_DEBUG_DISABLE_HOSTS_FILE_UPDATES", tt.local)
			m := &windowsManager{}
			if !tt.nilKnobs {
				m.knobs = new(controlknobs.Knobs)
				m.knobs.DisableHostsFileUpdates.Store(tt.policy)
			}
			if got := m.disableHostsFileUpdates(); got != tt.want {
				t.Errorf("disableHostsFileUpdates() = %v, want %v", got, tt.want)
			}
		})
	}
}
