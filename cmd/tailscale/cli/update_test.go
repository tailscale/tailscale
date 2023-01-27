// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import "testing"

func TestUpdateDebianAptSourcesListBytes(t *testing.T) {
	tests := []struct {
		name    string
		toTrack string
		in      string
		want    string // empty means want no change
		wantErr string
	}{
		{
			name:    "stable-to-unstable",
			toTrack: "unstable",
			in:      "# Tailscale packages for debian buster\ndeb https://pkgs.tailscale.com/stable/debian bullseye main\n",
			want:    "# Tailscale packages for debian buster\ndeb https://pkgs.tailscale.com/unstable/debian bullseye main\n",
		},
		{
			name:    "stable-unchanged",
			toTrack: "stable",
			in:      "# Tailscale packages for debian buster\ndeb https://pkgs.tailscale.com/stable/debian bullseye main\n",
		},
		{
			name:    "if-both-stable-and-unstable-dont-change",
			toTrack: "stable",
			in: "# Tailscale packages for debian buster\n" +
				"deb https://pkgs.tailscale.com/stable/debian bullseye main\n" +
				"deb https://pkgs.tailscale.com/unstable/debian bullseye main\n",
		},
		{
			name:    "if-both-stable-and-unstable-dont-change-unstable",
			toTrack: "unstable",
			in: "# Tailscale packages for debian buster\n" +
				"deb https://pkgs.tailscale.com/stable/debian bullseye main\n" +
				"deb https://pkgs.tailscale.com/unstable/debian bullseye main\n",
		},
		{
			name:    "signed-by-form",
			toTrack: "unstable",
			in:      "# Tailscale packages for ubuntu jammy\ndeb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu jammy main\n",
			want:    "# Tailscale packages for ubuntu jammy\ndeb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/unstable/ubuntu jammy main\n",
		},
		{
			name:    "unsupported-lines",
			toTrack: "unstable",
			in:      "# Tailscale packages for ubuntu jammy\ndeb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/foobar/ubuntu jammy main\n",
			wantErr: "unexpected/unsupported /etc/apt/sources.list.d/tailscale.list contents",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newContent, err := updateDebianAptSourcesListBytes([]byte(tt.in), tt.toTrack)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Fatalf("error = %v; want %q", err, tt.wantErr)
				}
				return
			}
			if tt.wantErr != "" {
				t.Fatalf("got no error; want %q", tt.wantErr)
			}
			var gotChange string
			if string(newContent) != tt.in {
				gotChange = string(newContent)
			}
			if gotChange != tt.want {
				t.Errorf("wrong result\n got: %q\nwant: %q", gotChange, tt.want)
			}
		})
	}
}
