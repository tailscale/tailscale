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

func TestParseSoftwareupdateList(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name: "update-at-end-of-list",
			input: []byte(`
	 Software Update Tool

	 Finding available software
	 Software Update found the following new or updated software:
			* Label: MacBookAirEFIUpdate2.4-2.4
					 Title: MacBook Air EFI Firmware Update, Version: 2.4, Size: 3817K, Recommended: YES, Action: restart,
			* Label: ProAppsQTCodecs-1.0
					 Title: ProApps QuickTime codecs, Version: 1.0, Size: 968K, Recommended: YES,
			* Label: Tailscale-1.23.4
					 Title: The Tailscale VPN, Version: 1.23.4, Size: 1023K, Recommended: YES,
`),
			want: "Tailscale-1.23.4",
		},
		{
			name: "update-in-middle-of-list",
			input: []byte(`
	 Software Update Tool

	 Finding available software
	 Software Update found the following new or updated software:
			* Label: MacBookAirEFIUpdate2.4-2.4
					 Title: MacBook Air EFI Firmware Update, Version: 2.4, Size: 3817K, Recommended: YES, Action: restart,
			* Label: Tailscale-1.23.5000
					 Title: The Tailscale VPN, Version: 1.23.4, Size: 1023K, Recommended: YES,
			* Label: ProAppsQTCodecs-1.0
					 Title: ProApps QuickTime codecs, Version: 1.0, Size: 968K, Recommended: YES,
`),
			want: "Tailscale-1.23.5000",
		},
		{
			name: "update-not-in-list",
			input: []byte(`
	 Software Update Tool

	 Finding available software
	 Software Update found the following new or updated software:
			* Label: MacBookAirEFIUpdate2.4-2.4
					 Title: MacBook Air EFI Firmware Update, Version: 2.4, Size: 3817K, Recommended: YES, Action: restart,
			* Label: ProAppsQTCodecs-1.0
					 Title: ProApps QuickTime codecs, Version: 1.0, Size: 968K, Recommended: YES,
`),
			want: "",
		},
		{
			name: "decoy-in-list",
			input: []byte(`
	 Software Update Tool

	 Finding available software
	 Software Update found the following new or updated software:
			* Label: MacBookAirEFIUpdate2.4-2.4
					 Title: MacBook Air EFI Firmware Update, Version: 2.4, Size: 3817K, Recommended: YES, Action: restart,
			* Label: Malware-1.0
					 Title: * Label: Tailscale-0.99.0, Version: 1.0, Size: 968K, Recommended: NOT REALLY TBH,
`),
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseSoftwareupdateList(test.input)
			if test.want != got {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestParsePacmanVersion(t *testing.T) {
	tests := []struct {
		desc    string
		out     string
		want    string
		wantErr bool
	}{
		{
			desc: "valid version",
			out: `
:: Synchronizing package databases...
 endeavouros is up to date
 core is up to date
 extra is up to date
 multilib is up to date
Repository      : extra
Name            : tailscale
Version         : 1.44.2-1
Description     : A mesh VPN that makes it easy to connect your devices, wherever they are.
Architecture    : x86_64
URL             : https://tailscale.com
Licenses        : MIT
Groups          : None
Provides        : None
Depends On      : glibc
Optional Deps   : None
Conflicts With  : None
Replaces        : None
Download Size   : 7.98 MiB
Installed Size  : 32.47 MiB
Packager        : Christian Heusel <gromit@archlinux.org>
Build Date      : Tue 18 Jul 2023 12:28:37 PM PDT
Validated By    : MD5 Sum  SHA-256 Sum  Signature
`,
			want: "1.44.2",
		},
		{
			desc: "version without Arch patch number",
			out: `
... snip ...
Name            : tailscale
Version         : 1.44.2
Description     : A mesh VPN that makes it easy to connect your devices, wherever they are.
... snip ...
`,
			want: "1.44.2",
		},
		{
			desc: "missing version",
			out: `
... snip ...
Name            : tailscale
Description     : A mesh VPN that makes it easy to connect your devices, wherever they are.
... snip ...
`,
			wantErr: true,
		},
		{
			desc: "empty version",
			out: `
... snip ...
Name            : tailscale
Version         :
Description     : A mesh VPN that makes it easy to connect your devices, wherever they are.
... snip ...
`,
			wantErr: true,
		},
		{
			desc:    "empty input",
			out:     "",
			wantErr: true,
		},
		{
			desc: "sneaky version in description",
			out: `
... snip ...
Name            : tailscale
Description     : A mesh VPN that makes it easy to connect your devices, wherever they are. Version : 1.2.3
Version         : 1.44.2
... snip ...
`,
			want: "1.44.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := parsePacmanVersion([]byte(tt.out))
			if err == nil && tt.wantErr {
				t.Fatalf("got nil error and version %q, want non-nil error", got)
			}
			if err != nil && !tt.wantErr {
				t.Fatalf("got error: %q, want nil", err)
			}
			if got != tt.want {
				t.Fatalf("got version: %q, want %q", got, tt.want)
			}
		})
	}
}
