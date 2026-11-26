// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

func TestCompleteFileCpTarget(t *testing.T) {
	targets := []apitype.FileTarget{
		{Node: &tailcfg.Node{ComputedName: "laptop", Online: ptr.To(true)}},
		{Node: &tailcfg.Node{ComputedName: "linux-box", Online: ptr.To(false)}},
		{Node: &tailcfg.Node{ComputedName: "phone"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/localapi/v0/file-targets" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(targets)
	}))
	defer srv.Close()

	oldDial := localClient.Dial
	t.Cleanup(func() { localClient.Dial = oldDial })
	localClient.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}

	tests := []struct {
		name    string
		arg     string
		want    []string
		wantDir ffcomplete.ShellCompDirective
	}{
		{"empty", "", []string{"laptop:", "linux-box:", "phone:"}, ffcomplete.ShellCompDirectiveNoSpace},
		{"prefix", "l", []string{"laptop:", "linux-box:"}, ffcomplete.ShellCompDirectiveNoSpace},
		{"exact-prefix", "lap", []string{"laptop:"}, ffcomplete.ShellCompDirectiveNoSpace},
		{"no-match-falls-back-to-files", "foo.txt", nil, ffcomplete.ShellCompDirectiveDefault},
		{"relative-path", "./l", nil, ffcomplete.ShellCompDirectiveDefault},
		{"dir-path", "dir/l", nil, ffcomplete.ShellCompDirectiveDefault},
		{"home", "~/l", nil, ffcomplete.ShellCompDirectiveDefault},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, dir, err := completeFileCpTarget(tt.arg)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("words = %q; want %q", got, tt.want)
			}
			if dir != tt.wantDir {
				t.Errorf("directive = %v; want %v", dir, tt.wantDir)
			}
		})
	}

	t.Run("first-arg-is-never-a-target", func(t *testing.T) {
		got, dir, err := completeFileCp([]string{"l"})
		if err != nil || got != nil || dir != ffcomplete.ShellCompDirectiveDefault {
			t.Errorf("got (%q, %v, %v); want (nil, Default, nil)", got, dir, err)
		}
	})
	t.Run("second-arg-completes-targets", func(t *testing.T) {
		got, _, err := completeFileCp([]string{"a.txt", "l"})
		want := []string{"laptop:", "linux-box:"}
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("got (%q, %v); want %q", got, err, want)
		}
	})
	t.Run("targets-flag-takes-no-args", func(t *testing.T) {
		cpArgs.targets = true
		defer func() { cpArgs.targets = false }()
		got, dir, err := completeFileCp([]string{"a.txt", "l"})
		if err != nil || got != nil || dir != ffcomplete.ShellCompDirectiveNoFileComp {
			t.Errorf("got (%q, %v, %v); want (nil, NoFileComp, nil)", got, dir, err)
		}
	})

	t.Run("daemon-down-falls-back-to-files", func(t *testing.T) {
		srv.Close()
		got, dir, err := completeFileCpTarget("l")
		if err != nil || got != nil || dir != ffcomplete.ShellCompDirectiveDefault {
			t.Errorf("got (%q, %v, %v); want (nil, Default, nil)", got, dir, err)
		}
	})
}

func TestCompleteFileGet(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want ffcomplete.ShellCompDirective
	}{
		{"first-arg-is-dir-only", []string{""}, ffcomplete.ShellCompDirectiveFilterDirs},
		{"partial-dir", []string{"~/Down"}, ffcomplete.ShellCompDirectiveFilterDirs},
		{"flag-name-not-suppressed", []string{"--co"}, ffcomplete.ShellCompDirectiveDefault},
		{"only-one-arg", []string{"/tmp", ""}, ffcomplete.ShellCompDirectiveNoFileComp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, dir, err := completeFileGet(tt.args)
			if err != nil || got != nil || dir != tt.want {
				t.Errorf("got (%q, %v, %v); want (nil, %v, nil)", got, dir, err, tt.want)
			}
		})
	}
}
