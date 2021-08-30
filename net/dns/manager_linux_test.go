// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"testing"
)

func TestLinuxNewOSConfigurator(t *testing.T) {
	tests := []struct {
		name    string
		env     newOSConfigEnv
		wantLog string
		want    string // reflect type string
	}{
		{
			name: "no_obvious_resolv.conf_owner",
			env: newOSConfigEnv{
				fs: memFS{
					"/etc/resolv.conf": "nameserver 10.0.0.1\n",
				},
				resolvOwner: resolvOwner,
			},
			wantLog: "dns: [rc=unknown ret=dns.directManager]\n",
			want:    "dns.directManager",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			logf := func(format string, a ...interface{}) {
				fmt.Fprintf(&logBuf, format, a...)
				logBuf.WriteByte('\n')
			}
			osc, err := newOSConfigurator(logf, "unused_if_name0", tt.env)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%T", osc); got != tt.want {
				t.Errorf("got %s; want %s", got, tt.want)
			}
			if tt.wantLog != string(logBuf.Bytes()) {
				t.Errorf("log output mismatch:\n got: %q\nwant: %q\n", logBuf.Bytes(), tt.wantLog)
			}
		})
	}
}

type memFS map[string]interface{} // full path => string for regular files

func (m memFS) Stat(name string) (isRegular bool, err error) {
	v, ok := m[name]
	if !ok {
		return false, fs.ErrNotExist
	}
	if _, ok := v.(string); ok {
		return true, nil
	}
	return false, nil
}

func (m memFS) Rename(oldName, newName string) error { panic("TODO") }
func (m memFS) Remove(name string) error             { panic("TODO") }
func (m memFS) ReadFile(name string) ([]byte, error) {
	v, ok := m[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if s, ok := v.(string); ok {
		return []byte(s), nil
	}
	panic("TODO")
}

func (fs memFS) WriteFile(name string, contents []byte, perm os.FileMode) error {
	fs[name] = string(contents)
	return nil
}
