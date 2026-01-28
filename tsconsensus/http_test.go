// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconsensus

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// errorReader is a reader that returns an error after reading n bytes
type errorReader struct {
	n    int
	err  error
	read int
}

func (er *errorReader) Read(p []byte) (n int, err error) {
	if er.read >= er.n {
		return 0, er.err
	}
	toRead := er.n - er.read
	if toRead > len(p) {
		toRead = len(p)
	}
	er.read += toRead
	return toRead, nil
}

func TestReadAllMaxBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   io.Reader
		wantLen int
		wantErr bool
	}{
		{
			name:    "small data",
			input:   strings.NewReader("hello world"),
			wantLen: 11,
			wantErr: false,
		},
		{
			name:    "exactly at limit",
			input:   bytes.NewReader(make([]byte, maxBodyBytes)),
			wantLen: maxBodyBytes,
			wantErr: false,
		},
		{
			name:    "over limit - should truncate to maxBodyBytes+1",
			input:   bytes.NewReader(make([]byte, maxBodyBytes+100)),
			wantLen: maxBodyBytes + 1,
			wantErr: false,
		},
		{
			name:    "reader error",
			input:   &errorReader{n: 5, err: errors.New("read error")},
			wantLen: 5,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readAllMaxBytes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("readAllMaxBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("readAllMaxBytes() got %d bytes, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestCommandClient_URL(t *testing.T) {
	tests := []struct {
		name string
		port uint16
		host string
		path string
		want string
	}{
		{
			name: "basic url",
			port: 6271,
			host: "192.168.1.1",
			path: "/join",
			want: "http://192.168.1.1:6271/join",
		},
		{
			name: "with ipv6",
			port: 8080,
			host: "fd7a:115c:a1e0::1",
			path: "/executeCommand",
			want: "http://fd7a:115c:a1e0::1:8080/executeCommand",
		},
		{
			name: "empty path",
			port: 3000,
			host: "localhost",
			path: "",
			want: "http://localhost:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &commandClient{port: tt.port}
			got := cc.url(tt.host, tt.path)
			if got != tt.want {
				t.Fatalf("url() = %v, want %v", got, tt.want)
			}
		})
	}
}
