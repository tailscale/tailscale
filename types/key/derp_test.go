// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"errors"
	"testing"

	"go4.org/mem"
)

func TestDERPMeshIsValid(t *testing.T) {
	for name, tt := range map[string]struct {
		input   string
		want    string
		wantErr error
	}{
		"good": {
			input:   "0123456789012345678901234567890123456789012345678901234567890123",
			want:    "0123456789012345678901234567890123456789012345678901234567890123",
			wantErr: nil,
		},
		"hex": {
			input:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: nil,
		},
		"uppercase": {
			input:   "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: nil,
		},
		"whitespace": {
			input:   "  0123456789012345678901234567890123456789012345678901234567890123  ",
			want:    "0123456789012345678901234567890123456789012345678901234567890123",
			wantErr: nil,
		},
		"short": {
			input:   "0123456789abcdef",
			wantErr: ErrInvalidMeshKey,
		},
		"long": {
			input:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
			wantErr: ErrInvalidMeshKey,
		},
	} {
		t.Run(name, func(t *testing.T) {
			k, err := ParseDERPMesh(tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err %v, want %v", err, tt.wantErr)
			}

			got := k.String()
			if got != tt.want && tt.wantErr == nil {
				t.Errorf("got %q, want %q", got, tt.want)
			}

		})
	}

}

func TestDERPMesh(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		str   string
		hex   []byte
		equal bool // are str and hex equal?
	}{
		"zero": {
			str: "0000000000000000000000000000000000000000000000000000000000000000",
			hex: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			equal: true,
		},
		"equal": {
			str: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			hex: []byte{
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			},
			equal: true,
		},
		"unequal": {
			str: "0badc0de00000000000000000000000000000000000000000000000000000000",
			hex: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			equal: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			k, err := ParseDERPMesh(tt.str)
			if err != nil {
				t.Fatal(err)
			}

			// string representation should round-trip
			s := k.String()
			if s != tt.str {
				t.Fatalf("string %s, want %s", s, tt.str)
			}

			// if tt.equal, then tt.hex is intended to be equal
			if k.k != [32]byte(tt.hex) && tt.equal {
				t.Fatalf("decoded %x, want %x", k.k, tt.hex)
			}

			h := DERPMeshFromRaw32(mem.B(tt.hex))
			if k.Equal(h) != tt.equal {
				if tt.equal {
					t.Fatalf("%v != %v", k, h)
				} else {
					t.Fatalf("%v == %v", k, h)
				}
			}

		})
	}
}
