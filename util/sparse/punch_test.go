// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sparse

import (
	"crypto/rand"
	"io"
	"os"
	"testing"

	"tailscale.com/util/must"
)

func TestFile_PunchAt(t *testing.T) {
	type args struct {
		fileSize int64
		off      int64
		size     int64
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test PunchAt",
			args: args{
				fileSize: 5000,
				off:      0,
				size:     4096,
			},
			wantErr: false,
		},
		{
			name: "Test PunchAt With FileOffset",
			args: args{
				fileSize: 100000,
				off:      4096,
				size:     4096 * 2,
			},
			wantErr: false,
		},
		{
			name: "Test PunchAt With FileOffset smaller than block size",
			args: args{
				fileSize: 100000,
				off:      3,
				size:     4096 * 2,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := must.Get(os.CreateTemp(t.TempDir(), "punch_at_"))
			defer f.Close()
			must.Get(io.Copy(f, io.LimitReader(rand.Reader, tt.args.fileSize)))

			if err := PunchAt(f, tt.args.off, tt.args.size); (err != nil) != tt.wantErr {
				t.Errorf("PunchAt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	t.Run("Test PunchAt truncate file twice", func(t *testing.T) {
		f := must.Get(os.CreateTemp(t.TempDir(), "punch_at_truncate_"))
		defer f.Close()
		must.Get(io.Copy(f, io.LimitReader(rand.Reader, 100000)))
		offset := int64(4096)
		size := int64(4096 * 2)
		if err := PunchAt(f, offset, size); err != nil {
			t.Errorf("PunchAt() error = %v, wantErr %v", err, false)
		}

		// Write random bytes to hole in file.
		must.Get(f.Seek(offset, io.SeekStart))
		must.Get(io.Copy(f, io.LimitReader(rand.Reader, size)))
		// Change the hole size
		offset = 4096 * 2
		size = 4096
		if err := PunchAt(f, offset, size); err != nil {
			t.Errorf("PunchAt() error = %v, wantErr %v", err, false)
		}

	})

}
