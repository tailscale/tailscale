// +build gofuzz

package cpio

import "bytes"
import "io"

// Fuzz tests the parsing and error handling of random byte arrays using
// https://github.com/dvyukov/go-fuzz.
func Fuzz(data []byte) int {
	r := NewReader(bytes.NewReader(data))
	h := NewHash()
	for {
		hdr, err := r.Next()
		if err != nil {
			if hdr != nil {
				panic("hdr != nil on error")
			}
			if err == io.EOF {
				// everything worked with random input... interesting
				return 1
			}
			// error returned for random input. Good!
			return -1
		}

		// hash file
		h.Reset()
		io.CopyN(h, r, hdr.Size)
		h.Sum32()

		// convert file header
		FileInfoHeader(hdr.FileInfo())
	}
}
