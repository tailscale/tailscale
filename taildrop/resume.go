// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

var (
	blockSize     = int64(64 << 10)
	hashAlgorithm = "sha256"
)

// BlockChecksum represents the checksum for a single block.
type BlockChecksum struct {
	Checksum  Checksum `json:"checksum"`
	Algorithm string   `json:"algo"` // always "sha256" for now
	Size      int64    `json:"size"` // always (64<<10) for now
}

// Checksum is an opaque checksum that is comparable.
type Checksum struct{ cs [sha256.Size]byte }

func hash(b []byte) Checksum {
	return Checksum{sha256.Sum256(b)}
}
func (cs Checksum) String() string {
	return hex.EncodeToString(cs.cs[:])
}
func (cs Checksum) AppendText(b []byte) ([]byte, error) {
	return hex.AppendEncode(b, cs.cs[:]), nil
}
func (cs Checksum) MarshalText() ([]byte, error) {
	return hex.AppendEncode(nil, cs.cs[:]), nil
}
func (cs *Checksum) UnmarshalText(b []byte) error {
	if len(b) != 2*len(cs.cs) {
		return fmt.Errorf("invalid hex length: %d", len(b))
	}
	_, err := hex.Decode(cs.cs[:], b)
	return err
}

// PartialFiles returns a list of partial files in [Handler.Dir]
// that were sent (or is actively being sent) by the provided id.
func (m *Manager) PartialFiles(id ClientID) (ret []string, err error) {
	if m == nil || m.opts.Dir == "" {
		return nil, ErrNoTaildrop
	}

	suffix := id.partialSuffix()
	if err := rangeDir(m.opts.Dir, func(de fs.DirEntry) bool {
		if name := de.Name(); strings.HasSuffix(name, suffix) {
			ret = append(ret, name)
		}
		return true
	}); err != nil {
		return ret, redactError(err)
	}
	return ret, nil
}

// HashPartialFile returns a function that hashes the next block in the file,
// starting from the beginning of the file.
// It returns (BlockChecksum{}, io.EOF) when the stream is complete.
// It is the caller's responsibility to call close.
func (m *Manager) HashPartialFile(id ClientID, baseName string) (next func() (BlockChecksum, error), close func() error, err error) {
	if m == nil || m.opts.Dir == "" {
		return nil, nil, ErrNoTaildrop
	}
	noopNext := func() (BlockChecksum, error) { return BlockChecksum{}, io.EOF }
	noopClose := func() error { return nil }

	dstFile, err := joinDir(m.opts.Dir, baseName)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(dstFile + id.partialSuffix())
	if err != nil {
		if os.IsNotExist(err) {
			return noopNext, noopClose, nil
		}
		return nil, nil, redactError(err)
	}

	b := make([]byte, blockSize) // TODO: Pool this?
	next = func() (BlockChecksum, error) {
		switch n, err := io.ReadFull(f, b); {
		case err != nil && err != io.EOF && err != io.ErrUnexpectedEOF:
			return BlockChecksum{}, redactError(err)
		case n == 0:
			return BlockChecksum{}, io.EOF
		default:
			return BlockChecksum{hash(b[:n]), hashAlgorithm, int64(n)}, nil
		}
	}
	close = f.Close
	return next, close, nil
}

// ResumeReader reads and discards the leading content of r
// that matches the content based on the checksums that exist.
// It returns the number of bytes consumed,
// and returns an [io.Reader] representing the remaining content.
func ResumeReader(r io.Reader, hashNext func() (BlockChecksum, error)) (int64, io.Reader, error) {
	if hashNext == nil {
		return 0, r, nil
	}

	var offset int64
	b := make([]byte, 0, blockSize)
	for {
		// Obtain the next block checksum from the remote peer.
		cs, err := hashNext()
		switch {
		case err == io.EOF:
			return offset, io.MultiReader(bytes.NewReader(b), r), nil
		case err != nil:
			return offset, io.MultiReader(bytes.NewReader(b), r), err
		case cs.Algorithm != hashAlgorithm || cs.Size < 0 || cs.Size > blockSize:
			return offset, io.MultiReader(bytes.NewReader(b), r), fmt.Errorf("invalid block size or hashing algorithm")
		}

		// Read the contents of the next block.
		n, err := io.ReadFull(r, b[:cs.Size])
		b = b[:n]
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = nil
		}
		if len(b) == 0 || err != nil {
			// This should not occur in practice.
			// It implies that an error occurred reading r,
			// or that the partial file on the remote side is fully complete.
			return offset, io.MultiReader(bytes.NewReader(b), r), err
		}

		// Compare the local and remote block checksums.
		// If it mismatches, then resume from this point.
		if cs.Checksum != hash(b) {
			return offset, io.MultiReader(bytes.NewReader(b), r), nil
		}
		offset += int64(len(b))
		b = b[:0]
	}
}
