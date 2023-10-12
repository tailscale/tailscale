// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

var (
	blockSize     = int64(64 << 10)
	hashAlgorithm = "sha256"
)

// FileChecksums represents checksums into partially received file.
type FileChecksums struct {
	// Offset is the offset into the file.
	Offset int64 `json:"offset"`
	// Length is the length of content being hashed in the file.
	Length int64 `json:"length"`
	// Checksums is a list of checksums of BlockSize-sized blocks
	// starting from Offset. The number of checksums is the Length
	// divided by BlockSize rounded up to the nearest integer.
	// All blocks except for the last one are guaranteed to be checksums
	// over BlockSize-sized blocks.
	Checksums []Checksum `json:"checksums"`
	// Algorithm is the hashing algorithm used to compute checksums.
	Algorithm string `json:"algorithm"` // always "sha256" for now
	// BlockSize is the size of each block.
	// The last block may be smaller than this, but never zero.
	BlockSize int64 `json:"blockSize"` // always (64<<10) for now
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
	return hexAppendEncode(b, cs.cs[:]), nil
}
func (cs Checksum) MarshalText() ([]byte, error) {
	return hexAppendEncode(nil, cs.cs[:]), nil
}
func (cs *Checksum) UnmarshalText(b []byte) error {
	if len(b) != 2*len(cs.cs) {
		return fmt.Errorf("invalid hex length: %d", len(b))
	}
	_, err := hex.Decode(cs.cs[:], b)
	return err
}

// TODO(https://go.dev/issue/53693): Use hex.AppendEncode instead.
func hexAppendEncode(dst, src []byte) []byte {
	n := hex.EncodedLen(len(src))
	dst = slices.Grow(dst, n)
	hex.Encode(dst[len(dst):][:n], src)
	return dst[:len(dst)+n]
}

// PartialFiles returns a list of partial files in [Handler.Dir]
// that were sent (or is actively being sent) by the provided id.
func (m *Manager) PartialFiles(id ClientID) (ret []string, err error) {
	if m.Dir == "" {
		return ret, ErrNoTaildrop
	}
	if m.DirectFileMode && m.AvoidFinalRename {
		return nil, nil // resuming is not supported for users that peek at our file structure
	}

	f, err := os.Open(m.Dir)
	if err != nil {
		return ret, err
	}
	defer f.Close()

	suffix := id.partialSuffix()
	for {
		des, err := f.ReadDir(10)
		if err != nil {
			return ret, err
		}
		for _, de := range des {
			if name := de.Name(); strings.HasSuffix(name, suffix) {
				ret = append(ret, name)
			}
		}
		if err == io.EOF {
			return ret, nil
		}
	}
}

// HashPartialFile hashes the contents of a partial file sent by id,
// starting at the specified offset and for the specified length.
// If length is negative, it hashes the entire file.
// If the length exceeds the remaining file length, then it hashes until EOF.
// If [FileHashes.Length] is less than length and no error occurred,
// then it implies that all remaining content in the file has been hashed.
func (m *Manager) HashPartialFile(id ClientID, baseName string, offset, length int64) (FileChecksums, error) {
	if m.Dir == "" {
		return FileChecksums{}, ErrNoTaildrop
	}
	if m.DirectFileMode && m.AvoidFinalRename {
		return FileChecksums{}, nil // resuming is not supported for users that peek at our file structure
	}

	dstFile, err := m.joinDir(baseName)
	if err != nil {
		return FileChecksums{}, err
	}
	f, err := os.Open(dstFile + id.partialSuffix())
	if err != nil {
		if os.IsNotExist(err) {
			return FileChecksums{}, nil
		}
		return FileChecksums{}, err
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return FileChecksums{}, err
	}
	checksums := FileChecksums{
		Offset:    offset,
		Algorithm: hashAlgorithm,
		BlockSize: blockSize,
	}
	b := make([]byte, blockSize) // TODO: Pool this?
	r := io.LimitReader(f, length)
	for {
		switch n, err := io.ReadFull(r, b); {
		case err != nil && err != io.EOF && err != io.ErrUnexpectedEOF:
			return checksums, err
		case n == 0:
			return checksums, nil
		default:
			checksums.Checksums = append(checksums.Checksums, hash(b[:n]))
			checksums.Length += int64(n)
		}
	}
}

// ResumeReader reads and discards the leading content of r
// that matches the content based on the checksums that exist.
// It returns the number of bytes consumed,
// and returns an [io.Reader] representing the remaining content.
func ResumeReader(r io.Reader, hashFile func(offset, length int64) (FileChecksums, error)) (int64, io.Reader, error) {
	if hashFile == nil {
		return 0, r, nil
	}

	// Ask for checksums of a particular content length,
	// where the amount of memory needed to represent the checksums themselves
	// is exactly equal to the blockSize.
	numBlocks := blockSize / sha256.Size
	hashLength := blockSize * numBlocks

	var offset int64
	b := make([]byte, 0, blockSize)
	for {
		// Request a list of checksums for the partial file starting at offset.
		checksums, err := hashFile(offset, hashLength)
		if len(checksums.Checksums) == 0 || err != nil {
			return offset, io.MultiReader(bytes.NewReader(b), r), err
		} else if checksums.BlockSize != blockSize || checksums.Algorithm != hashAlgorithm {
			return offset, io.MultiReader(bytes.NewReader(b), r), fmt.Errorf("invalid block size or hashing algorithm")
		}

		// Read from r, comparing each block with the provided checksums.
		for _, want := range checksums.Checksums {
			// Read a block from r.
			n, err := io.ReadFull(r, b[:blockSize])
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
			got := hash(b)
			if got != want {
				return offset, io.MultiReader(bytes.NewReader(b), r), nil
			}
			offset += int64(len(b))
			b = b[:0]
		}

		// We hashed the remainder of the partial file, so stop.
		if checksums.Length < hashLength {
			return offset, io.MultiReader(bytes.NewReader(b), r), nil
		}
	}
}
