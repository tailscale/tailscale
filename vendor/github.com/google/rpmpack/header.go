// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rpmpack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/pkg/errors"
)

const (
	signatures = 0x3e
	immutable  = 0x3f

	typeInt16       = 0x03
	typeInt32       = 0x04
	typeString      = 0x06
	typeBinary      = 0x07
	typeStringArray = 0x08
)

// Only integer types are aligned. This is not just an optimization - some versions
// of rpm fail when integers are not aligned. Other versions fail when non-integers are aligned.
var boundaries = map[int]int{
	typeInt16: 2,
	typeInt32: 4,
}

type IndexEntry struct {
	rpmtype, count int
	data           []byte
}

func (e IndexEntry) indexBytes(tag, contentOffset int) []byte {
	b := &bytes.Buffer{}
	if err := binary.Write(b, binary.BigEndian, []int32{int32(tag), int32(e.rpmtype), int32(contentOffset), int32(e.count)}); err != nil {
		// binary.Write can fail if the underlying Write fails, or the types are invalid.
		// bytes.Buffer's write never error out, it can only panic with OOM.
		panic(err)
	}
	return b.Bytes()
}

func intEntry(rpmtype, size int, value interface{}) IndexEntry {
	b := &bytes.Buffer{}
	if err := binary.Write(b, binary.BigEndian, value); err != nil {
		// binary.Write can fail if the underlying Write fails, or the types are invalid.
		// bytes.Buffer's write never error out, it can only panic with OOM.
		panic(err)
	}
	return IndexEntry{rpmtype, size, b.Bytes()}
}

func EntryInt16(value []int16) IndexEntry {
	return intEntry(typeInt16, len(value), value)
}
func EntryUint16(value []uint16) IndexEntry {
	return intEntry(typeInt16, len(value), value)
}
func EntryInt32(value []int32) IndexEntry {
	return intEntry(typeInt32, len(value), value)
}
func EntryUint32(value []uint32) IndexEntry {
	return intEntry(typeInt32, len(value), value)
}
func EntryString(value string) IndexEntry {
	return IndexEntry{typeString, 1, append([]byte(value), byte(00))}
}
func EntryBytes(value []byte) IndexEntry {
	return IndexEntry{typeBinary, len(value), value}
}

func EntryStringSlice(value []string) IndexEntry {
	b := [][]byte{}
	for _, v := range value {
		b = append(b, []byte(v))
	}
	bb := append(bytes.Join(b, []byte{00}), byte(00))
	return IndexEntry{typeStringArray, len(value), bb}
}

type index struct {
	entries map[int]IndexEntry
	h       int
}

func newIndex(h int) *index {
	return &index{entries: make(map[int]IndexEntry), h: h}
}
func (i *index) Add(tag int, e IndexEntry) {
	i.entries[tag] = e
}
func (i *index) AddEntries(m map[int]IndexEntry) {
	for t, e := range m {
		i.Add(t, e)
	}
}

func (i *index) sortedTags() []int {
	t := []int{}
	for k := range i.entries {
		t = append(t, k)
	}
	sort.Ints(t)
	return t
}

func pad(w *bytes.Buffer, rpmtype, offset int) {
	// We need to align integer entries...
	if b, ok := boundaries[rpmtype]; ok && offset%b != 0 {
		if _, err := w.Write(make([]byte, b-offset%b)); err != nil {
			// binary.Write can fail if the underlying Write fails, or the types are invalid.
			// bytes.Buffer's write never error out, it can only panic with OOM.
			panic(err)
		}
	}
}

// Bytes returns the bytes of the index.
func (i *index) Bytes() ([]byte, error) {
	w := &bytes.Buffer{}
	// Even the header has three parts: The lead, the index entries, and the entries.
	// Because of alignment, we can only tell the actual size and offset after writing
	// the entries.
	entryData := &bytes.Buffer{}
	tags := i.sortedTags()
	offsets := make([]int, len(tags))
	for ii, tag := range tags {
		e := i.entries[tag]
		pad(entryData, e.rpmtype, entryData.Len())
		offsets[ii] = entryData.Len()
		entryData.Write(e.data)
	}
	entryData.Write(i.eigenHeader().data)

	// 4 magic and 4 reserved
	w.Write([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0})
	// 4 count and 4 size
	// We add the pseudo-entry "eigenHeader" to count.
	if err := binary.Write(w, binary.BigEndian, []int32{int32(len(i.entries)) + 1, int32(entryData.Len())}); err != nil {
		return nil, errors.Wrap(err, "failed to write eigenHeader")
	}
	// Write the eigenHeader index entry
	w.Write(i.eigenHeader().indexBytes(i.h, entryData.Len()-0x10))
	// Write all of the other index entries
	for ii, tag := range tags {
		e := i.entries[tag]
		w.Write(e.indexBytes(tag, offsets[ii]))
	}
	w.Write(entryData.Bytes())
	return w.Bytes(), nil
}

// the eigenHeader is a weird entry. Its index entry is sorted first, but its content
// is last. The content is a 16 byte index entry, which is almost the same as the index
// entry except for the offset. The offset here is ... minus the length of the index entry region.
// Which is always 0x10 * number of entries.
// I kid you not.
func (i *index) eigenHeader() IndexEntry {
	b := &bytes.Buffer{}
	if err := binary.Write(b, binary.BigEndian, []int32{int32(i.h), int32(typeBinary), -int32(0x10 * (len(i.entries) + 1)), int32(0x10)}); err != nil {
		// binary.Write can fail if the underlying Write fails, or the types are invalid.
		// bytes.Buffer's write never error out, it can only panic with OOM.
		panic(err)
	}

	return EntryBytes(b.Bytes())
}

func lead(name, fullVersion string) []byte {
	// RPM format = 0xedabeedb
	// version 3.0 = 0x0300
	// type binary = 0x0000
	// machine archnum (i386?) = 0x0001
	// name ( 66 bytes, with null termination)
	// osnum (linux?) = 0x0001
	// sig type (header-style) = 0x0005
	// reserved 16 bytes of 0x00
	n := []byte(fmt.Sprintf("%s-%s", name, fullVersion))
	if len(n) > 65 {
		n = n[:65]
	}
	n = append(n, make([]byte, 66-len(n))...)
	b := []byte{0xed, 0xab, 0xee, 0xdb, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01}
	b = append(b, n...)
	b = append(b, []byte{0x00, 0x01, 0x00, 0x05}...)
	b = append(b, make([]byte, 16)...)
	return b
}
