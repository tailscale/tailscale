/*
 * Copyright (c) SAS Institute, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cpio

import (
	"errors"
	"fmt"
	"io"
)

const TRAILER = "TRAILER!!!"

var ErrStrippedHeader = errors.New("invalid cpio header: rpm-style stripped cpio requires supplemental size info")

type CpioEntry struct {
	Header  *Cpio_newc_header
	payload *file_stream
}

type CpioStream struct {
	stream   *countingReader
	next_pos int64
	sizes    []int64
}

type countingReader struct {
	stream   io.Reader
	curr_pos int64
}

func NewCpioStream(stream io.Reader) *CpioStream {
	return &CpioStream{
		stream: &countingReader{
			stream:   stream,
			curr_pos: 0,
		},
		next_pos: 0,
	}
}

// Provide supplemental file size info so that RPMs with files > 4GiB can be read
func (cs *CpioStream) SetFileSizes(sizes []int64) {
	cs.sizes = sizes
}

func (cs *CpioStream) ReadNextEntry() (*CpioEntry, error) {
	if cs.next_pos != cs.stream.curr_pos {
		logger.Debugf("seeking %d, curr_pos: %d, next_pos: %d", cs.next_pos-cs.stream.curr_pos, cs.stream.curr_pos, cs.next_pos)
		_, err := cs.stream.Seek(cs.next_pos-cs.stream.curr_pos, 1)
		if err != nil {
			return nil, err
		}
	}

	// Read header
	hdr, err := readHeader(cs.stream)
	if err != nil {
		return nil, err
	} else if hdr.stripped {
		return cs.readStrippedEntry(hdr)
	}

	// Read filename
	buf := make([]byte, hdr.c_namesize)
	if _, err = io.ReadFull(cs.stream, buf); err != nil {
		return nil, err
	}

	filename := string(buf[:len(buf)-1])
	logger.Debugf("filename: %s", filename)

	offset := pad(cpio_newc_header_length+int(hdr.c_namesize)) - cpio_newc_header_length - int(hdr.c_namesize)

	if offset > 0 {
		_, err := cs.stream.Seek(int64(offset), 1)
		if err != nil {
			return nil, err
		}
	}

	// Find the next entry
	cs.next_pos = pad64(cs.stream.curr_pos + int64(hdr.c_filesize))

	// Find the payload
	payload, err := newFileStream(cs.stream, int64(hdr.c_filesize))
	if err != nil {
		return nil, err
	}

	// Create then entry
	hdr.filename = filename
	entry := CpioEntry{
		Header:  hdr,
		payload: payload,
	}

	return &entry, nil
}

func (cs *CpioStream) readStrippedEntry(hdr *Cpio_newc_header) (*CpioEntry, error) {
	// magic has already been read
	if cs.sizes == nil {
		return nil, ErrStrippedHeader
	} else if hdr.index >= len(cs.sizes) {
		return nil, fmt.Errorf("stripped cpio refers to invalid file index %d", hdr.index)
	}
	size := cs.sizes[hdr.index]
	cs.next_pos = pad64(cs.stream.curr_pos + size)
	payload, err := newFileStream(cs.stream, size)
	if err != nil {
		return nil, err
	}
	return &CpioEntry{Header: hdr, payload: payload}, nil
}

func (cr *countingReader) Read(p []byte) (n int, err error) {
	n, err = cr.stream.Read(p)
	cr.curr_pos += int64(n)
	return
}

func (cr *countingReader) Seek(offset int64, whence int) (int64, error) {
	if whence != 1 {
		return 0, fmt.Errorf("only seeking from current location supported")
	}
	if offset == 0 {
		return cr.curr_pos, nil
	}
	logger.Debugf("offset: %d, curr_pos: %d", offset, cr.curr_pos)
	b := make([]byte, offset)
	n, err := io.ReadFull(cr, b)
	if err != nil && err != io.EOF {
		return 0, err
	}
	return int64(n), nil
}

func pad(num int) int {
	return num + 3 - (num+3)%4
}

func pad64(num int64) int64 {
	return num + 3 - (num+3)%4
}
