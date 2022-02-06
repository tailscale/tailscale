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
	"fmt"
	"io"
)

type file_stream struct {
	stream    io.ReadSeeker
	start_pos int64
	curr_pos  int64
	size      int64
}

func newFileStream(stream io.ReadSeeker, size int64) (*file_stream, error) {
	pos, err := stream.Seek(0, 1)
	if err != nil {
		return nil, err
	}
	return &file_stream{
		stream:    stream,
		start_pos: pos,
		curr_pos:  0,
		size:      size,
	}, nil
}

func (fs *file_stream) Read(p []byte) (n int, err error) {
	logger.Debugf("reading: %d, start_pos: %d, curr_pos: %d, size: %d",
		len(p), fs.start_pos, fs.curr_pos, fs.size)
	if fs.curr_pos >= fs.size {
		logger.Debugf("cur_pos: %d, size: %d", fs.curr_pos, fs.size)
		logger.Debug("EOF")
		return 0, io.EOF
	}

	pos, err := fs.stream.Seek(0, 1)
	if err != nil {
		return 0, err
	}
	if fs.start_pos+fs.curr_pos != pos {
		logger.Debugf("start_pos: %d, curr_pos: %d, pos: %d",
			fs.start_pos, fs.curr_pos, pos)
		return 0, fmt.Errorf("read out of order")
	}

	if int64(len(p)) > fs.size-fs.curr_pos {
		p = p[0 : fs.size-fs.curr_pos]
	}
	n, err = fs.stream.Read(p)
	fs.curr_pos += int64(n)
	//logger.Debugf("read %v", p)
	return
}
