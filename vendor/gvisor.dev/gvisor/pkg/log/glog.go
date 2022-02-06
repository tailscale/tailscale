// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// GoogleEmitter is a wrapper that emits logs in a format compatible with
// package github.com/golang/glog.
type GoogleEmitter struct {
	*Writer
}

// pid is used for the threadid component of the header.
var pid = os.Getpid()

// Emit emits the message, google-style.
//
// Log lines have this form:
//   Lmmdd hh:mm:ss.uuuuuu threadid file:line] msg...
//
// where the fields are defined as follows:
//   L                A single character, representing the log level (eg 'I' for INFO)
//   mm               The month (zero padded; ie May is '05')
//   dd               The day (zero padded)
//   hh:mm:ss.uuuuuu  Time in hours, minutes and fractional seconds
//   threadid         The space-padded thread ID as returned by GetTID()
//   file             The file name
//   line             The line number
//   msg              The user-supplied message
//
func (g GoogleEmitter) Emit(depth int, level Level, timestamp time.Time, format string, args ...interface{}) {
	// Log level.
	prefix := byte('?')
	switch level {
	case Debug:
		prefix = byte('D')
	case Info:
		prefix = byte('I')
	case Warning:
		prefix = byte('W')
	}

	// Timestamp.
	_, month, day := timestamp.Date()
	hour, minute, second := timestamp.Clock()
	microsecond := int(timestamp.Nanosecond() / 1000)

	// 0 = this frame.
	_, file, line, ok := runtime.Caller(depth + 1)
	if ok {
		// Trim any directory path from the file.
		slash := strings.LastIndexByte(file, byte('/'))
		if slash >= 0 {
			file = file[slash+1:]
		}
	} else {
		// We don't have a filename.
		file = "???"
		line = 0
	}

	// Generate the message.
	message := fmt.Sprintf(format, args...)

	// Emit the formatted result.
	fmt.Fprintf(g.Writer, "%c%02d%02d %02d:%02d:%02d.%06d % 7d %s:%d] %s\n", prefix, int(month), day, hour, minute, second, microsecond, pid, file, line, message)
}
