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
	"encoding/json"
	"fmt"
	"time"
)

type jsonLog struct {
	Msg   string    `json:"msg"`
	Level Level     `json:"level"`
	Time  time.Time `json:"time"`
}

// MarshalJSON implements json.Marshaler.MarashalJSON.
func (l Level) MarshalJSON() ([]byte, error) {
	switch l {
	case Warning:
		return []byte(`"warning"`), nil
	case Info:
		return []byte(`"info"`), nil
	case Debug:
		return []byte(`"debug"`), nil
	default:
		return nil, fmt.Errorf("unknown level %v", l)
	}
}

// UnmarshalJSON implements json.Unmarshaler.UnmarshalJSON.  It can unmarshal
// from both string names and integers.
func (l *Level) UnmarshalJSON(b []byte) error {
	switch s := string(b); s {
	case "0", `"warning"`:
		*l = Warning
	case "1", `"info"`:
		*l = Info
	case "2", `"debug"`:
		*l = Debug
	default:
		return fmt.Errorf("unknown level %q", s)
	}
	return nil
}

// JSONEmitter logs messages in json format.
type JSONEmitter struct {
	*Writer
}

// Emit implements Emitter.Emit.
func (e JSONEmitter) Emit(_ int, level Level, timestamp time.Time, format string, v ...interface{}) {
	j := jsonLog{
		Msg:   fmt.Sprintf(format, v...),
		Level: level,
		Time:  timestamp,
	}
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	e.Writer.Write(b)
}
