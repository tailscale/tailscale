// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"testing"
)

func TestHandlerReadString(t *testing.T) {
	tests := []struct {
		name            string
		key             string
		handlerKey      Key
		handlerValue    string
		handlerError    error
		preserveHandler bool
		wantValue       string
		wantErr         error
		strings         map[string]string
		expectedCalls   int
	}{
		{
			name:          "read existing cached values",
			key:           "test",
			handlerKey:    "do not read",
			strings:       map[string]string{"test": "foo"},
			wantValue:     "foo",
			expectedCalls: 0,
		},
		{
			name:          "read existing values not cached",
			key:           "test",
			handlerKey:    "test",
			handlerValue:  "foo",
			wantValue:     "foo",
			expectedCalls: 1,
		},
		{
			name:          "error no such key",
			key:           "test",
			handlerKey:    "test",
			handlerError:  ErrNoSuchKey,
			wantErr:       ErrNoSuchKey,
			expectedCalls: 1,
		},
		{
			name:            "other error",
			key:             "test",
			handlerKey:      "test",
			handlerError:    someOtherError,
			wantErr:         someOtherError,
			preserveHandler: true,
			expectedCalls:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := &testHandler{
				t:   t,
				key: tt.handlerKey,
				s:   tt.handlerValue,
				err: tt.handlerError,
			}
			cache := NewCachingHandler(testHandler)
			if tt.strings != nil {
				cache.strings = tt.strings
			}
			got, err := cache.ReadString(tt.key)
			if err != tt.wantErr {
				t.Errorf("err=%v want %v", err, tt.wantErr)
			}
			if got != tt.wantValue {
				t.Errorf("got %v want %v", got, cache.strings[tt.key])
			}
			if !tt.preserveHandler {
				testHandler.key, testHandler.s, testHandler.err = "do not read", "", nil
			}
			got, err = cache.ReadString(tt.key)
			if err != tt.wantErr {
				t.Errorf("repeat err=%v want %v", err, tt.wantErr)
			}
			if got != tt.wantValue {
				t.Errorf("repeat got %v want %v", got, cache.strings[tt.key])
			}
			if testHandler.calls != tt.expectedCalls {
				t.Errorf("calls=%v want %v", testHandler.calls, tt.expectedCalls)
			}
		})
	}
}

func TestHandlerReadUint64(t *testing.T) {
	tests := []struct {
		name            string
		key             string
		handlerKey      Key
		handlerValue    uint64
		handlerError    error
		preserveHandler bool
		wantValue       uint64
		wantErr         error
		uint64s         map[string]uint64
		expectedCalls   int
	}{
		{
			name:          "read existing cached values",
			key:           "test",
			handlerKey:    "do not read",
			uint64s:       map[string]uint64{"test": 1},
			wantValue:     1,
			expectedCalls: 0,
		},
		{
			name:          "read existing values not cached",
			key:           "test",
			handlerKey:    "test",
			handlerValue:  1,
			wantValue:     1,
			expectedCalls: 1,
		},
		{
			name:          "error no such key",
			key:           "test",
			handlerKey:    "test",
			handlerError:  ErrNoSuchKey,
			wantErr:       ErrNoSuchKey,
			expectedCalls: 1,
		},
		{
			name:            "other error",
			key:             "test",
			handlerKey:      "test",
			handlerError:    someOtherError,
			wantErr:         someOtherError,
			preserveHandler: true,
			expectedCalls:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := &testHandler{
				t:   t,
				key: tt.handlerKey,
				u64: tt.handlerValue,
				err: tt.handlerError,
			}
			cache := NewCachingHandler(testHandler)
			if tt.uint64s != nil {
				cache.uint64s = tt.uint64s
			}
			got, err := cache.ReadUInt64(tt.key)
			if err != tt.wantErr {
				t.Errorf("err=%v want %v", err, tt.wantErr)
			}
			if got != tt.wantValue {
				t.Errorf("got %v want %v", got, cache.strings[tt.key])
			}
			if !tt.preserveHandler {
				testHandler.key, testHandler.s, testHandler.err = "do not read", "", nil
			}
			got, err = cache.ReadUInt64(tt.key)
			if err != tt.wantErr {
				t.Errorf("repeat err=%v want %v", err, tt.wantErr)
			}
			if got != tt.wantValue {
				t.Errorf("repeat got %v want %v", got, cache.strings[tt.key])
			}
			if testHandler.calls != tt.expectedCalls {
				t.Errorf("calls=%v want %v", testHandler.calls, tt.expectedCalls)
			}
		})
	}

}

func TestHandlerReadBool(t *testing.T) {
	tests := []struct {
		name            string
		key             string
		handlerKey      Key
		handlerValue    bool
		handlerError    error
		preserveHandler bool
		wantValue       bool
		wantErr         error
		bools           map[string]bool
		expectedCalls   int
	}{
		{
			name:          "read existing cached values",
			key:           "test",
			handlerKey:    "do not read",
			bools:         map[string]bool{"test": true},
			wantValue:     true,
			expectedCalls: 0,
		},
		{
			name:          "read existing values not cached",
			key:           "test",
			handlerKey:    "test",
			handlerValue:  true,
			wantValue:     true,
			expectedCalls: 1,
		},
		{
			name:          "error no such key",
			key:           "test",
			handlerKey:    "test",
			handlerError:  ErrNoSuchKey,
			wantErr:       ErrNoSuchKey,
			expectedCalls: 1,
		},
		{
			name:            "other error",
			key:             "test",
			handlerKey:      "test",
			handlerError:    someOtherError,
			wantErr:         someOtherError,
			preserveHandler: true,
			expectedCalls:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := &testHandler{
				t:   t,
				key: tt.handlerKey,
				b:   tt.handlerValue,
				err: tt.handlerError,
			}
			cache := NewCachingHandler(testHandler)
			if tt.bools != nil {
				cache.bools = tt.bools
			}
			got, err := cache.ReadBoolean(tt.key)
			if err != tt.wantErr {
				t.Errorf("err=%v want %v", err, tt.wantErr)
			}
			if got != tt.wantValue {
				t.Errorf("got %v want %v", got, cache.strings[tt.key])
			}
			if !tt.preserveHandler {
				testHandler.key, testHandler.s, testHandler.err = "do not read", "", nil
			}
			got, err = cache.ReadBoolean(tt.key)
			if err != tt.wantErr {
				t.Errorf("repeat err=%v want %v", err, tt.wantErr)
			}
			if got != tt.wantValue {
				t.Errorf("repeat got %v want %v", got, cache.strings[tt.key])
			}
			if testHandler.calls != tt.expectedCalls {
				t.Errorf("calls=%v want %v", testHandler.calls, tt.expectedCalls)
			}
		})
	}

}
