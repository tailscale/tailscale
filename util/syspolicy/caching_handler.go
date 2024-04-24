// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"
	"sync"
)

// CachingHandler is a handler that reads policies from an underlying handler the first time each key is requested
// and permanently caches the result unless there is an error. If there is an ErrNoSuchKey error, that result is cached,
// otherwise the actual error is returned and the next read for that key will retry using the handler.
type CachingHandler struct {
	mu       sync.Mutex
	strings  map[string]string
	uint64s  map[string]uint64
	bools    map[string]bool
	strArrs  map[string][]string
	notFound map[string]bool
	handler  Handler
}

// NewCachingHandler creates a CachingHandler given a handler.
func NewCachingHandler(handler Handler) *CachingHandler {
	return &CachingHandler{
		handler:  handler,
		strings:  make(map[string]string),
		uint64s:  make(map[string]uint64),
		bools:    make(map[string]bool),
		strArrs:  make(map[string][]string),
		notFound: make(map[string]bool),
	}
}

// ReadString reads the policy settings value string given the key.
// ReadString first reads from the handler's cache before resorting to using the handler.
func (ch *CachingHandler) ReadString(key string) (string, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if val, ok := ch.strings[key]; ok {
		return val, nil
	}
	if notFound := ch.notFound[key]; notFound {
		return "", ErrNoSuchKey
	}
	val, err := ch.handler.ReadString(key)
	if errors.Is(err, ErrNoSuchKey) {
		ch.notFound[key] = true
		return "", err
	} else if err != nil {
		return "", err
	}
	ch.strings[key] = val
	return val, nil
}

// ReadUInt64 reads the policy settings uint64 value given the key.
// ReadUInt64 first reads from the handler's cache before resorting to using the handler.
func (ch *CachingHandler) ReadUInt64(key string) (uint64, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if val, ok := ch.uint64s[key]; ok {
		return val, nil
	}
	if notFound := ch.notFound[key]; notFound {
		return 0, ErrNoSuchKey
	}
	val, err := ch.handler.ReadUInt64(key)
	if errors.Is(err, ErrNoSuchKey) {
		ch.notFound[key] = true
		return 0, err
	} else if err != nil {
		return 0, err
	}
	ch.uint64s[key] = val
	return val, nil
}

// ReadBoolean reads the policy settings boolean value given the key.
// ReadBoolean first reads from the handler's cache before resorting to using the handler.
func (ch *CachingHandler) ReadBoolean(key string) (bool, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if val, ok := ch.bools[key]; ok {
		return val, nil
	}
	if notFound := ch.notFound[key]; notFound {
		return false, ErrNoSuchKey
	}
	val, err := ch.handler.ReadBoolean(key)
	if errors.Is(err, ErrNoSuchKey) {
		ch.notFound[key] = true
		return false, err
	} else if err != nil {
		return false, err
	}
	ch.bools[key] = val
	return val, nil
}

// ReadBoolean reads the policy settings boolean value given the key.
// ReadBoolean first reads from the handler's cache before resorting to using the handler.
func (ch *CachingHandler) ReadStringArray(key string) ([]string, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if val, ok := ch.strArrs[key]; ok {
		return val, nil
	}
	if notFound := ch.notFound[key]; notFound {
		return nil, ErrNoSuchKey
	}
	val, err := ch.handler.ReadStringArray(key)
	if errors.Is(err, ErrNoSuchKey) {
		ch.notFound[key] = true
		return nil, err
	} else if err != nil {
		return nil, err
	}
	ch.strArrs[key] = val
	return val, nil
}
