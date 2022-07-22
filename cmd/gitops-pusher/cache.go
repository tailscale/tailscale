// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
)

// Cache contains cached information about the last time this tool was run.
//
// This is serialized to a JSON file that should NOT be checked into git.
// It should be managed with either CI cache tools or stored locally somehow. The
// exact mechanism is irrelevant as long as it is consistent.
//
// This allows gitops-pusher to detect external ACL changes. I'm not sure what to
// call this problem, so I've been calling it the "three version problem" in my
// notes. The basic problem is that at any given time we only have two versions
// of the ACL file at any given point. In order to check if there has been
// tampering of the ACL files in the admin panel, we need to have a _third_ version
// to compare against.
//
// In this case I am not storing the old ACL entirely (though that could be a
// reasonable thing to add in the future), but only its sha256sum. This allows
// us to detect if the shasum in control matches the shasum we expect, and if that
// expectation fails, then we can react accordingly.
type Cache struct {
	PrevETag string // Stores the previous ETag of the ACL to allow
}

// Save persists the cache to a given file.
func (c *Cache) Save(fname string) error {
	os.Remove(fname)
	fout, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer fout.Close()

	return json.NewEncoder(fout).Encode(c)
}

// LoadCache loads the cache from a given file.
func LoadCache(fname string) (*Cache, error) {
	var result Cache

	fin, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer fin.Close()

	err = json.NewDecoder(fin).Decode(&result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// Shuck removes the first and last character of a string, analogous to
// shucking off the husk of an ear of corn.
func Shuck(s string) string {
	return s[1 : len(s)-1]
}
