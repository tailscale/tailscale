// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package pidowner

import (
	"math/rand"
	"os"
	"os/user"
	"testing"
)

func TestOwnerOfPID(t *testing.T) {
	id, err := OwnerOfPID(os.Getpid())
	if err == ErrNotImplemented {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("id=%q", id)

	u, err := user.LookupId(id)
	if err != nil {
		t.Fatalf("LookupId: %v", err)
	}
	t.Logf("Got: %+v", u)
}

// validate that OS implementation returns ErrProcessNotFound.
func TestNotFoundError(t *testing.T) {
	// Try a bunch of times to stumble upon a pid that doesn't exist...
	const tries = 50
	for range tries {
		_, err := OwnerOfPID(rand.Intn(1e9))
		if err == ErrNotImplemented {
			t.Skip(err)
		}
		if err == nil {
			// We got unlucky and this pid existed. Try again.
			continue
		}
		if err == ErrProcessNotFound {
			// Pass.
			return
		}
		t.Fatalf("Error is not ErrProcessNotFound: %T %v", err, err)
	}
	t.Errorf("after %d tries, couldn't find a process that didn't exist", tries)
}
