// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

package ipnlocal

import "sync"

// In tests we can't import feature/acme (it would import this package
// and form a cycle), so the real cert extension is never registered.
// Install a default [hookCertState] provider here that lazily creates
// a [CertState] per [LocalBackend].
//
// Tests that want different behavior can use
// [feature.Hook.SetForTest] to override this hook for the duration
// of the test.
func init() {
	if hookCertState.IsSet() {
		return
	}
	var (
		mu     sync.Mutex
		states = map[*LocalBackend]*CertState{}
	)
	hookCertState.Set(func(b *LocalBackend) *CertState {
		mu.Lock()
		defer mu.Unlock()
		if s, ok := states[b]; ok {
			return s
		}
		s := new(CertState)
		states[b] = s
		return s
	})
}
