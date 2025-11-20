// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"sync/atomic"

	"tailscale.com/types/key"
)

type discoKeyPair struct {
	private key.DiscoPrivate
	public  key.DiscoPublic
	short   string // public.ShortString()
}

// discoAtomic is an atomic container for a disco private key, public key, and
// the public key's ShortString. The private and public keys are always kept
// synchronized.
//
// The zero value is not ready for use. Use [Set] to provide a usable value.
type discoAtomic struct {
	pair atomic.Pointer[discoKeyPair]
}

// Pair returns the private and public keys together atomically.
// Code that needs both the private and public keys synchronized should
// use Pair instead of calling Private and Public separately.
func (dk *discoAtomic) Pair() (key.DiscoPrivate, key.DiscoPublic) {
	p := dk.pair.Load()
	return p.private, p.public
}

// Private returns the private key.
func (dk *discoAtomic) Private() key.DiscoPrivate {
	return dk.pair.Load().private
}

// Public returns the public key.
func (dk *discoAtomic) Public() key.DiscoPublic {
	return dk.pair.Load().public
}

// Short returns the short string of the public key (see [DiscoPublic.ShortString]).
func (dk *discoAtomic) Short() string {
	return dk.pair.Load().short
}

// Set updates the private key (and the cached public key and short string).
func (dk *discoAtomic) Set(private key.DiscoPrivate) {
	public := private.Public()
	dk.pair.Store(&discoKeyPair{
		private: private,
		public:  public,
		short:   public.ShortString(),
	})
}
