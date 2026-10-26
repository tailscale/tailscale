// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package health

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"

	"tailscale.com/types/logger"
)

// Probe is a Kubernetes probe server. It serves 200 only once every check
// registered with it passes, otherwise 503 with the reason each failing check
// gave.
//
// A nil Probe is valid and ignores registrations, so callers don't need to
// check whether health checks are enabled.
type Probe struct {
	name string
	logf logger.Logf

	mu     sync.Mutex // protects following
	checks []check
}

type check struct {
	name string
	fn   func(context.Context) error
}

func (p *Probe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	checks := slices.Clone(p.checks)
	p.mu.Unlock()

	var errs []error
	for _, c := range checks {
		if err := c.fn(r.Context()); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.name, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if _, err := w.Write([]byte("ok")); err != nil {
		http.Error(w, fmt.Sprintf("error writing status: %v", err), http.StatusInternalServerError)
	}
}

// AddCheck registers a check that is run on every request. fn returns nil if
// the check passes, or the reason it doesn't. fn must be cheap and safe for
// concurrent use.
func (p *Probe) AddCheck(name string, fn func(context.Context) error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checks = append(p.checks, check{name: name, fn: fn})
}

// AddCondition registers a check whose state is set by its owner with
// [Condition.Set]. It starts out failing, reporting reason.
func (p *Probe) AddCondition(name, reason string) *Condition {
	if p == nil {
		return nil
	}
	c := &Condition{name: p.name + ": " + name, reason: reason, logf: p.logf}
	p.AddCheck(name, c.check)
	return c
}

// Condition is a check that its owner sets as its state changes.
// A nil Condition is valid and ignores Set.
type Condition struct {
	name   string
	reason string
	logf   logger.Logf

	mu   sync.Mutex // protects following
	pass bool
}

// Set records whether the condition holds.
func (c *Condition) Set(pass bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pass != pass {
		c.logf("%s passing: %v", c.name, pass)
	}
	c.pass = pass
}

func (c *Condition) check(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.pass {
		return errors.New(c.reason)
	}
	return nil
}
