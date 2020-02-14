// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package empty defines an empty struct type.
package empty

// Message is an empty message. Its purpose is to be used as pointer
// type where nil and non-nil distinguish whether it's set. This is
// used instead of a bool when we want to marshal it as a JSON empty
// object (or null) for the future ability to add other fields, at
// which point callers would define a new struct and not use
// empty.Message.
type Message struct{}
