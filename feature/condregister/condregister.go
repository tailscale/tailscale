// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The condregister package registers all conditional features guarded
// by build tags. It is one central package that callers can empty import
// to ensure all conditional features are registered.
package condregister
