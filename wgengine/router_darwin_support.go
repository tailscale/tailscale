// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux darwin

package wgengine

// SetRoutesFunc applies the given route settings to the OS network
// stack.
//
// This is logically part of the router_darwin.go implementation, and
// should not be used on other platforms.
//
// The code to reconfigure the network stack on MacOS and iOS is in
// the non-open `ipn-go-bridge` package, which bridges between the Go
// and Swift pieces of the application. The ipn-go-bridge sets
// SetRoutesFunc at startup.
//
// So why isn't this in router_darwin.go? Because in the non-oss
// repository, we build ipn-go-bridge when developing on Linux as well
// as MacOS, so that we don't have to wait until the Mac CI to
// discover that we broke it. So this one definition needs to exist in
// both the darwin and linux builds. Hence this file and build tag.
var SetRoutesFunc func(rs RouteSettings) error
