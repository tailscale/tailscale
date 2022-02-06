# netaddr [![Test Status](https://github.com/inetaf/netaddr/workflows/Linux/badge.svg)](https://github.com/inetaf/netaddr/actions) [![Go Reference](https://pkg.go.dev/badge/inet.af/netaddr.svg)](https://pkg.go.dev/inet.af/netaddr)

## What

This is a package containing a new IP address type for Go.

See its docs: https://pkg.go.dev/inet.af/netaddr

## Status

This package is mature, optimized, and used heavily in production at [Tailscale](https://tailscale.com).
However, API stability is not yet guaranteed.

netaddr is intended to be a core, low-level package.
We take code review, testing, dependencies, and performance seriously, similar to Go's standard library or the golang.org/x repos.

## Motivation

See https://tailscale.com/blog/netaddr-new-ip-type-for-go/ for a long
blog post about why we made a new IP address package.

Other links:

* https://github.com/golang/go/issues/18804 ("net: reconsider representation of IP")
* https://github.com/golang/go/issues/18757 ("net: ParseIP should return an error, like other Parse functions")
* https://github.com/golang/go/issues/37921 ("net: Unable to reliably distinguish IPv4-mapped-IPv6 addresses from regular IPv4 addresses")
* merges net.IPAddr and net.IP (which the Go net package is a little torn between for legacy reasons)

## Testing

In addition to regular Go tests, netaddr uses fuzzing.
The corpus is stored separately, in a submodule,
to minimize the impact on everyone else.

To use:

```
$ git submodule update --init
$ go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
$ go-fuzz-build && go-fuzz
```
