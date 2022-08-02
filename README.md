# Tailscale

https://tailscale.com

Private WireGuard® networks made easy

## Overview

This repository contains all the open source Tailscale client code and
the `tailscaled` daemon and `tailscale` CLI tool. The `tailscaled`
daemon runs on Linux, Windows and [macOS](https://tailscale.com/kb/1065/macos-variants/), and to varying degrees on FreeBSD, OpenBSD, and Darwin. (The Tailscale iOS and Android apps use this repo's code, but this repo doesn't contain the mobile GUI code.)

The Android app is at https://github.com/tailscale/tailscale-android

The Synology package is at https://github.com/tailscale/tailscale-synology

## Using

We serve packages for a variety of distros at
https://pkgs.tailscale.com .

## Other clients

The [macOS, iOS, and Windows clients](https://tailscale.com/download)
use the code in this repository but additionally include small GUI
wrappers that are not open source.

## Building

```
go install tailscale.com/cmd/tailscale{,d}
```

If you're packaging Tailscale for distribution, use `build_dist.sh`
instead, to burn commit IDs and version info into the binaries:

```
./build_dist.sh tailscale.com/cmd/tailscale
./build_dist.sh tailscale.com/cmd/tailscaled
```

If your distro has conventions that preclude the use of
`build_dist.sh`, please do the equivalent of what it does in your
distro's way, so that bug reports contain useful version information.

We require the latest Go release, currently Go 1.19.

## Bugs

Please file any issues about this code or the hosted service on
[the issue tracker](https://github.com/tailscale/tailscale/issues).

## Contributing

PRs welcome! But please file bugs. Commit messages should [reference
bugs](https://docs.github.com/en/github/writing-on-github/autolinked-references-and-urls).

We require [Developer Certificate of
Origin](https://en.wikipedia.org/wiki/Developer_Certificate_of_Origin)
`Signed-off-by` lines in commits.

## About Us

[Tailscale](https://tailscale.com/) is primarily developed by the
people at https://github.com/orgs/tailscale/people. For other contributors,
see:

* https://github.com/tailscale/tailscale/graphs/contributors
* https://github.com/tailscale/tailscale-android/graphs/contributors

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.
