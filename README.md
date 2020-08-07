# Tailscale

https://tailscale.com

Private WireGuard® networks made easy

## Overview

This repository contains all the open source Tailscale client code and
the `tailscaled` daemon and `tailscale` CLI tool. The `tailscaled`
daemon runs primarily on Linux; it also works to varying degrees on
FreeBSD, OpenBSD, Darwin, and Windows.

The Android app is at https://github.com/tailscale/tailscale-android

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

We only guarantee to support the latest Go release and any Go beta or
release candidate builds (currently Go 1.14) in module mode. It might
work in earlier Go versions or in GOPATH mode, but we're making no
effort to keep those working.

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

We are apenwarr, bradfitz, crawshaw, danderson, dfcarney, josharian
from Tailscale Inc.
You can learn more about us from [our website](https://tailscale.com).

WireGuard is a registered trademark of Jason A. Donenfeld.
