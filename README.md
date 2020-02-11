# Tailscale

https://tailscale.com

Private WireGuard® networks made easy

## Overview

This repository contains all the open source Tailscale code.
It currently includes the Linux client.

The Linux client is currently `cmd/relaynode`, but will
soon be replaced by `cmd/tailscaled`.

## Building

```
go install tailscale.com/cmd/tailscale{,d}
```

We only support the latest Go release and any Go beta or release
candidate builds (currently Go 1.13.x or Go 1.14) in module mode. It
might work in earlier Go versions or in GOPATH mode, but we're making
no effort to keep those working.

## Bugs

Please file any issues about this code or the hosted service on
[the issue tracker](https://github.com/tailscale/tailscale/issues).

## Contributing

`under_construction.gif`

PRs welcome, but we are still working out our contribution process and
tooling.

We require [Developer Certificate of
Origin](https://en.wikipedia.org/wiki/Developer_Certificate_of_Origin)
`Signed-off-by` lines in commits.

## About Us

We are apenwarr, bradfitz, crawshaw, danderson, dfcarney,
from Tailscale Inc.
You can learn more about us from [our website](https://tailscale.com).

WireGuard is a registered trademark of Jason A. Donenfeld.
