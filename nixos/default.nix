# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Tailscale NixOS module entry point.
# Provides both single-instance (services.tailscale) and multi-instance
# (services.tailscales.<name>) Tailscale daemon configuration.
self: {
  imports = [
    (import ./options.nix self)
    (import ./service.nix self)
  ];
}
