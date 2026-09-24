# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Tailscale nix-darwin module entry point.
# Provides services.tailscales.<name> — multiple userspace tailscaled
# instances managed as per-user launchd LaunchAgents, designed to
# coexist with the official Tailscale GUI app.
self: {
  imports = [
    (import ./options.nix self)
    (import ./service.nix self)
  ];
}
