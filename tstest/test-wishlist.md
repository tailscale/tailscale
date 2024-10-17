# Testing wishlist

This is a list of tests we'd like to add one day, as our e2e/natlab/VM
testing infrastructure matures.

We're going to start collecting ideas as we develop PRs (updating this
wishlist in the same PR that adds something that could be better
tested) and then use this list to inform the order we build out our
future testing machinery.

For each item, try to include a `#nnn` or `tailscale/corp#nnn`
reference to an issue or PR about the feature.

# The list

- Link-local multicast, and mDNS/LLMNR specifically, when an exit node is used,
  both with and without the "Allow local network access" option enabled.
  When the option is disabled, we should still permit it for internal interfaces,
  such as Hyper-V/WSL2 on Windows.

