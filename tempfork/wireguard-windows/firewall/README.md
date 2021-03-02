This is a copy of the `tunnel/firewall` package of
https://git.zx2c4.com/wireguard-windows, with some hardcoded filter
rules adjusted to function with Tailscale, rather than
wireguard-windows's process structure.

You should not use this package. It exists as a band-aid while we
figure out how to upstream a more flexible firewall package that does
the fancier things we need, while also supporting wireguard-windows's
goals.
