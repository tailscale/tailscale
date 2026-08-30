# Exit Node Split Tunnel

This fork adds a Linux option for using a Tailscale exit node without letting
`tailscaled` install its normal policy-routing `ip rule` entries.

The option is useful on routers, especially OpenWrt systems, where Tailscale
should populate its routing table but another policy-routing system should
decide which traffic uses that table.

In this mode:

- Tailscale still joins the tailnet normally.
- Exit-node routes are still installed into Tailscale's Linux route table,
  table `52`.
- Tailscale does not install its automatic policy-routing rules for table `52`.
- You can add your own `ip rule`, `nftables`, `mwan3`, `pbr`, or OpenWrt policy
  routing rules to send only selected traffic to table `52`.

## Why This Exists

Standard Tailscale exit-node behavior on Linux installs routes into table `52`
and also installs policy rules that make the host use those routes.

That is correct for normal clients, but it is too broad for router split
tunneling. For example, on OpenWrt you might want only traffic from one
interface, VLAN, bridge, or source subnet to use the Tailscale exit node while
all other traffic continues to use the normal WAN route.

`--exit-node-split-tunnel=true` leaves table `52` available but lets you decide
which packets should look it up.

## Enable The Option

First select an exit node as usual:

```bash
sudo tailscale set --exit-node=100.x.y.z
```

Then enable split-tunnel exit-node mode:

```bash
sudo tailscale set --exit-node-split-tunnel=true
```

You can check the current value with:

```bash
tailscale get exit-node-split-tunnel
```

Expected output:

```text
true
```

The setting is stored in Tailscale preferences, so it survives `tailscaled`
restarts.

To disable it and return to normal Tailscale exit-node behavior:

```bash
sudo tailscale set --exit-node-split-tunnel=false
```

## Cold-Start Configuration

If you need to guarantee that Tailscale never installs its automatic policy
rules during startup, set the option in the `tailscaled` config file before the
daemon starts.

Example:

```json
{
  "Version": "alpha0",
  "AuthKey": "file:/path/to/authkey",
  "Hostname": "openwrt-router",
  "acceptDNS": false,
  "exitNode": "100.x.y.z",
  "exitNodeSplitTunnel": true
}
```

Start `tailscaled` with that config:

```bash
tailscaled --config=/etc/tailscale/tailscaled.json
```

Replace `100.x.y.z` with the Tailscale IP of your exit node.

## Verify Behavior

After enabling the option, table `52` should contain Tailscale routes:

```bash
ip route show table 52
ip -6 route show table 52
```

With an exit node active, you should normally see default routes like:

```text
default dev tailscale0
default dev tailscale0 metric 1024 pref medium
```

But Tailscale's automatic policy rules should be absent:

```bash
ip -4 rule show
ip -6 rule show
```

On a clean system with split-tunnel mode enabled, IPv4 should look similar to:

```text
0:      from all lookup local
32766:  from all lookup main
32767:  from all lookup default
```

IPv6 should look similar to:

```text
0:      from all lookup local
32766:  from all lookup main
```

You can also check for common Tailscale rule priorities:

```bash
ip -4 rule show | grep -E '(^|[[:space:]])(5210|5230|5250|5270|1310|1330|1350|1370):'
ip -6 rule show | grep -E '(^|[[:space:]])(5210|5230|5250|5270|1310|1330|1350|1370):'
```

Both commands should produce no output.

## OpenWrt Example

Assume:

- `br-lan` should keep using the normal WAN route.
- `br-vpn` should use the Tailscale exit node.
- Tailscale has installed exit-node routes into table `52`.

Add a policy rule for only the selected interface:

```bash
ip rule add pref 1000 iif br-vpn lookup 52
```

Check routing decisions:

```bash
ip route get 1.1.1.1 iif br-vpn
ip route get 1.1.1.1 iif br-lan
```

Traffic arriving on `br-vpn` should route through `tailscale0`. Traffic arriving
on `br-lan` should continue to use the normal WAN route.

For persistent OpenWrt configuration, put the equivalent policy in your normal
OpenWrt routing stack, such as `pbr`, `mwan3`, hotplug scripts, or custom
`/etc/config/network` rules.

## Notes And Caveats

- This option is Linux-specific.
- This option only controls Tailscale's automatic policy-routing rules. It does
  not disable route installation into table `52`.
- This option does not create custom split-tunnel rules for you. You must add
  your own policy routing to select which traffic uses table `52`.
- If you enable the option on an already-running node, existing Tailscale policy
  rules are removed.
- If you disable the option, normal Tailscale policy rules are installed again.
- This is intended for advanced router and policy-routing setups. For ordinary
  clients, normal `tailscale set --exit-node=...` behavior is usually the right
  choice.
