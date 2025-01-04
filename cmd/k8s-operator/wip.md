This is an experimental attempt to add UDP forwarding support to serve with a goal of being able to implement the Kubernetes Operator L3 proxies, that currently use iptables/nftables, in code using serve.

This allows configuring a UDP backend for serve like so:

```sh
{"UDP":{"53":{"UDPForward":"10.0.0.3:1053"}}}
```

where 53 is the port that will be exposed on the proxy and 10.0.0.3:1053 is the address and port of a Kubernetes Service.
There is already an existing TCPForward field that works the same way.

The operator could generate these serve configs for proxies.

This would allow deploying L3 proxies without needing to use privileged containers (if run in userspace) and would also allow users to benefit from some of the performance improvements in userspace.

I've tested both TCP and UDP forwarding to Kubernetes Services both in tun mode and userspace mode and it works as expected.

Kubernetes Services also support SCTP, but it is not widely used.
