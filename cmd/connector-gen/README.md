# connector-gen

Generate Tailscale app connector configuration details from third party data.

Tailscale app connectors are used to dynamically route traffic for domain names
via specific nodes on a tailnet. For larger upstream domains this may involve a
large number of domains or routes, and fully dynamic discovery may be slower or
involve more manual labor than ideal. This can be accelerated by
pre-configuration of the associated routes, based on data provided by the
target providers, which can be used to set precise `autoApprovers` routes, and
also to pre-populate the subnet routes via `--advertise-routes` avoiding
frequent routing reconfiguration that may otherwise occur while routes are
first being discovered and advertised by the connectors.


