# chaos

Chaos is a CLI framework that aims to make it easy to implement variants of a Chaos tailnet scenario, where a large number of Tailscale nodes join a tailnet and then perform some actions.

It is currently under development, so the interface is expected to change, which means this readme can be out of date. However here are some good starting points:

- `chaos.go` is the main entry point setting up the sub-command structure and has some helper code for API interaction.
  - When adding a new scenario, you will need to add a new sub-command here.
- `scenario.go` contains the structure of a scenario, it defines the steps and how they are ran.
- `node.go` contains two different implementations of a "node" or Tailscale client:
  - `NodeDirect` is a lightweight implementation that sets up a basic Direct client and minimal map logic, but does the full authentication flow.
  - `NodeTSNet` is a full Tailscale client that uses the tsnet package to set up a full userspace client.
- `scenario-join-n-nodes.go` implements the original chaos tailnet scenario, where N nodes join a tailnet, and also serves as a nice example for how to create a scenario with different configurable variables via flags.


### Remove nodes from tailnet

A helper to clean out all the nodes in the tailnet can be ran as follow:

```bash
 go run ./cmd/chaos \
    --apikey <API_KEY> \
    --tailnet <TAILNET_NAME> \
    --login-server http://127.0.0.1:31544 \
    remove-all-nodes
```
