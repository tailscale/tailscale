# NATLab Linux test Appliance

This is the definition of the NATLab Linux test appliance image that boots a
buggy Linux 7.0 kernel for UDP GSO mitigation tests.

It is similar to ../natlabapp, but uses the local
github.com/tailscale/gokrazy-kernel-buggy-linux-7_0 kernel package and is
booted by vmtest with QEMU's `igb` NIC.
