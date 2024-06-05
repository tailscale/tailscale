# Tailscale Appliance Gokrazy Image

This is (as of 2024-06-02) a **WORK IN PROGRESS** (pre-alpha) experiment to
package Tailscale as a [Gokrazy](https://gokrazy.org/) appliance image
for use on both VMs (AWS, GCP, Azure, Proxmox, ...) and Rasperry Pis.

See https://github.com/tailscale/tailscale/issues/1866

## Overview

It makes a ~70MB image (about the same size as
`tailscale-setup-full-1.66.4.exe` and smaller than the combined
Tailscale Android APK) that combines the Linux kernel and Tailscale
and that's it. Nothing written in C. (except optional busybox for
debugging) So no operating system to maintain. Gokrazy has three
partitions: two read-only ones (one active at a time, the other for
updates for the next boot) and one optional stateful, writable
partition that survives upgrades (`/perm/`)

Initial bootstrap configuration of this appliance will be over either
serial or configuration files (auth keys, subnet routes, etc) baked into
the image (for Raspberry Pis) or in cloud-init/user-data (for AWS, etc).
As of 2024-06-02, AWS user-data config files work.

## Quick start

Install dependencies:
```
$ brew install qemu e2fsprogs
```

Build + launch:
```
$ make qemu
```

That puts serial on stdio. To exit the serial console and escape to
the qemu monitor, type `Ctrl-a c`. Then type `quit` in the monitor to
quit.

## Building

`make image` to build just the image (`tsapp.img`), without uploading it.

## UTM

You can also use UTM, but the qemu path above is easier.
For UTM, see the [UTM instructions](UTM.md).

## AWS

### Build an AMI

`go run build.go --bucket=your-S3-temp-bucket` to build an AMI. Make
sure your "aws" command is in your path and has access.

### Creating an instance

When creating an instance, you need a Nitro machine type to get a
virtual serial console. Notably, that means the `t2.*` instance types
that AWS pushes as a free option are not new enough. Use `t3.*` at least.

As of 2024-06-02 this builder tool only supports x86_64 (arm64 should
be trivial and will come soon), so don't use a Graviton machine type.

To connect to the serial console, you can either use the web console, or
use the CLI like:

```
$ aws ec2-instance-connect send-serial-console-ssh-public-key --instance-id i-0b4a0eabc43629f13 --serial-port 0 --ssh-public-key file:///your/home/.ssh/id_ed25519.pub --region us-west-2
{
    "RequestId": "a93b0ea3-9ff9-45d5-b8ed-b1e70ccc0410",
    "Success": true
}
$ ssh i-0b4a0eabc43629f13.port0@serial-console.ec2-instance-connect.us-west-2.aws 
```
