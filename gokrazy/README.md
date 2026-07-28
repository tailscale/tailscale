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

`go run build.go --bucket=your-S3-temp-bucket` to build an AMI.

Credentials come from the AWS SDK's default chain, so authenticate any way it
recognizes: `aws sso login`, `aws configure`, an `AWS_PROFILE`,
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars, or
`aws-vault exec <profile> -- go run build.go --bucket=...` (aws-vault injects
temporary credentials as env vars). If no credentials are found the build stops
with a message telling you how to log in.

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

### Configuring the appliance

The appliance's `tailscaled` runs with `-config=optional:vm:user-data`, so a
single AMI supports two ways of joining a tailnet:

- **Declarative (user-data):** put a Tailscale config (the `alpha0` HuJSON
  format) in the instance's user-data and the node configures itself on first
  boot. The minimal config is just an auth key:

  ```json
  {
    "Version": "alpha0",
    "AuthKey": "tskey-auth-..."
  }
  ```

  A config present in user-data locks the CLI (`tailscale set`/`up` are
  rejected) unless it sets `"Locked": false`. Add `"RemoteConfig": true` to
  hand full remote management of the node to the tailnet admin (see
  `Prefs.RemoteConfig`) — appropriate for admin-owned fleet devices.

- **Interactive (serial console):** launch the AMI with *no* user-data. The
  `optional:` prefix means the missing config is not an error, so `tailscaled`
  boots unconfigured and you can enroll it over the serial console (connect as
  above, then run `tailscale up` and open the printed login URL).

To require config instead (fail to boot if none is present), build an image
whose `tailscaled` uses `-config=vm:user-data` without the `optional:` prefix.
