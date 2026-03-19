# End-to-End VM-based Integration Testing

These tests spin up a Tailscale client in a Linux VM and try to connect it to
[`testcontrol`](https://pkg.go.dev/tailscale.com/tstest/integration/testcontrol)
server.

## Running

This test currently only runs on Linux.

This test depends on the following command line tools:

- [qemu](https://www.qemu.org/)
- [cdrkit](https://en.wikipedia.org/wiki/Cdrkit)
- [openssh](https://www.openssh.com/)

This test also requires the following:

- about 10 GB of temporary storage
- about 10 GB of cached VM images
- at least 4 GB of ram for virtual machines
- hardware virtualization support
  ([KVM](https://www.linux-kvm.org/page/Main_Page)) enabled in the BIOS
- the `kvm` module to be loaded (`modprobe kvm`)
- the user running these tests must have access to `/dev/kvm` (being in the
  `kvm` group should suffice)

The `--no-s3` flag is needed to disable downloads from S3, which require
credentials. However keep in mind that some distributions do not use stable URLs
for each individual image artifact, so there may be spurious test failures as a
result.

If you are using [Nix](https://nixos.org), you can run all of the tests with the
correct command line tools using this command:

```console
$ nix-shell -p nixos-generators -p openssh -p go -p qemu -p cdrkit --run "go test . --run-vm-tests --v --timeout 30m --no-s3"
```

Keep the timeout high for the first run, especially if you are not downloading
VM images from S3. The mirrors we pull images from have download rate limits and
will take a while to download.

Because of the hardware requirements of this test, this test will not run
without the `--run-vm-tests` flag set.

## Other Fun Flags

This test's behavior is customized with command line flags.

### Don't Download Images From S3

If you pass the `-no-s3` flag to `go test`, the S3 step will be skipped in favor
of downloading the images directly from upstream sources, which may cause the
test to fail in odd places.

### Ram Limiting

This test uses a lot of memory. In order to avoid making machines run out of
memory running this test, a semaphore is used to limit how many megabytes of ram
are being used at once. By default this semaphore is set to 4096 MB of ram
(about 4 gigabytes). You can customize this with the `--ram-limit` flag:

```console
$ go test --run-vm-tests --ram-limit 2048
$ go test --run-vm-tests --ram-limit 65536
```

The first example will set the limit to 2048 MB of ram (about 2 gigabytes). The
second example will set the limit to 65536 MB of ram (about 65 gigabytes).
Please be careful with this flag, improper usage of it is known to cause the
Linux out-of-memory killer to engage. Try to keep it within 50-75% of your
machine's available ram (there is some overhead involved with the
virtualization) to be on the safe side.
