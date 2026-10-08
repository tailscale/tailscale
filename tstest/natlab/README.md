# natlab

Virtual network lab for integration tests. Tracking issue:
https://github.com/tailscale/tailscale/issues/13038

Use the `run-natlab-tests` GitHub label on PRs to run these tests.

## Prerequisites

- `qemu-system-x86_64` and `qemu-img`. On Debian/Ubuntu:
  `apt install qemu-system-x86 qemu-utils`
- A built gokrazy natlabapp image (auto-built on first run via
  `make -C gokrazy natlab`)

KVM is used automatically on Linux when `/dev/kvm` is readable+writable. Add
yourself to the `kvm` group to avoid QEMU falling back to software emulation.

## Running locally

```
go test ./tstest/natlab/vmtest/ --run-vm-tests -v -timeout=15
```

`go test`'s default timeout (10 min) is likely not enough to cover the whole
package. You may need to raise it further or disable the timeout entirely
(`-timeout=0`) when running the full suite.

Alternatively, select individual tests with the usual `-run`.
