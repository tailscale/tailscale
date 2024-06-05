# Tailscale Appliance

This is the definition of the Gokrazy Tailscale Appliance (tsapp) image.
See the parent directory for context.

## File contents

The `config.json` is a Gokrazy config.

The `usr-dir.tar` is a single symlink named `bin` pointing to `/user`. We write it to `/usr/bin => /user` so the Busybox `ash` shell's default `$PATH` includes `/user`, where the `tailscale` CLI is.

The `builddir` is the Gokrazy build environment, defining each program's `go.mod`.
