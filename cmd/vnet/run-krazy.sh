#!/usr/bin/env bash

echo "Type 'C-a c' to enter monitor; q to quit."

# If the USE_V6 environment is set to 1, set the nameserver explicitly to.
EXTRA_ARG=""
if [ "$USE_V6" = "1" ]; then
    EXTRA_ARG="tta.nameserver=2411::411"
fi

set -eux
qemu-system-x86_64 -M microvm,isa-serial=off \
    -m 1G \
    -nodefaults -no-user-config -nographic \
    -kernel $HOME/src/github.com/tailscale/gokrazy-kernel/vmlinuz \
    -append "console=hvc0 root=PARTUUID=60c24cc1-f3f9-427a-8199-76baa2d60001/PARTNROFF=1 ro init=/gokrazy/init panic=10 oops=panic pci=off nousb tsc=unstable clocksource=hpet tailscale-tta=1 tailscaled.env=TS_DEBUG_RAW_DISCO=1 ${EXTRA_ARG}" \
    -drive id=blk0,file=$HOME/src/tailscale.com/gokrazy/natlabapp.img,format=raw \
    -device virtio-blk-device,drive=blk0 \
    -device virtio-rng-device \
    -netdev stream,id=net0,addr.type=unix,addr.path=/tmp/qemu.sock \
    -device virtio-serial-device \
    -device virtio-net-device,netdev=net0,mac=52:cc:cc:cc:cc:01 \
    -chardev stdio,id=virtiocon0,mux=on \
    -device virtconsole,chardev=virtiocon0 \
    -mon chardev=virtiocon0,mode=readline \
    -audio none

