help:
	echo "See Makefile"

image:
	go run build.go --build

qemu: image
	qemu-system-x86_64 -m 1G -drive file=tsapp.img,format=raw -boot d -netdev user,id=user.0 -device virtio-net-pci,netdev=user.0 -serial mon:stdio -audio none

# For natlab integration tests:
natlab:
	go run build.go --build --app=natlabapp
	qemu-img convert -O qcow2 natlabapp.img natlabapp.qcow2

# For natlab integration tests that need the Linux 7.0 UDP GSO bug.
# Requires ../github.com/tailscale/gokrazy-kernel-buggy-linux-7_0/vmlinuz.
natlab-buggy-linux-7_0:
	go run build.go --build --app=natlabapp.buggy-linux-7_0
	qemu-img convert -O qcow2 natlabapp.buggy-linux-7_0.img natlabapp.buggy-linux-7_0.qcow2

# For natlab integration tests on macOS arm64:
natlab-arm64:
	go run build.go --build --app=natlabapp.arm64
	qemu-img convert -O qcow2 natlabapp.arm64.img natlabapp.arm64.qcow2
