# ./qemu-wrapper /tmp/qemu.sock qemu-system-x86_64 [...] -netdev socket,id=vlan,fd=3 -device virtio-net-pci,netdev=vlan

help:
	echo "See Makefile"

image:
	go run build.go --build

qemu: image
	qemu-system-x86_64 -m 1G -drive file=tsapp.img,format=raw -boot d -netdev user,id=user.0 -device virtio-net-pci,netdev=user.0 -serial mon:stdio -audio none

qemuwrap: image
	go run ./cmd/vnetwrap qemu-system-x86_64 -m 1G -drive file=tsapp.img,format=raw -boot d -netdev socket,fd=3,id=user.0 -device virtio-net-pci,netdev=user.0 -serial mon:stdio -audio none
