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
