help:
	echo "See Makefile"

image:
	go run build.go --build

gaf:
	go run build.go --gaf

qemu: image
	qemu-system-x86_64 -m 1G -drive file=tsapp.img,format=raw -boot d -netdev user,id=user.0 -device virtio-net-pci,netdev=user.0 -serial mon:stdio -audio none

# For natlab integration tests.
#
# The natlab targets use ../tool/go rather than whatever "go" is on
# $PATH so that they match tstest/natlab/vmtest, which rebuilds this
# image from inside "go test". The go command puts its own $GOROOT/bin
# first on the test binary's $PATH, so the in-test rebuild always uses
# the tailscale/go toolchain. Building with a different toolchain here
# (as CI did with the runner's stock Go) leaves nothing in the build
# cache for the test's rebuild to reuse, turning a ~4 second cache-hit
# rebuild into a multi-minute cold build inside the test's timeout.
natlab:
	../tool/go run build.go --build --app=natlabapp
	qemu-img convert -O qcow2 natlabapp.img natlabapp.qcow2

# For natlab integration tests on macOS arm64:
natlab-arm64:
	../tool/go run build.go --build --app=natlabapp.arm64
	qemu-img convert -O qcow2 natlabapp.arm64.img natlabapp.arm64.qcow2
