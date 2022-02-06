PACKAGE = github.com/cavaliercoder/go-cpio

all: check

check:
	go test -v

cpio-fuzz.zip: *.go
	go-fuzz-build $(PACKAGE)

fuzz: cpio-fuzz.zip
	go-fuzz -bin=./cpio-fuzz.zip -workdir=.fuzz/

clean-fuzz:
	rm -rf cpio-fuzz.zip .fuzz/crashers/* .fuzz/suppressions/*


.PHONY: all check
