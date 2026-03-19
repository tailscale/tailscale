XCPRETTIFIER := xcpretty
ifeq (, $(shell which $(XCPRETTIFIER)))
	XCPRETTIFIER := cat
endif

.PHONY: tailmac
tailmac:
	xcodebuild -scheme tailmac -destination 'platform=macOS,arch=arm64' -derivedDataPath build -configuration Release build | $(XCPRETTIFIER)
	cp -r ./build/Build/Products/Release/tailmac ./bin/tailmac

.PHONY: host
host:
	xcodebuild -scheme host -destination 'platform=macOS,arch=arm64'  -derivedDataPath build -configuration Release build | $(XCPRETTIFIER)
	cp -r ./build/Build/Products/Release/Host.app ./bin/Host.app

.PHONY: clean
clean:
	rm -rf ./bin
	rm -rf ./build
	mkdir -p ./bin

.PHONY: all
all: clean tailmac host
