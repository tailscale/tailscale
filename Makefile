IMAGE_REPO ?= tailscale/tailscale
SYNO_ARCH ?= "amd64"
SYNO_DSM ?= "7"

usage:
	echo "See Makefile"

vet:
	go vet ./...

updatedeps:
	go run github.com/tailscale/depaware --update tailscale.com/cmd/tailscaled
	go run github.com/tailscale/depaware --update tailscale.com/cmd/tailscale

depaware:
	go run github.com/tailscale/depaware --check tailscale.com/cmd/tailscaled
	go run github.com/tailscale/depaware --check tailscale.com/cmd/tailscale

buildwindows:
	GOOS=windows GOARCH=amd64 go install tailscale.com/cmd/tailscale tailscale.com/cmd/tailscaled

build386:
	GOOS=linux GOARCH=386 go install tailscale.com/cmd/tailscale tailscale.com/cmd/tailscaled

buildlinuxarm:
	GOOS=linux GOARCH=arm go install tailscale.com/cmd/tailscale tailscale.com/cmd/tailscaled

buildmultiarchimage:
	./build_docker.sh

check: staticcheck vet depaware buildwindows build386 buildlinuxarm

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck -- $$(go list ./... | grep -v tempfork)

spk:
	PATH="${PWD}/tool:${PATH}" ./tool/go run github.com/tailscale/tailscale-synology@main -o tailscale.spk --source=. --goarch=${SYNO_ARCH} --dsm-version=${SYNO_DSM}

spkall:
	mkdir -p spks
	PATH="${PWD}/tool:${PATH}" ./tool/go run github.com/tailscale/tailscale-synology@main -o spks --source=. --goarch=all --dsm-version=all

pushspk: spk
	echo "Pushing SPK to root@${SYNO_HOST} (env var SYNO_HOST) ..."
	scp tailscale.spk root@${SYNO_HOST}:
	ssh root@${SYNO_HOST} /usr/syno/bin/synopkg install tailscale.spk
