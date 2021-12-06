IMAGE_REPO ?= tailscale/tailscale

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
	go run github.com/tailscale/tailscale-synology@main --version=build -o tailscale.spk --source=.

pushspk: spk
	echo "Pushing SPKG to root@${SYNOHOST} (env var SYNOHOST) ..."
	scp tailscale.spk root@${SYNOHOST}:
	ssh root@${SYNOHOST} /usr/syno/bin/synopkg install tailscale.spk
