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
	docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t ${IMAGE_REPO}:latest --push -f Dockerfile .

check: staticcheck vet depaware buildwindows build386 buildlinuxarm

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck -- $$(go list ./... | grep -v tempfork)
