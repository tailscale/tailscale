usage:
	echo "See Makefile"

vet:
	go vet ./...

updatedeps:
	go run github.com/tailscale/depaware --update tailscale.com/cmd/tailscaled
	go run github.com/tailscale/depaware --update tailscale.com/cmd/tailscale
	go run github.com/tailscale/depaware --update tailscale.com/cmd/tsshd

depaware:
	go run github.com/tailscale/depaware --check tailscale.com/cmd/tailscaled
	go run github.com/tailscale/depaware --check tailscale.com/cmd/tailscale
	go run github.com/tailscale/depaware --check tailscale.com/cmd/tsshd

check: staticcheck vet depaware

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck -- $$(go list ./... | grep -v tempfork)
