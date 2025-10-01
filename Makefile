IMAGE_REPO ?= tailscale/tailscale
SYNO_ARCH ?= "x86_64"
SYNO_DSM ?= "7"
TAGS ?= "latest"

PLATFORM ?= "flyio" ## flyio==linux/amd64. Set to "" to build all platforms.

vet: ## Run go vet
	./tool/go vet ./...

tidy: ## Run go mod tidy and update nix flake hashes
	./tool/go mod tidy
	./update-flake.sh

lint: ## Run golangci-lint
	./tool/go run github.com/golangci/golangci-lint/cmd/golangci-lint run

updatedeps: ## Update depaware deps
	# depaware (via x/tools/go/packages) shells back to "go", so make sure the "go"
	# it finds in its $$PATH is the right one.
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --update --vendor --internal \
		tailscale.com/cmd/tailscaled \
		tailscale.com/cmd/tailscale \
		tailscale.com/cmd/derper \
		tailscale.com/cmd/k8s-operator \
		tailscale.com/cmd/stund \
		tailscale.com/cmd/tsidp
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --update --goos=linux,darwin,windows,android,ios --vendor --internal \
		tailscale.com/tsnet
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --update --file=depaware-minbox.txt --goos=linux --tags="$$(./tool/go run ./cmd/featuretags --min --add=cli)" --vendor --internal \
		tailscale.com/cmd/tailscaled
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --update --file=depaware-min.txt --goos=linux --tags="$$(./tool/go run ./cmd/featuretags --min)" --vendor --internal \
		tailscale.com/cmd/tailscaled

depaware: ## Run depaware checks
	# depaware (via x/tools/go/packages) shells back to "go", so make sure the "go"
	# it finds in its $$PATH is the right one.
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --check --vendor --internal \
		tailscale.com/cmd/tailscaled \
		tailscale.com/cmd/tailscale \
		tailscale.com/cmd/derper \
		tailscale.com/cmd/k8s-operator \
		tailscale.com/cmd/stund \
		tailscale.com/cmd/tsidp
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --check --goos=linux,darwin,windows,android,ios --vendor --internal \
		tailscale.com/tsnet
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --check --file=depaware-minbox.txt --goos=linux --tags="$$(./tool/go run ./cmd/featuretags --min --add=cli)" --vendor --internal \
		tailscale.com/cmd/tailscaled
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --check --file=depaware-min.txt --goos=linux --tags="$$(./tool/go run ./cmd/featuretags --min)" --vendor --internal \
		tailscale.com/cmd/tailscaled

buildwindows: ## Build tailscale CLI for windows/amd64
	GOOS=windows GOARCH=amd64 ./tool/go install tailscale.com/cmd/tailscale tailscale.com/cmd/tailscaled

build386: ## Build tailscale CLI for linux/386
	GOOS=linux GOARCH=386 ./tool/go install tailscale.com/cmd/tailscale tailscale.com/cmd/tailscaled

buildlinuxarm: ## Build tailscale CLI for linux/arm
	GOOS=linux GOARCH=arm ./tool/go install tailscale.com/cmd/tailscale tailscale.com/cmd/tailscaled

buildwasm: ## Build tailscale CLI for js/wasm
	GOOS=js GOARCH=wasm ./tool/go install ./cmd/tsconnect/wasm ./cmd/tailscale/cli

buildplan9:
	GOOS=plan9 GOARCH=amd64 ./tool/go install ./cmd/tailscale ./cmd/tailscaled

buildlinuxloong64: ## Build tailscale CLI for linux/loong64
	GOOS=linux GOARCH=loong64 ./tool/go install tailscale.com/cmd/tailscale tailscale.com/cmd/tailscaled

buildmultiarchimage: ## Build (and optionally push) multiarch docker image
	./build_docker.sh

check: staticcheck vet depaware buildwindows build386 buildlinuxarm buildwasm ## Perform basic checks and compilation tests

staticcheck: ## Run staticcheck.io checks
	./tool/go run honnef.co/go/tools/cmd/staticcheck -- $$(./tool/go run ./tool/listpkgs --ignore-3p  ./...)

kube-generate-all: kube-generate-deepcopy ## Refresh generated files for Tailscale Kubernetes Operator
	./tool/go generate ./cmd/k8s-operator

# Tailscale operator watches Connector custom resources in a Kubernetes cluster
# and caches them locally. Caching is done implicitly by controller-runtime
# library (the middleware used by Tailscale operator to create kube control
# loops). When a Connector resource is GET/LIST-ed from within our control loop,
# the request goes through the cache. To ensure that cache contents don't get
# modified by control loops, controller-runtime deep copies the requested
# object. In order for this to work, Connector must implement deep copy
# functionality so we autogenerate it here.
# https://github.com/kubernetes-sigs/controller-runtime/blob/v0.16.3/pkg/cache/internal/cache_reader.go#L86-L89
kube-generate-deepcopy: ## Refresh generated deepcopy functionality for Tailscale kube API types
	./scripts/kube-deepcopy.sh

spk: ## Build synology package for ${SYNO_ARCH} architecture and ${SYNO_DSM} DSM version
	./tool/go run ./cmd/dist build synology/dsm${SYNO_DSM}/${SYNO_ARCH}

spkall: ## Build synology packages for all architectures and DSM versions
	./tool/go run ./cmd/dist build synology

pushspk: spk ## Push and install synology package on ${SYNO_HOST} host
	echo "Pushing SPK to root@${SYNO_HOST} (env var SYNO_HOST) ..."
	scp tailscale.spk root@${SYNO_HOST}:
	ssh root@${SYNO_HOST} /usr/syno/bin/synopkg install tailscale.spk

.PHONY: check-image-repo
check-image-repo:
	@if [ -z "$(REPO)" ]; then \
		echo "REPO=... required; e.g. REPO=ghcr.io/$$USER/tailscale" >&2; \
		exit 1; \
	fi
	@for repo in tailscale/tailscale ghcr.io/tailscale/tailscale \
		tailscale/k8s-operator ghcr.io/tailscale/k8s-operator \
		tailscale/k8s-nameserver ghcr.io/tailscale/k8s-nameserver \
		tailscale/tsidp ghcr.io/tailscale/tsidp \
		tailscale/k8s-proxy ghcr.io/tailscale/k8s-proxy; do \
		if [ "$(REPO)" = "$$repo" ]; then \
			echo "REPO=... must not be $$repo" >&2; \
			exit 1; \
		fi; \
	done

publishdevimage: check-image-repo ## Build and publish tailscale image to location specified by ${REPO}
	TAGS="${TAGS}" REPOS=${REPO} PLATFORM=${PLATFORM} PUSH=true TARGET=client ./build_docker.sh

publishdevoperator: check-image-repo ## Build and publish k8s-operator image to location specified by ${REPO}
	TAGS="${TAGS}" REPOS=${REPO} PLATFORM=${PLATFORM} PUSH=true TARGET=k8s-operator ./build_docker.sh

publishdevnameserver: check-image-repo ## Build and publish k8s-nameserver image to location specified by ${REPO}
	TAGS="${TAGS}" REPOS=${REPO} PLATFORM=${PLATFORM} PUSH=true TARGET=k8s-nameserver ./build_docker.sh

publishdevtsidp: check-image-repo ## Build and publish tsidp image to location specified by ${REPO}
	TAGS="${TAGS}" REPOS=${REPO} PLATFORM=${PLATFORM} PUSH=true TARGET=tsidp ./build_docker.sh

publishdevproxy: check-image-repo ## Build and publish k8s-proxy image to location specified by ${REPO}
	TAGS="${TAGS}" REPOS=${REPO} PLATFORM=${PLATFORM} PUSH=true TARGET=k8s-proxy ./build_docker.sh

.PHONY: sshintegrationtest
sshintegrationtest: ## Run the SSH integration tests in various Docker containers
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 ./tool/go test -tags integrationtest -c ./ssh/tailssh -o ssh/tailssh/testcontainers/tailssh.test && \
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 ./tool/go build -o ssh/tailssh/testcontainers/tailscaled ./cmd/tailscaled && \
	echo "Testing on ubuntu:focal" && docker build --build-arg="BASE=ubuntu:focal" -t ssh-ubuntu-focal ssh/tailssh/testcontainers && \
	echo "Testing on ubuntu:jammy" && docker build --build-arg="BASE=ubuntu:jammy" -t ssh-ubuntu-jammy ssh/tailssh/testcontainers && \
	echo "Testing on ubuntu:noble" && docker build --build-arg="BASE=ubuntu:noble" -t ssh-ubuntu-noble ssh/tailssh/testcontainers && \
	echo "Testing on alpine:latest" && docker build --build-arg="BASE=alpine:latest" -t ssh-alpine-latest ssh/tailssh/testcontainers

.PHONY: generate
generate: ## Generate code
	./tool/go generate ./...

.PHONY: pin-github-actions
pin-github-actions:
	./tool/go tool github.com/stacklok/frizbee actions .github/workflows

help: ## Show this help
	@echo ""
	@echo "Specify a command. The choices are:"
	@echo ""
	@grep -hE '^[0-9a-zA-Z_-]+:.*?## .*$$' ${MAKEFILE_LIST} | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;36m%-20s\033[m %s\n", $$1, $$2}'
	@echo ""
.PHONY: help

.DEFAULT_GOAL := help
