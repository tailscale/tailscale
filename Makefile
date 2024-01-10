IMAGE_REPO ?= tailscale/tailscale
SYNO_ARCH ?= "amd64"
SYNO_DSM ?= "7"
TAGS ?= "latest"

PLATFORM ?= "flyio" ## flyio==linux/amd64. Set to "" to build all platforms.

vet: ## Run go vet
	./tool/go vet ./...

tidy: ## Run go mod tidy
	./tool/go mod tidy

lint: ## Run golangci-lint
	./tool/go run github.com/golangci/golangci-lint/cmd/golangci-lint run

updatedeps: ## Update depaware deps
	# depaware (via x/tools/go/packages) shells back to "go", so make sure the "go"
	# it finds in its $$PATH is the right one.
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --update \
		tailscale.com/cmd/tailscaled \
		tailscale.com/cmd/tailscale \
		tailscale.com/cmd/derper \
		tailscale.com/cmd/stund

depaware: ## Run depaware checks
	# depaware (via x/tools/go/packages) shells back to "go", so make sure the "go"
	# it finds in its $$PATH is the right one.
	PATH="$$(./tool/go env GOROOT)/bin:$$PATH" ./tool/go run github.com/tailscale/depaware --check \
		tailscale.com/cmd/tailscaled \
		tailscale.com/cmd/tailscale \
		tailscale.com/cmd/derper \
		tailscale.com/cmd/stund

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
	./tool/go run honnef.co/go/tools/cmd/staticcheck -- $$(./tool/go list ./... | grep -v tempfork)

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

publishdevimage: ## Build and publish tailscale image to location specified by ${REPO}
	@test -n "${REPO}" || (echo "REPO=... required; e.g. REPO=ghcr.io/${USER}/tailscale" && exit 1)
	@test "${REPO}" != "tailscale/tailscale" || (echo "REPO=... must not be tailscale/tailscale" && exit 1)
	@test "${REPO}" != "ghcr.io/tailscale/tailscale" || (echo "REPO=... must not be ghcr.io/tailscale/tailscale" && exit 1)
	@test "${REPO}" != "tailscale/k8s-operator" || (echo "REPO=... must not be tailscale/k8s-operator" && exit 1)
	@test "${REPO}" != "ghcr.io/tailscale/k8s-operator" || (echo "REPO=... must not be ghcr.io/tailscale/k8s-operator" && exit 1)
	TAGS="${TAGS}" REPOS=${REPO} PLATFORM=${PLATFORM} PUSH=true TARGET=client ./build_docker.sh

publishdevoperator: ## Build and publish k8s-operator image to location specified by ${REPO}
	@test -n "${REPO}" || (echo "REPO=... required; e.g. REPO=ghcr.io/${USER}/tailscale" && exit 1)
	@test "${REPO}" != "tailscale/tailscale" || (echo "REPO=... must not be tailscale/tailscale" && exit 1)
	@test "${REPO}" != "ghcr.io/tailscale/tailscale" || (echo "REPO=... must not be ghcr.io/tailscale/tailscale" && exit 1)
	@test "${REPO}" != "tailscale/k8s-operator" || (echo "REPO=... must not be tailscale/k8s-operator" && exit 1)
	@test "${REPO}" != "ghcr.io/tailscale/k8s-operator" || (echo "REPO=... must not be ghcr.io/tailscale/k8s-operator" && exit 1)
	TAGS="${TAGS}" REPOS=${REPO} PLATFORM=${PLATFORM} PUSH=true TARGET=operator ./build_docker.sh

help: ## Show this help
	@echo "\nSpecify a command. The choices are:\n"
	@grep -hE '^[0-9a-zA-Z_-]+:.*?## .*$$' ${MAKEFILE_LIST} | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;36m%-20s\033[m %s\n", $$1, $$2}'
	@echo ""
.PHONY: help

.DEFAULT_GOAL := help
