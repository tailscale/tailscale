SOURCE_FILES?=./...
TEST_PATTERN?=.
TEST_OPTIONS?=
TEST_TIMEOUT?=15m

export PATH := ./bin:$(PATH)
export GO111MODULE := on
export GOPROXY := https://proxy.golang.org,https://gocenter.io,direct

# Install all the build and lint dependencies
setup:
	go mod download
	go generate -v ./...
	git config core.hooksPath .githooks
.PHONY: setup


pull_test_imgs:
	grep FROM ./acceptance/testdata/*.dockerfile | cut -f2 -d' ' | sort | uniq | while read -r img; do docker pull "$$img"; done
.PHONY: pull_test_imgs

acceptance: pull_test_imgs
	make -e TEST_OPTIONS="-tags=acceptance" test
.PHONY: acceptance

test:
	go test $(TEST_OPTIONS) -v -failfast -race -coverpkg=./... -covermode=atomic -coverprofile=coverage.txt $(SOURCE_FILES) -run $(TEST_PATTERN) -timeout=$(TEST_TIMEOUT)
.PHONY: test

cover: test
	go tool cover -html=coverage.txt
.PHONY: cover

fmt:
	find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do gofmt -w -s "$$file"; goimports -w "$$file"; done
.PHONY: fmt

lint: check
	golangci-lint run
.PHONY: check

ci: build lint test acceptance
.PHONY: ci

build:
	go build -o nfpm ./cmd/nfpm/main.go
.PHONY: build

deps:
	go get -u
	go mod tidy
	go mod verify
.PHONY: deps

imgs:
	wget -O www/docs/static/logo.png https://github.com/goreleaser/artwork/raw/master/goreleaserfundo.png
	wget -O www/docs/static/card.png "https://og.caarlos0.dev/**NFPM**%20|%20A%20simple%20Deb%20and%20RPM%20packager%20written%20in%20Go.png?theme=light&md=1&fontSize=80px&images=https://github.com/goreleaser.png"
	wget -O www/docs/static/avatar.png https://github.com/goreleaser.png
	convert www/docs/static/avatar.png -define icon:auto-resize=64,48,32,16 www/docs/static/favicon.ico
	convert www/docs/static/avatar.png -resize x120 www/docs/static/apple-touch-icon.png
.PHONY: imgs

serve:
	@docker run --rm -it -p 8000:8000 -v ${PWD}/www:/docs squidfunk/mkdocs-material
.PHONY: serve

todo:
	@grep \
		--exclude-dir=vendor \
		--exclude-dir=node_modules \
		--exclude-dir=bin \
		--exclude=Makefile \
		--text \
		--color \
		-nRo -E ' TODO:.*|SkipNow' .
.PHONY: todo

.DEFAULT_GOAL := build
