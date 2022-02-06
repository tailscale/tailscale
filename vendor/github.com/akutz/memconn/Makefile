SHELL := /bin/bash

all: build

build: memconn.a
memconn.a: $(filter-out %_test.go, $(wildcard *.go))
	go build -o $@

GO_VERSION ?= 1.9.4
IMPORT_PATH := github.com/akutz/memconn

docker-run:
	docker run --rm -it \
      -v $$(pwd):/go/src/$(IMPORT_PATH) \
      golang:$(GO_VERSION) \
      make -C /go/src/$(IMPORT_PATH) $(MAKE_TARGET)

BENCH ?= .

benchmark:
	go test -bench $(BENCH) -run Bench -benchmem .

benchmark-go1.9:
	MAKE_TARGET=benchmark $(MAKE) docker-run

test:
	go test
	go test -race -run 'Race$$'

test-go1.9:
	MAKE_TARGET=test $(MAKE) docker-run